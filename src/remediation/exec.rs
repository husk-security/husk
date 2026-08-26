//! The one place Husk writes or spawns as part of a fix.
//!
//! Planners are pure and know about ecosystems; this module knows nothing about
//! ecosystems and owns every safety property instead:
//!
//! 1. **Containment**: every write must land inside its recipe's `scope` (a
//!    repo root or an ecosystem workspace root, derived from the scan) or the
//!    run's `.husk` directory. Nothing else is writable.
//! 2. **Symlink refusal** on every write, not just `.gitignore`.
//! 3. **Atomic writes** through [`crate::paths`], preserving the original's
//!    permission bits, so a crash mid-write cannot truncate a file Husk just
//!    backed up.
//! 4. **One backup snapshot per apply run**, taken before the first write and
//!    covering every file the run touches, so one `--rollback` undoes it all.
//! 5. **Idempotence**: an already-satisfied op reports `Skipped`, and a file
//!    Husk cannot read is a file Husk does not write (only a missing path is
//!    an empty document).
//! 6. **Stale-plan detection**: [`FixOp::ReplaceSpan`] re-reads the file and
//!    refuses when the bytes moved, so a plan serialised into a report and
//!    acted on a minute later cannot corrupt it.
//! 7. **`RunTool` resolves on `PATH` at apply time**, never through a shell, and
//!    identical invocations run once per apply run (thirty overrides in one
//!    `package.json` mean one `npm install`, not thirty).
//! 8. **Dry-run** produces the identical result shape and writes nothing, not
//!    even a snapshot directory.
//!
//! Husk never rotates or deletes credentials, rewrites git history, deletes
//! user files, pipes to a shell, or asks a model what to execute. The op
//! vocabulary cannot express any of those; keep it that way.

use super::op::{Authority, FailureHint, FixOp, Recipe, Safety, ToolPurpose, Verify};
use super::render;
use super::{ActionResult, ActionStatus, RemediationPlan, RemediationProposal};
use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct ApplyOptions {
    pub dry_run: bool,
    /// `.husk` directory root for backups and the lock.
    pub husk_dir: PathBuf,
    /// Only act on the proposal with this id, if set.
    pub only: Option<String>,
    /// Grant the consent tier: recipes that run a package manager (which
    /// executes third-party code) are opt-in. There is deliberately no option
    /// that authorizes [`Safety::Manual`].
    pub deps: bool,
    /// Called with the argv right before a tool actually runs, so a caller with
    /// no other progress signal can print something before what may be a slow
    /// install.
    pub on_dep_run: Option<DepRunHook>,
}

pub type DepRunHook = Box<dyn Fn(&str) + Send>;

impl ApplyOptions {
    pub fn new(dry_run: bool) -> Self {
        Self {
            dry_run,
            husk_dir: PathBuf::from(".husk"),
            only: None,
            deps: false,
            on_dep_run: None,
        }
    }

    fn authority(&self) -> Authority {
        if self.deps {
            Authority::SafeEditsAndConsented
        } else {
            Authority::SafeEditsOnly
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplyOutcome {
    pub dry_run: bool,
    /// Backup snapshot dir, if any file was written.
    pub backup_dir: Option<PathBuf>,
    pub results: Vec<ActionResult>,
}

#[derive(Serialize, Deserialize)]
struct BackupManifest {
    generated_at: String,
    entries: Vec<BackupEntry>,
}

#[derive(Serialize, Deserialize)]
struct BackupEntry {
    action_id: String,
    original_path: String,
    backup_file: String,
    /// Whether `original_path` existed before the fix ran. When false the fix
    /// *created* the file, so rollback removes it instead of restoring a copy.
    /// Defaults to true so manifests written before this field existed keep
    /// their old restore-a-copy behavior.
    #[serde(default = "default_existed")]
    existed: bool,
}

fn default_existed() -> bool {
    true
}

/// Mutable state shared by every op in one apply run: the single snapshot, the
/// dry-run flag, and the tool invocations already made.
struct Session<'a> {
    dry_run: bool,
    backup_root: PathBuf,
    manifest: BackupManifest,
    wrote: bool,
    /// Files already snapshotted this run, so a second op on the same file
    /// cannot overwrite the pre-run copy with a half-fixed one.
    backed_up: BTreeSet<PathBuf>,
    /// `(program, args, cwd)` already run successfully this session.
    ran: BTreeSet<(String, Vec<String>, PathBuf)>,
    on_dep_run: Option<&'a DepRunHook>,
}

/// Apply the proposals in `plan`.
///
/// Auto-safe recipes run unconditionally; the consent tier runs only with
/// `opts.deps`. Blocked and manual proposals are reported as `NeedsUser` and
/// never executed. The whole run shares one lock, one snapshot, and one
/// rollback point.
pub fn apply(plan: &RemediationPlan, opts: &ApplyOptions) -> Result<ApplyOutcome> {
    let _lock = if opts.dry_run {
        None
    } else {
        Some(FixLock::acquire(&opts.husk_dir)?)
    };

    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let mut session = Session {
        dry_run: opts.dry_run,
        backup_root: opts.husk_dir.join("backups").join(&stamp),
        manifest: BackupManifest {
            generated_at: Utc::now().to_rfc3339(),
            entries: Vec::new(),
        },
        wrote: false,
        backed_up: BTreeSet::new(),
        ran: BTreeSet::new(),
        on_dep_run: opts.on_dep_run.as_ref(),
    };

    let mut results = Vec::new();
    for proposal in &plan.proposals {
        if let Some(only) = &opts.only
            && &proposal.id != only
        {
            continue;
        }
        results.push(run_proposal(&mut session, proposal, opts.authority()));
    }

    let backup_dir = if session.wrote {
        std::fs::create_dir_all(&session.backup_root)
            .with_context(|| format!("create backup dir {}", session.backup_root.display()))?;
        std::fs::write(
            session.backup_root.join("manifest.json"),
            serde_json::to_vec_pretty(&session.manifest)?,
        )?;
        ensure_husk_dir_ignored(&opts.husk_dir)?;
        Some(session.backup_root.clone())
    } else {
        None
    };

    Ok(ApplyOutcome {
        dry_run: opts.dry_run,
        backup_dir,
        results,
    })
}

/// What `recipe` would change, read from the files as they stand now.
///
/// The one place a diff is computed. Every surface renders this rather than
/// deriving its own, and it goes through the same [`render`] the executor
/// does, so what a user is shown is what applying writes. Best effort by
/// design: a file that cannot be read yields no diff here, while the executor
/// refuses outright, because a missing preview costs a picture and a wrong
/// write costs the file.
///
/// `None` for a recipe with no ops, which is what a manual proposal is.
pub fn preview(recipe: &Recipe) -> Option<render::FixPreview> {
    if recipe.ops.is_empty() {
        return None;
    }
    // Ops are applied in order and several can land in one file (an override
    // plus the direct dependency npm insists must match it), so each op sees
    // what the one before it wrote. Diffing them independently would show only
    // the last edit.
    let mut files: Vec<(PathBuf, Option<String>, Option<String>)> = Vec::new();
    let mut fragments = Vec::new();
    let mut complete = true;
    let mut cwd = None;
    // Found before the loop because the tool runs last: the manifest edits
    // shown ahead of it are that manager's, not a fixed one's.
    let manager = recipe.ops.iter().find_map(|op| match op {
        FixOp::RunTool { program, .. } => Some(program.as_str()),
        _ => None,
    });

    for op in &recipe.ops {
        let existing = match op.write_target() {
            None => None,
            Some(path) => {
                let entry = match files.iter().position(|(seen, ..)| seen == path) {
                    Some(index) => index,
                    None => {
                        let original = readable_text(path);
                        // A file that is there but will not read as text gets
                        // no preview at all: diffing it against "" would
                        // invent a rewrite of the whole file.
                        if original.is_none() && path.exists() {
                            return None;
                        }
                        files.push((path.clone(), original.clone(), original));
                        files.len() - 1
                    }
                };
                files[entry].2.clone()
            }
        };
        match render::render(op, existing.as_deref()) {
            Ok(render::Rendered::Write { contents, .. }) => {
                if let Some(path) = op.write_target()
                    && let Some(entry) = files.iter_mut().find(|(seen, ..)| seen == path)
                {
                    entry.2 = Some(contents);
                }
            }
            // Nothing to show and nothing to run: an op that is already
            // satisfied is not part of the change either way.
            Ok(render::Rendered::Satisfied(_)) => continue,
            Ok(render::Rendered::Command) => {}
            // The file moved, vanished, or stopped parsing since this fix was
            // planned, so the op yields neither a diff nor a command fragment.
            // Dropping it silently would leave the rest reading as the whole
            // change, which is how someone runs the one-liner and believes they
            // are patched when an edit never happened.
            Err(_) => {
                complete = false;
                continue;
            }
        }
        match render::shell_equivalent(op, existing.as_deref(), manager) {
            Some(fragment) => fragments.push(fragment),
            // An op no one-liner expresses: the command stays honest by
            // admitting it is not the whole fix.
            None => complete = false,
        }
        if let FixOp::RunTool { cwd: dir, .. } = op {
            cwd.get_or_insert_with(|| dir.clone());
        }
    }

    let diff = files
        .into_iter()
        .filter_map(|(path, before, after)| {
            let after = after?;
            (Some(&after) != before.as_ref())
                .then(|| render::file_diff(&path, before.as_deref(), &after))
        })
        .collect::<Vec<_>>();
    let command = (!fragments.is_empty()).then(|| fragments.join(" && "));
    if diff.is_empty() && command.is_none() {
        return None;
    }
    Some(render::FixPreview {
        diff,
        complete: command.is_some() && complete,
        cwd: cwd.or_else(|| Some(recipe.scope.clone())),
        command,
    })
}

/// A file's text for previewing only. Anything Husk cannot cheaply read as
/// text simply has no diff; only the executor treats that as a refusal.
fn readable_text(path: &Path) -> Option<String> {
    let size = std::fs::metadata(path).ok()?.len();
    if size as usize > render::MAX_DIFF_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// The gate every proposal passes before a single op runs: blocked, manual, or
/// above the authority this run was given.
fn run_proposal(
    session: &mut Session<'_>,
    proposal: &RemediationProposal,
    authority: Authority,
) -> ActionResult {
    let recipe = &proposal.recipe;
    let needs_user = |detail: String| ActionResult {
        id: proposal.id.clone(),
        status: ActionStatus::NeedsUser,
        detail,
        output: None,
    };

    if let Some(blocker) = proposal.blockers.first() {
        return needs_user(blocker.render());
    }
    if recipe.safety == Safety::Manual || recipe.ops.is_empty() {
        return needs_user(if recipe.steps.is_empty() {
            "manual remediation".to_string()
        } else {
            recipe
                .steps
                .iter()
                .map(|step| step.text.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        });
    }
    if !authority.permits(recipe.safety) {
        return needs_user(format!(
            "run yourself: {} (or pass --deps to let husk run it)",
            recipe
                .ops
                .iter()
                .map(FixOp::preview)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    run_recipe(session, &proposal.id, recipe)
}

/// Execute one recipe's ops in order, collapsing them into a single result. The
/// first hard failure stops the recipe; the run's snapshot is the rollback
/// point for whatever already landed.
fn run_recipe(session: &mut Session<'_>, id: &str, recipe: &Recipe) -> ActionResult {
    // Fail closed: a scope that will not canonicalize is a scope no write can
    // be proved to be inside, and "could not resolve it" is not a reason to
    // allow the write.
    let scope = match recipe.scope.canonicalize() {
        Ok(scope) => scope,
        Err(error) => {
            return failed(
                id,
                format!(
                    "could not resolve {}: {error}. Refusing to write without a scope to contain \
                     the change",
                    recipe.scope.display()
                ),
                &[],
            );
        }
    };
    let mut applied = Vec::new();
    let mut skipped = Vec::new();
    let mut output = Vec::new();

    // A package manager rewrites its own manifests, so nothing here calls
    // `write_file` for them and nothing else would snapshot them: `cargo
    // update` rewrites Cargo.lock and `go get` rewrites go.mod and go.sum
    // entirely inside the tool. Without this, `husk fix --rollback` silently
    // could not undo a dependency update. `Verify::Recoordinate` already names
    // exactly those files, because they are the ones re-read to prove the fix
    // stuck.
    if let Err(error) = snapshot_recoordinated(session, id, &recipe.verify) {
        return failed(id, error, &applied);
    }

    for op in &recipe.ops {
        if let Some(target) = op.write_target()
            && let Err(error) = check_writable(target, &scope)
        {
            return failed(id, error, &applied);
        }
        match run_op(session, id, op, &recipe.failure_hints, &mut output) {
            Ok(OpOutcome::Applied(detail)) => applied.push(detail),
            Ok(OpOutcome::Skipped(detail) | OpOutcome::Warned(detail)) => skipped.push(detail),
            Err(detail) => return failed(id, detail, &applied).with_output(&output),
        }
    }

    let mut detail = if applied.is_empty() {
        skipped.join("; ")
    } else {
        applied.join("; ")
    };
    if !session.dry_run
        && !applied.is_empty()
        && let Some(verdict) = verify(&recipe.verify)
    {
        detail.push_str(". ");
        detail.push_str(&verdict);
    }
    ActionResult {
        id: id.to_string(),
        status: if session.dry_run {
            ActionStatus::WouldApply
        } else if applied.is_empty() {
            ActionStatus::Skipped
        } else {
            ActionStatus::Applied
        },
        detail,
        output: None,
    }
    .with_output(&output)
}

fn failed(id: &str, detail: String, applied: &[String]) -> ActionResult {
    ActionResult {
        id: id.to_string(),
        status: ActionStatus::Failed,
        detail: if applied.is_empty() {
            detail
        } else {
            format!("{detail} (already done: {})", applied.join("; "))
        },
        output: None,
    }
}

enum OpOutcome {
    Applied(String),
    Skipped(String),
    /// Something non-fatal went wrong (a `Tidy` step); the fix still stands.
    Warned(String),
}

fn run_op(
    session: &mut Session<'_>,
    id: &str,
    op: &FixOp,
    hints: &[FailureHint],
    output: &mut Vec<String>,
) -> Result<OpOutcome, String> {
    if let FixOp::RunTool {
        program,
        args,
        cwd,
        purpose,
    } = op
    {
        return run_tool(session, program, args, cwd, *purpose, hints, output);
    }
    let path = op
        .write_target()
        .expect("every op that is not a tool run writes a file");
    // `CreateFile` never overwrites, so only whether the path is taken
    // matters: bytes Husk cannot decode are still a file that is already
    // there, and reading them would turn a skip into a failure.
    let existing = match op {
        FixOp::CreateFile { .. } => path.exists().then(String::new),
        _ => read_existing(path)?,
    };
    match render::render(op, existing.as_deref()).map_err(|error| error.to_string())? {
        render::Rendered::Satisfied(detail) => Ok(OpOutcome::Skipped(detail)),
        render::Rendered::Write { contents, detail } => {
            write_file(session, id, path, &contents)?;
            Ok(OpOutcome::Applied(detail))
        }
        render::Rendered::Command => unreachable!("tool runs returned above"),
    }
}

/// The file an op is about to rewrite, as text.
///
/// `Ok(None)` means the path does not exist, which is the one legitimately
/// empty document. Every other read failure (bytes that are not UTF-8, a
/// permission error, an I/O error) is an error, because the alternative is
/// computing the new contents from an empty string and writing that over a
/// file Husk could not even read. One Latin-1 byte in a `package.json` author
/// name is enough to make the read fail.
fn read_existing(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "could not read {}: {error}. Husk will not rewrite a file it cannot read",
            path.display()
        )),
    }
}

fn run_tool(
    session: &mut Session<'_>,
    program: &str,
    args: &[String],
    cwd: &Path,
    purpose: ToolPurpose,
    hints: &[FailureHint],
    output: &mut Vec<String>,
) -> Result<OpOutcome, String> {
    let argv = std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    if session.dry_run {
        return Ok(OpOutcome::Applied(format!("run `{argv}`")));
    }
    // Resolved here, not at plan time: a user who installs npm because Husk
    // told them to should not have to re-scan for the click to work.
    if !program_on_path(program) {
        // The advice is the message; the log keeps the shell's own words, so a
        // user reading the output sees what their terminal would have said.
        output.push(format!("$ {argv}\n{program}: command not found\n"));
        return Err(format!(
            "{program} isn't installed. {}",
            super::install_advice_for(program)
        ));
    }
    let key = (program.to_string(), args.to_vec(), cwd.to_path_buf());
    if session.ran.contains(&key) {
        return Ok(OpOutcome::Skipped(format!(
            "`{argv}` already ran in this batch"
        )));
    }
    if let Some(hook) = session.on_dep_run {
        hook(&argv);
    }
    let dir = if cwd.is_dir() {
        cwd.to_path_buf()
    } else {
        PathBuf::from(".")
    };
    match Command::new(program).args(args).current_dir(&dir).output() {
        Ok(out) if out.status.success() => {
            output.push(tool_log(&argv, &out));
            session.ran.insert(key);
            Ok(OpOutcome::Applied(format!("ran `{argv}`")))
        }
        // A prune step is housekeeping: the pin already landed, so a failure is
        // a warning the user can act on, not a failed fix.
        Ok(out) if purpose == ToolPurpose::BestEffort => {
            output.push(tool_log(&argv, &out));
            Ok(OpOutcome::Warned(format!(
                "`{argv}` failed ({}). Run it yourself or the next scan may still flag the stale \
                 entry it leaves behind",
                stderr_tail(&String::from_utf8_lossy(&out.stderr))
            )))
        }
        Ok(out) => {
            output.push(tool_log(&argv, &out));
            let stderr = String::from_utf8_lossy(&out.stderr);
            // The planner knows what a failure means; the executor only
            // matches the markers it was handed.
            let explained = hints
                .iter()
                .find(|hint| hint.markers.iter().any(|marker| stderr.contains(marker)))
                .map(|hint| hint.detail.clone());
            Err(explained.unwrap_or_else(|| format!("`{argv}` failed: {}", stderr_tail(&stderr))))
        }
        Err(error) => {
            output.push(format!("$ {argv}\n{error}\n"));
            Err(format!("could not run `{program}`: {error}"))
        }
    }
}

/// One command's transcript: what was run, then both its streams verbatim.
/// Shown as-is, because a package manager's own words are more use than any
/// summary of them.
fn tool_log(argv: &str, out: &std::process::Output) -> String {
    format!(
        "$ {argv}\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Refuse to write outside the recipe's scope, through a symlink, or to
/// something that is not a regular file.
fn check_writable(path: &Path, scope: &Path) -> Result<(), String> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{} is a symlink; refusing to write",
                path.display()
            ));
        }
        if !metadata.is_file() {
            return Err(format!(
                "{} is not a regular file; refusing to write",
                path.display()
            ));
        }
    }
    // Canonicalize the deepest existing ancestor: the target itself may not
    // exist yet (a created file), but every directory on the way to it must
    // resolve inside the scope, which is what defeats a `..` or a symlinked
    // parent directory. An ancestor that never resolves is refused, not
    // waved through.
    let mut probe = path.parent().unwrap_or(path);
    let resolved = loop {
        match probe.canonicalize() {
            Ok(resolved) => break resolved,
            Err(_) => match probe.parent() {
                Some(parent) => probe = parent,
                None => return Err(format!("could not resolve {}", path.display())),
            },
        }
    };
    if resolved.starts_with(scope) {
        Ok(())
    } else {
        Err(format!(
            "{} is outside {}; refusing to write",
            path.display(),
            scope.display()
        ))
    }
}

/// Snapshot the manifests a tool run rewrites in place, before it runs.
///
/// Only files that already exist are copied: `back_up` records a missing path
/// as "created by husk", which would make rollback *delete* a manifest the fix
/// never created.
fn snapshot_recoordinated(
    session: &mut Session<'_>,
    id: &str,
    verify: &Verify,
) -> Result<(), String> {
    if session.dry_run {
        return Ok(());
    }
    let Verify::Recoordinate { manifests, .. } = verify else {
        return Ok(());
    };
    for path in manifests.iter().filter(|path| path.exists()) {
        back_up(session, id, path)
            .map_err(|error| format!("could not back up {}: {error:#}", path.display()))?;
        session.wrote = true;
    }
    Ok(())
}

/// Snapshot then atomically write, preserving the original's permission bits so
/// a 0600 file does not come back world-readable.
fn write_file(
    session: &mut Session<'_>,
    id: &str,
    path: &Path,
    contents: &str,
) -> Result<(), String> {
    if session.dry_run {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Err(format!("could not create {}: {error}", parent.display()));
    }
    back_up(session, id, path).map_err(|error| format!("could not back up: {error:#}"))?;
    let mode = file_mode(path);
    crate::paths::write_atomic_mode(path, contents.as_bytes(), mode)
        .map_err(|error| format!("could not write {}: {error:#}", path.display()))?;
    session.wrote = true;
    Ok(())
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}

/// Snapshot `original` once per apply run, before anything has touched it.
///
/// Once per *path*, not once per proposal: batch application routinely sends
/// two proposals into one file (two dotenv appends to one `.gitignore`), and a
/// second snapshot would capture the first proposal's write, so rollback would
/// restore a half-fixed file. The first snapshot wins; later writes to the
/// same path reuse it.
fn back_up(session: &mut Session<'_>, action_id: &str, original: &Path) -> Result<()> {
    let abs = original
        .canonicalize()
        .unwrap_or_else(|_| original.to_path_buf());
    if !session.backed_up.insert(abs.clone()) {
        return Ok(());
    }
    // Mirror the absolute path under backups/<ts>/files/<path-without-root>.
    let stripped: PathBuf = abs.components().skip(1).collect();
    let backup_file = session.backup_root.join("files").join(&stripped);
    if let Some(parent) = backup_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existed = original.exists();
    if existed {
        std::fs::copy(original, &backup_file)
            .with_context(|| format!("back up {}", original.display()))?;
    }
    // When the file does not exist yet the fix is *creating* it: record
    // `existed: false` (no copy) so rollback removes the created file instead
    // of "restoring" it to an empty stand-in.
    session.manifest.entries.push(BackupEntry {
        action_id: action_id.to_string(),
        original_path: abs.to_string_lossy().to_string(),
        backup_file: backup_file.to_string_lossy().to_string(),
        existed,
    });
    Ok(())
}

/// Ensure `.husk/backups/` (which may contain copies of secret files) is never
/// committed, preserving whatever the user already has in that `.gitignore`.
fn ensure_husk_dir_ignored(husk_dir: &Path) -> Result<()> {
    let ignore = husk_dir.join(".gitignore");
    let existing = std::fs::read_to_string(&ignore).unwrap_or_default();
    let missing: Vec<&str> = ["backups/", "fix.lock"]
        .into_iter()
        .filter(|entry| !existing.lines().any(|line| line.trim() == *entry))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(husk_dir)?;
    let mut contents = existing;
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    for entry in missing {
        contents.push_str(entry);
        contents.push('\n');
    }
    std::fs::write(&ignore, contents)?;
    Ok(())
}

/// Restore files from the most recent (or named) backup snapshot.
pub fn rollback(husk_dir: &Path, stamp: Option<&str>) -> Result<Vec<String>> {
    let backups = husk_dir.join("backups");
    let snapshot = match stamp {
        Some(stamp) => backups.join(stamp),
        None => latest_backup(&backups).context("no husk fix backups to roll back")?,
    };
    let manifest_path = snapshot.join("manifest.json");
    let manifest: BackupManifest = serde_json::from_slice(
        &std::fs::read(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?,
    )?;
    let mut restored = Vec::new();
    for entry in manifest.entries {
        if entry.existed {
            std::fs::copy(&entry.backup_file, &entry.original_path)
                .with_context(|| format!("restore {}", entry.original_path))?;
        } else {
            // The fix created this file; undoing it means removing it, not
            // "restoring" an empty stand-in. Already-gone is fine.
            match std::fs::remove_file(&entry.original_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("remove created {}", entry.original_path));
                }
            }
        }
        restored.push(entry.original_path);
    }
    Ok(restored)
}

fn latest_backup(backups: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(backups)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs.pop()
}

/// A simple advisory lockfile so two `husk fix --apply` runs cannot race.
struct FixLock {
    path: PathBuf,
}

impl FixLock {
    fn acquire(husk_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(husk_dir)?;
        let path = husk_dir.join("fix.lock");
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(_) => Ok(Self { path }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                anyhow::bail!(
                    "another `husk fix` is running ({} exists); remove it if stale",
                    path.display()
                )
            }
            Err(error) => Err(error).context("create fix lock"),
        }
    }
}

impl Drop for FixLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Re-observe the world after a recipe applied. `None` when there is nothing
/// cheap to observe.
///
/// [`Verify::Recoordinate`] re-runs the **scanner's own parser** over the files
/// the fix touched and asserts the coordinate now reads the target version.
/// That costs zero ecosystem-specific code, which is the payoff for keying the
/// fixer registry on the same ecosystem id as [`crate::scan::targets`]. An exit
/// code of 0 is not evidence: it is exactly what pnpm returns while ignoring an
/// override written where it no longer reads.
fn verify(verify: &Verify) -> Option<String> {
    let Verify::Recoordinate {
        manifests,
        ecosystem,
        name,
        expect,
    } = verify
    else {
        // A `Rescan` names the guide control that settles it rather than
        // invoking one, so that `remediation` never calls back into `guide`.
        return match verify {
            Verify::Rescan { control_id } => Some(format!("{} `{control_id}`", super::RESCAN_HINT)),
            _ => None,
        };
    };

    let targets = crate::scan::targets::default_targets();
    let (mut packages, mut warnings) = (Vec::new(), Vec::new());
    for manifest in manifests.iter().filter(|path| path.is_file()) {
        crate::scan::targets::discover_from_file(&targets, manifest, &mut packages, &mut warnings);
    }
    let versions: Vec<&str> = packages
        .iter()
        .filter(|package| package.ecosystem == *ecosystem && package.name == *name)
        .map(|package| package.version.as_str())
        .collect();

    Some(if versions.is_empty() {
        format!("Verified: {name} is no longer in the manifest")
    } else if versions.iter().all(|version| version == expect) {
        format!("Verified: the manifest now reads {name} {expect}")
    } else if versions.contains(&expect.as_str()) {
        format!(
            "Partly verified: the manifest reads {name} {expect}, and also still {}. Another copy \
             is pinned elsewhere",
            others(&versions, expect)
        )
    } else {
        format!(
            "NOT verified: the manifest still reads {name} {}. The change did not take; re-scan \
             before trusting this fix",
            versions.join(", ")
        )
    })
}

fn others(versions: &[&str], expect: &str) -> String {
    versions
        .iter()
        .filter(|version| **version != expect)
        .copied()
        .collect::<Vec<_>>()
        .join(", ")
}

/// Where `program` resolves on `PATH`, if anywhere.
pub fn program_path(program: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var).find_map(|dir| {
        let candidate = dir.join(program);
        candidate.is_file().then_some(candidate)
    })
}

/// Whether `program` resolves on `PATH`: a cheap, read-only filesystem check
/// (no subprocess spawn) so a plan can warn *before* offering a doomed click.
pub fn program_on_path(program: &str) -> bool {
    program_path(program).is_some()
}

/// The last few meaningful stderr lines. Package managers pad failures with
/// decoration and pointers to output we do not have, which crowds the real
/// error out of a short tail; drop those lines rather than showing them.
fn stderr_tail(stderr: &str) -> String {
    let meaningful = |line: &&str| {
        let trimmed = line.trim();
        !trimmed.is_empty()
            && !trimmed.starts_with("note:")
            && !trimmed.starts_with('×')
            && !trimmed.starts_with("╰─>")
            && !trimmed.starts_with('│')
    };
    let mut lines: Vec<&str> = stderr.lines().filter(meaningful).rev().take(3).collect();
    lines.reverse();
    lines
        .into_iter()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation::op::{DocFormat, Explain, Verify};

    fn session(dir: &Path) -> Session<'static> {
        Session {
            dry_run: false,
            backup_root: dir.join(".husk/backups/test"),
            manifest: BackupManifest {
                generated_at: "test".to_string(),
                entries: Vec::new(),
            },
            wrote: false,
            backed_up: BTreeSet::new(),
            ran: BTreeSet::new(),
            on_dep_run: None,
        }
    }

    fn recipe(scope: &Path, ops: Vec<FixOp>) -> Recipe {
        Recipe {
            ops,
            safety: Safety::SafeEdit,
            scope: scope.to_path_buf(),
            explain: Explain::new("test"),
            verify: Verify::UserConfirms,
            steps: Vec::new(),
            failure_hints: Vec::new(),
        }
    }

    #[test]
    fn append_unique_line_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let gitignore = dir.path().join(".gitignore");
        std::fs::write(&gitignore, "node_modules/\n").unwrap();
        let op = FixOp::AppendUniqueLine {
            path: gitignore.clone(),
            line: ".env".into(),
            header: None,
        };
        let mut session = session(dir.path());

        let first = run_recipe(&mut session, "a", &recipe(dir.path(), vec![op.clone()]));
        assert_eq!(first.status, ActionStatus::Applied);
        let second = run_recipe(&mut session, "a", &recipe(dir.path(), vec![op]));
        assert_eq!(second.status, ActionStatus::Skipped);
        assert_eq!(
            std::fs::read_to_string(&gitignore).unwrap(),
            "node_modules/\n.env\n"
        );
    }

    #[test]
    fn replace_span_refuses_a_stale_plan() {
        let dir = tempfile::tempdir().unwrap();
        let workflow = dir.path().join("ci.yml");
        let plan = FixOp::ReplaceSpan {
            path: workflow.clone(),
            start: 6,
            end: 25,
            expect: "actions/checkout@v4".into(),
            replacement: "actions/checkout@abc123".into(),
        };
        // The file moved underneath the plan, so applying it would corrupt it.
        std::fs::write(&workflow, "# a comment\nuses: actions/checkout@v4\n").unwrap();
        let mut session = session(dir.path());
        let result = run_recipe(&mut session, "pin", &recipe(dir.path(), vec![plan]));
        assert_eq!(result.status, ActionStatus::Failed);
        assert!(result.detail.contains("changed since this fix was planned"));
    }

    #[test]
    fn writes_outside_the_recipe_scope_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let scope = dir.path().join("project");
        std::fs::create_dir_all(&scope).unwrap();
        let outside = dir.path().join("elsewhere.txt");
        let mut session = session(dir.path());
        let result = run_recipe(
            &mut session,
            "escape",
            &recipe(
                &scope,
                vec![FixOp::CreateFile {
                    path: outside.clone(),
                    contents: "x".into(),
                }],
            ),
        );
        assert_eq!(result.status, ActionStatus::Failed);
        assert!(result.detail.contains("refusing to write"));
        assert!(!outside.exists());
    }

    #[cfg(unix)]
    #[test]
    fn writes_through_a_symlink_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.txt");
        std::fs::write(&real, "original\n").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut session = session(dir.path());
        let result = run_recipe(
            &mut session,
            "link",
            &recipe(
                dir.path(),
                vec![FixOp::AppendUniqueLine {
                    path: link,
                    line: "x".into(),
                    header: None,
                }],
            ),
        );
        assert_eq!(result.status, ActionStatus::Failed);
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "original\n");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writes_preserve_the_original_permission_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".npmrc");
        std::fs::write(&config, "registry=https://example\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut session = session(dir.path());
        let result = run_recipe(
            &mut session,
            "cfg",
            &recipe(
                dir.path(),
                vec![FixOp::SetValue {
                    path: config.clone(),
                    format: DocFormat::KeyValue,
                    key: vec!["ignore-scripts".into()],
                    value: "true".into(),
                }],
            ),
        );
        assert_eq!(result.status, ActionStatus::Applied);
        let mode = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a 0600 config must not come back readable");
    }

    #[test]
    fn dry_run_writes_nothing_and_creates_no_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("new.txt");
        let mut session = session(dir.path());
        session.dry_run = true;
        let result = run_recipe(
            &mut session,
            "create",
            &recipe(
                dir.path(),
                vec![FixOp::CreateFile {
                    path: target.clone(),
                    contents: "x".into(),
                }],
            ),
        );
        assert_eq!(result.status, ActionStatus::WouldApply);
        assert!(!target.exists());
        assert!(!session.wrote);
    }

    /// A recipe whose whole change happens inside a package manager, the way
    /// `cargo update --precise` and `go get` do.
    fn tool_recipe(scope: &Path, manifests: Vec<PathBuf>) -> Recipe {
        let mut recipe = recipe(
            scope,
            vec![FixOp::RunTool {
                program: "true".to_string(),
                args: Vec::new(),
                cwd: scope.to_path_buf(),
                purpose: ToolPurpose::Required,
            }],
        );
        recipe.safety = Safety::NeedsConsent;
        recipe.verify = Verify::Recoordinate {
            manifests,
            ecosystem: "cargo".to_string(),
            name: "serde".to_string(),
            expect: "1.0.1".to_string(),
        };
        recipe
    }

    #[test]
    fn a_tool_run_snapshots_the_manifests_it_rewrites() {
        // `cargo update --precise` rewrites Cargo.lock and `go get` rewrites
        // go.mod/go.sum entirely inside the tool, so no write op covers them.
        // Without a snapshot taken here, `husk fix --rollback` cannot undo a
        // dependency update at all.
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("Cargo.lock");
        let original = "version = 3\n";
        std::fs::write(&lock, original).unwrap();
        let mut session = session(dir.path());

        let result = run_recipe(
            &mut session,
            "dep:cargo:serde",
            &tool_recipe(dir.path(), vec![lock.clone()]),
        );

        assert_eq!(result.status, ActionStatus::Applied);
        assert!(session.wrote, "a snapshot must produce a backup directory");
        let absolute = lock.canonicalize().unwrap().to_string_lossy().into_owned();
        let entry = session
            .manifest
            .entries
            .iter()
            .find(|entry| entry.original_path == absolute)
            .expect("the lockfile the tool rewrites must be snapshotted before it runs");
        assert!(entry.existed);
        assert_eq!(
            std::fs::read_to_string(&entry.backup_file).unwrap(),
            original,
            "the snapshot must hold the bytes from before the tool ran"
        );
    }

    #[test]
    fn a_manifest_that_does_not_exist_is_not_recorded_as_husk_created() {
        // `back_up` records a missing path as "husk created this", which
        // rollback undoes by deleting it. A manifest the fix never creates
        // must not be recorded at all.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("go.sum");
        let mut session = session(dir.path());

        let result = run_recipe(
            &mut session,
            "dep:go:x",
            &tool_recipe(dir.path(), vec![missing]),
        );

        assert_eq!(result.status, ActionStatus::Applied);
        assert!(
            session.manifest.entries.is_empty(),
            "a manifest that was never there must not be recorded for deletion"
        );
    }

    #[test]
    fn identical_tool_invocations_run_once_per_apply_run() {
        // Thirty overrides in one package.json must mean one `npm install`,
        // not thirty sequential re-resolves of the same tree.
        let dir = tempfile::tempdir().unwrap();
        let op = FixOp::RunTool {
            program: "true".into(),
            args: vec![],
            cwd: dir.path().to_path_buf(),
            purpose: ToolPurpose::Required,
        };
        let mut session = session(dir.path());
        let first = run_recipe(&mut session, "a", &recipe(dir.path(), vec![op.clone()]));
        assert_eq!(first.status, ActionStatus::Applied);
        let second = run_recipe(&mut session, "b", &recipe(dir.path(), vec![op]));
        assert_eq!(second.status, ActionStatus::Skipped);
        assert!(second.detail.contains("already ran in this batch"));
    }

    #[test]
    fn two_proposals_writing_one_file_share_the_pre_run_snapshot() {
        // Snapshotting per proposal would capture the previous proposal's
        // write, and rollback would then restore a half-fixed file.
        let dir = tempfile::tempdir().unwrap();
        let gitignore = dir.path().join(".gitignore");
        let original = "node_modules/\n";
        std::fs::write(&gitignore, original).unwrap();

        let append = |line: &str| {
            recipe(
                dir.path(),
                vec![FixOp::AppendUniqueLine {
                    path: gitignore.clone(),
                    line: line.to_string(),
                    header: None,
                }],
            )
        };
        let mut session = session(dir.path());
        for (id, line) in [("first", ".env"), ("second", ".env.local")] {
            assert_eq!(
                run_recipe(&mut session, id, &append(line)).status,
                ActionStatus::Applied
            );
        }
        assert_eq!(
            std::fs::read_to_string(&gitignore).unwrap(),
            "node_modules/\n.env\n.env.local\n"
        );
        assert_eq!(
            session.manifest.entries.len(),
            1,
            "one snapshot per path, not per proposal"
        );

        std::fs::create_dir_all(&session.backup_root).unwrap();
        std::fs::write(
            session.backup_root.join("manifest.json"),
            serde_json::to_vec(&session.manifest).unwrap(),
        )
        .unwrap();
        rollback(&dir.path().join(".husk"), None).unwrap();
        assert_eq!(
            std::fs::read_to_string(&gitignore).unwrap(),
            original,
            "rollback must undo the whole batch, not just its last write"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_file_husk_cannot_read_is_left_byte_for_byte_alone() {
        // A read failure must not become an empty document: the op would then
        // write contents computed from "" over the file, and one Latin-1 byte
        // in an author name is enough to make the read fail.
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        let original: &[u8] = b"{\"name\":\"app\",\"author\":\"Bj\xF8rn\"}\n";
        std::fs::write(&manifest, original).unwrap();

        let mut session = session(dir.path());
        let result = run_recipe(
            &mut session,
            "override",
            &recipe(
                dir.path(),
                vec![FixOp::SetValue {
                    path: manifest.clone(),
                    format: DocFormat::Json,
                    key: vec!["overrides".into(), "lodash".into()],
                    value: "4.17.21".into(),
                }],
            ),
        );
        assert_eq!(result.status, ActionStatus::Failed);
        assert!(
            result
                .detail
                .contains("will not rewrite a file it cannot read"),
            "{}",
            result.detail
        );
        assert_eq!(std::fs::read(&manifest).unwrap(), original);
        assert!(!session.wrote, "a refused op must not touch the snapshot");
    }

    #[test]
    fn an_unresolvable_scope_refuses_every_write() {
        // A scope that will not canonicalize must fail closed, not read as
        // "no scope to be outside of".
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("in-scope.txt");
        let mut session = session(dir.path());
        let result = run_recipe(
            &mut session,
            "ghost",
            &recipe(
                &dir.path().join("was-here"),
                vec![FixOp::CreateFile {
                    path: target.clone(),
                    contents: "x".into(),
                }],
            ),
        );
        assert_eq!(result.status, ActionStatus::Failed);
        assert!(!target.exists());
    }

    #[test]
    fn a_failure_hint_replaces_an_unhelpful_tool_tail() {
        let dir = tempfile::tempdir().unwrap();
        let mut recipe = recipe(
            dir.path(),
            vec![FixOp::RunTool {
                program: "false".into(),
                args: vec![],
                cwd: dir.path().to_path_buf(),
                purpose: ToolPurpose::Required,
            }],
        );
        recipe.safety = Safety::NeedsConsent;
        recipe.failure_hints.push(FailureHint {
            markers: vec![String::new()],
            detail: "the explained cause".into(),
        });
        let mut session = session(dir.path());
        let result = run_recipe(&mut session, "x", &recipe);
        assert_eq!(result.status, ActionStatus::Failed);
        assert_eq!(result.detail, "the explained cause");
    }
}
