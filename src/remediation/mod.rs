//! Typed remediation proposed by scan-backed guide controls.
//!
//! Markdown owns the explanation; Rust owns observation, planning, and the
//! small set of deterministic operations Husk is allowed to execute. A
//! proposal is either safe to apply directly, requires explicit confirmation
//! (for example an ecosystem package-manager operation), or is manual.
//!
//! Planning is read-only. Applying is always explicit, uses typed operations
//! rather than shell text supplied by a client, refuses unsafe filesystem
//! targets, and snapshots changed files under `.husk/backups/<ts>/`. Husk never
//! rotates or deletes credentials, rewrites git history, deletes user files, or
//! asks an LLM to decide what code to execute.
//!
//! Four modules, each with one job:
//!
//! - [`op`] is the closed vocabulary of operations a fix may speak, plus the
//!   [`Recipe`] a planner returns. Pure data.
//! - [`plan`] is the pure planning input and output: a [`Change`], the
//!   already-read [`Workspace`], the probed [`Toolbox`], and the
//!   [`Plan`](plan::Plan) carrying both a recipe and every [`Blocker`] against
//!   it.
//! - [`ecosystems`] is the per-ecosystem planner registry, keyed on the same
//!   ecosystem id as [`crate::scan::targets`].
//! - [`exec`] is the only code that writes, spawns, or re-reads the world.
//!
//! Dependencies run one way: guide controls call the planners here, and
//! nothing here calls back into [`crate::guide`].

pub mod ecosystems;
pub mod exec;
pub mod op;
pub mod plan;
pub mod render;

use crate::model::{ScanReport, Severity};
use chrono::{DateTime, Utc};
use op::{Direction, Explain, FixOp, Recipe, Safety, Step};
use plan::{Blocker, Change, Override, Toolbox, Workspace};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub use exec::{ApplyOptions, ApplyOutcome, apply, program_on_path, program_path, rollback};

/// How Husk may act on a planned fix. A projection of [`Safety`], kept because
/// every surface renders it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionClass {
    /// Husk can apply this itself: idempotent, reversible, narrowly scoped, and
    /// it runs no third-party code.
    AutoSafe,
    /// Husk may apply this only after explicit confirmation.
    Confirm,
    /// Husk refuses to act; emits a checklist.
    Manual,
}

impl From<Safety> for ExecutionClass {
    fn from(safety: Safety) -> Self {
        match safety {
            Safety::SafeEdit => ExecutionClass::AutoSafe,
            Safety::NeedsConsent => ExecutionClass::Confirm,
            Safety::Manual => ExecutionClass::Manual,
        }
    }
}

/// What a proposal does, for display.
///
/// A projection of [`RemediationProposal::recipe`], built beside it and never
/// planned separately. The executor reads the recipe and only the recipe; this
/// exists so the CLI, TUI and web can group and label proposals without
/// understanding ops.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RemediationOperation {
    /// Set one key in a line-oriented `key=value` config file.
    SetConfigValue {
        path: PathBuf,
        key: String,
        value: String,
    },
    /// Append a dotenv path to its repository `.gitignore`.
    GitignoreAppend { secret_path: PathBuf },
    /// Generate a committable `<secret_path>.template` holding the dotenv's
    /// keys but no values.
    EnvTemplate { secret_path: PathBuf },
    /// Move a compromised or vulnerable dependency to the advisory's safe
    /// version, in either direction.
    DependencyUpdate {
        ecosystem: String,
        name: String,
        current_version: String,
        target_version: String,
        manifest_path: PathBuf,
        /// The package-manager argv the recipe will run, for display. The
        /// executor takes its argv from the recipe, never from here.
        command: Vec<String>,
        /// Whether `command[0]` resolved on `PATH` when the plan was made. The
        /// executor re-checks at apply time; this only stops a surface
        /// inviting a doomed click.
        tool_available: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool_advice: Option<String>,
        /// The first blocker, rendered, for surfaces that show prose.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocker: Option<String>,
    },
    /// Manual remediation steps; Husk does not act.
    Manual { steps: Vec<Step> },
}

/// One classified, prioritized fix derived from the scan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemediationProposal {
    pub id: String,
    /// Guide control that owns and explains this proposal.
    pub control_id: String,
    /// Scan findings this proposal addresses. Empty for posture-only controls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finding_ids: Vec<String>,
    pub title: String,
    pub severity: Severity,
    pub class: ExecutionClass,
    /// One-line reason for the classification, composed from the recipe's
    /// structured explanation.
    pub reason: String,
    pub action: RemediationOperation,
    /// The executable truth. Everything else here is derived from it.
    pub recipe: Recipe,
    /// What this fix would change and the command that does the same thing,
    /// rendered once here so the CLI, TUI, web and MCP cannot each compute a
    /// different answer. `None` for a manual proposal, which changes nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<render::FixPreview>,
    /// Every reason this cannot run as-is. Empty means one click is safe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<Blocker>,
    /// The opt-ins that would clear **every** blocker, empty when one of them
    /// is a hard stop.
    ///
    /// The single question a surface asks before offering a "do it anyway"
    /// affordance, answered here rather than by each surface matching prose.
    /// It crosses the wire, so the browser branches on a variant too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overrides: Vec<Override>,
    /// Whether one click runs this right now, with nothing asked of the reader
    /// first. The number behind every "N fixes ready" claim: a blocked fix is
    /// listed but never counted, so the badge matches what opening it shows.
    /// Derived in [`normalize_proposals`], which every plan passes through.
    #[serde(default)]
    pub ready: bool,
}

impl RemediationProposal {
    fn is_ready(&self) -> bool {
        let changes_something = self
            .preview
            .as_ref()
            .is_some_and(|preview| preview.command.is_some() || !preview.diff.is_empty());
        self.class != ExecutionClass::Manual && self.blockers.is_empty() && changes_something
    }

    /// What running this proposal would do, ignoring which finding asked for
    /// it. Two dependency updates with the same target in the same directory
    /// running the same command are one fix, however many manifests in that
    /// directory carry the coordinate.
    fn effect(&self) -> Option<(String, String, PathBuf, Vec<String>)> {
        match &self.action {
            RemediationOperation::DependencyUpdate {
                ecosystem,
                name,
                target_version,
                manifest_path,
                command,
                ..
            } => Some((
                format!("{ecosystem}:{name}"),
                target_version.clone(),
                manifest_path
                    .parent()
                    .unwrap_or(manifest_path)
                    .to_path_buf(),
                command.clone(),
            )),
            _ => None,
        }
    }
}

/// The full, deterministic fix plan for a scan report.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemediationPlan {
    pub generated_at: DateTime<Utc>,
    pub proposals: Vec<RemediationProposal>,
}

impl RemediationPlan {
    pub fn auto_safe_count(&self) -> usize {
        self.count(ExecutionClass::AutoSafe)
    }
    pub fn confirm_count(&self) -> usize {
        self.count(ExecutionClass::Confirm)
    }
    pub fn manual_count(&self) -> usize {
        self.count(ExecutionClass::Manual)
    }
    fn count(&self, class: ExecutionClass) -> usize {
        self.proposals
            .iter()
            .filter(|proposal| proposal.class == class)
            .count()
    }

    /// The proposals addressing a finding, so a surface acting on one row still
    /// gets the cross-finding merged answer rather than re-planning its own.
    pub fn for_finding<'a>(
        &'a self,
        finding_id: &'a str,
    ) -> impl Iterator<Item = &'a RemediationProposal> {
        self.proposals.iter().filter(move |proposal| {
            proposal
                .finding_ids
                .iter()
                .any(|candidate| candidate == finding_id)
        })
    }
}

/// The fix plan for a report.
///
/// The one entry point every surface uses, so the CLI, TUI, web and MCP cannot
/// disagree about a package two advisories both name. Proposals are produced by
/// the guide controls during scan finalization; a report that never went
/// through finalization carries none, and running the controls is the caller's
/// job rather than a hidden fallback here.
pub fn plan(report: &ScanReport) -> RemediationPlan {
    let mut proposals = report.remediations.clone();
    normalize_proposals(&mut proposals);
    RemediationPlan {
        generated_at: report.generated_at,
        proposals,
    }
}

/// Canonicalize proposal output from independently registered controls: one
/// proposal per id, then one per distinct effect, then the `ready` flag every
/// surface counts.
pub fn normalize_proposals(proposals: &mut Vec<RemediationProposal>) {
    let mut by_id = BTreeMap::<String, RemediationProposal>::new();
    for mut proposal in proposals.drain(..) {
        if let Some(existing) = by_id.get_mut(&proposal.id) {
            existing.severity = existing.severity.max(proposal.severity);
            existing.finding_ids.append(&mut proposal.finding_ids);
        } else {
            by_id.insert(proposal.id.clone(), proposal);
        }
    }

    // Keyed on the effect, so the survivor is the lowest id of the group and
    // the choice does not depend on which control ran first.
    let mut by_effect = BTreeMap::<(String, String, PathBuf, Vec<String>), String>::new();
    let mut merges: Vec<(String, String)> = Vec::new();
    for (id, proposal) in &by_id {
        let Some(effect) = proposal.effect() else {
            continue;
        };
        match by_effect.get(&effect) {
            Some(kept) => merges.push((kept.clone(), id.clone())),
            None => {
                by_effect.insert(effect, id.clone());
            }
        }
    }
    for (kept, dropped) in merges {
        let Some(duplicate) = by_id.remove(&dropped) else {
            continue;
        };
        let Some(target) = by_id.get_mut(&kept) else {
            continue;
        };
        target.severity = target.severity.max(duplicate.severity);
        target.finding_ids.extend(duplicate.finding_ids);
    }

    *proposals = by_id.into_values().collect();
    for proposal in proposals.iter_mut() {
        proposal.finding_ids.sort();
        proposal.finding_ids.dedup();
        proposal.ready = proposal.is_ready();
    }
    proposals.sort_by_key(|proposal| std::cmp::Reverse(proposal.severity));
}

// ---------------------------------------------------------------------------
// The `secrets-out-of-code` control's proposals.
// ---------------------------------------------------------------------------

/// The guide control that owns every secret proposal, and the one a rescan
/// settles them against.
const SECRETS_CONTROL: &str = "secrets-out-of-code";

fn rescan() -> op::Verify {
    op::Verify::Rescan {
        control_id: SECRETS_CONTROL.to_string(),
    }
}

/// Instructions only, to be filled in with [`Recipe::step`]. Husk never rotates
/// or deletes a credential; that has to happen at the provider.
fn manual(scope: &Path, headline: &str) -> Recipe {
    Recipe::manual(scope.to_path_buf(), Explain::new(headline), Vec::new())
}

/// Remediation owned by the `secrets-out-of-code` guide control.
///
/// Source-file secrets collapse into one proposal per credential kind per
/// project, because those two are what separate one rotation job from another:
/// an AWS key and a GitHub token are revoked in different consoles, and two
/// projects are two owners. Anything finer would repeat one identical checklist,
/// so the per-finding fact worth keeping is *where* each value is.
pub fn secret_proposals(report: &ScanReport) -> Vec<RemediationProposal> {
    let secrets = report
        .findings
        .iter()
        .filter(|finding| finding.category == crate::rule::Category::Secret)
        .collect::<Vec<_>>();
    let mut repos = RepoCache::default();
    repos.prime(
        &secrets
            .iter()
            .filter_map(|finding| finding.path.clone())
            .filter(|path| is_dotenv_path(path))
            .collect::<Vec<_>>(),
    );
    let mut proposals = Vec::new();
    let mut rotations: BTreeMap<(String, String), Vec<&crate::model::Finding>> = BTreeMap::new();
    for finding in secrets {
        match finding.path.as_ref().filter(|path| is_dotenv_path(path)) {
            Some(path) => proposals.extend(dotenv_proposals(finding, path, &repos)),
            // Husk will not gitignore a source file, and it never rotates a
            // credential for you.
            None => {
                let project = finding.project_id.as_ref().map_or("", |id| id.0.as_str());
                rotations
                    .entry((project.to_string(), finding.title.clone()))
                    .or_default()
                    .push(finding);
            }
        }
    }
    for ((_, kind), findings) in rotations {
        proposals.push(grouped_rotation(report, &kind, &findings));
    }
    proposals
}

/// One rotation card for every secret of one kind in one project.
fn grouped_rotation(
    report: &ScanReport,
    kind: &str,
    findings: &[&crate::model::Finding],
) -> RemediationProposal {
    let root = findings
        .first()
        .and_then(|finding| project_root(report, finding))
        .unwrap_or(Path::new("."));
    let mut locations: Vec<String> = findings
        .iter()
        .filter_map(|finding| finding.path.as_deref())
        .map(|path| relative_label(path, root))
        .collect();
    locations.sort();
    locations.dedup();
    let mut finding_ids: Vec<String> = findings.iter().map(|finding| finding.id.clone()).collect();
    finding_ids.sort();
    finding_ids.dedup();
    let severity = findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::High);
    let title = match locations.as_slice() {
        [only] => format!("{kind} in {only}"),
        many => format!("{kind} in {} files", many.len()),
    };
    rotation_proposal(
        format!("rotate:{}:{kind}", root.display()),
        finding_ids,
        title,
        severity,
        root,
        "These secrets are in source files, so ignoring the files is not the answer.",
        &locations,
    )
}

/// The canonical root of the project a finding was attached to during
/// finalization, when it has one.
fn project_root<'a>(report: &'a ScanReport, finding: &crate::model::Finding) -> Option<&'a Path> {
    report.project_of(finding).map(|p| p.root.as_path())
}

/// A path as the user would name it: the project or repository directory plus
/// the path inside it. Two files sharing a basename have to stay
/// distinguishable in a column narrow enough to truncate the tail, so what
/// differs comes early rather than in a trailing filename.
fn labelled(root: &Path, inside: &str) -> String {
    match root.file_name() {
        Some(name) => format!("{}/{inside}", name.to_string_lossy()),
        None => inside.to_string(),
    }
}

/// [`labelled`] for a path Husk holds only in absolute form.
fn relative_label(path: &Path, root: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(inside) => labelled(root, &inside.to_string_lossy()),
        Err(_) => path.display().to_string(),
    }
}

fn dotenv_proposals(
    finding: &crate::model::Finding,
    path: &Path,
    repos: &RepoCache,
) -> Vec<RemediationProposal> {
    let repo = repos.resolve(path);
    let label = repo
        .as_ref()
        .map(|(_, root, relative)| labelled(root, relative))
        .unwrap_or_else(|| path.display().to_string());
    let mut out = Vec::new();
    out.extend(gitignore_proposal(finding, path, repo, &label));
    out.extend(env_template_proposal(finding, path, &label));
    out.push(rotation_proposal(
        format!("rotate:{}", path.display()),
        vec![finding.id.clone()],
        format!("Rotate any real secret in {label}"),
        finding.severity,
        path.parent().unwrap_or(Path::new(".")),
        "Husk never rotates or deletes a credential; that has to happen at the provider.",
        std::slice::from_ref(&label),
    ));
    out
}

fn gitignore_proposal(
    finding: &crate::model::Finding,
    path: &Path,
    repo: Option<(GitignoreStatus, PathBuf, String)>,
    label: &str,
) -> Option<RemediationProposal> {
    let (status, root, relative) = repo?;
    let recipe = match status {
        // Git's own rules already cover it, so a redundant line would be noise
        // and an already-solved item does not belong on a to-do list.
        GitignoreStatus::AlreadyIgnored => return None,
        GitignoreStatus::Applicable => Recipe::new(
            root.clone(),
            Safety::SafeEdit,
            Explain::new(format!(
                "Adding {relative} to .gitignore stops a future commit from carrying it."
            )),
            rescan(),
        )
        .op(FixOp::AppendUniqueLine {
            path: root.join(".gitignore"),
            line: relative.clone(),
            header: Some("# Added by `husk fix`".to_string()),
        }),
        GitignoreStatus::Tracked => manual(
            &root,
            "Git already tracks this file, so ignoring it now would change nothing.",
        )
        .step(format!(
            "Run `git rm --cached {relative}` to stop tracking it."
        ))
        .step(format!("Add {relative} to .gitignore."))
        .step("Rotate every credential it held; treat the committed values as known."),
    };
    Some(proposal(
        format!("gitignore:{}", path.display()),
        vec![finding.id.clone()],
        format!("Keep {label} out of git"),
        finding.severity,
        recipe,
        RemediationOperation::GitignoreAppend {
            secret_path: path.to_path_buf(),
        },
    ))
}

fn env_template_proposal(
    finding: &crate::model::Finding,
    path: &Path,
    label: &str,
) -> Option<RemediationProposal> {
    let mut template = path.as_os_str().to_owned();
    template.push(".template");
    let template = PathBuf::from(template);
    if template.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(path).ok()?;
    // A template lists the keys the project needs without any values, so it is
    // safe to commit. It never modifies the original and never overwrites an
    // existing template.
    let recipe = Recipe::new(
        path.parent().unwrap_or(Path::new(".")).to_path_buf(),
        Safety::SafeEdit,
        Explain::new(
            "A template lists the keys the project needs without any values, so it is safe to \
             commit.",
        ),
        rescan(),
    )
    .op(FixOp::CreateFile {
        path: template,
        contents: env_template_from(&contents),
    });
    Some(proposal(
        format!("env-template:{}", path.display()),
        vec![finding.id.clone()],
        format!("Generate {label}.template (keys only)"),
        Severity::Low,
        recipe,
        RemediationOperation::EnvTemplate {
            secret_path: path.to_path_buf(),
        },
    ))
}

/// The rotation checklist: revoking twenty credentials is one instruction over
/// twenty locations, not twenty instructions.
///
/// The locations are listed in full and never truncated: a to-do list of
/// credentials to revoke is the wrong thing to shorten.
fn rotation_proposal(
    id: String,
    finding_ids: Vec<String>,
    title: String,
    severity: Severity,
    scope: &Path,
    headline: &str,
    locations: &[String],
) -> RemediationProposal {
    let recipe = manual(scope, headline)
        .step_over(
            "Revoke or rotate each of these credentials at its provider (assume it is \
             compromised if it was ever committed or shared).",
            locations.to_vec(),
        )
        .step(
            "Move each value into a secret store or vault and reference it through the \
             environment.",
        )
        .step(
            "If a value was committed, scrub it from history with a dedicated tool \
             (git-filter-repo, for example); Husk will not rewrite your history.",
        );
    let steps = recipe.steps.clone();
    proposal(
        id,
        finding_ids,
        title,
        severity,
        recipe,
        RemediationOperation::Manual { steps },
    )
}

// ---------------------------------------------------------------------------
// The `dependency-security` control's proposals.
// ---------------------------------------------------------------------------

/// Ecosystem version changes owned by the `dependency-security` guide control.
pub fn dependency_proposals(report: &ScanReport) -> Vec<RemediationProposal> {
    plan_changes(collect_changes(report), &Toolbox::probe())
}

/// Re-plan a proposal with PEP 668's escape hatch acknowledged.
///
/// The acknowledgement is an *input to planning*, so every other preflight
/// check runs again from scratch: an opt-in clears exactly the blocker it names
/// and nothing else.
pub fn with_break_system_packages(proposal: RemediationProposal) -> RemediationProposal {
    let RemediationOperation::DependencyUpdate {
        ecosystem,
        name,
        current_version,
        target_version,
        manifest_path,
        ..
    } = &proposal.action
    else {
        return proposal;
    };
    let mut change = Change::new(name, current_version, target_version, manifest_path.clone());
    change.finding_ids = proposal.finding_ids.clone();
    change.severity = proposal.severity;
    let tools = Toolbox::probe().accepting(Override::BreakSystemPackages);
    plan_changes(vec![(ecosystem.clone(), change)], &tools)
        .into_iter()
        .next()
        .unwrap_or(proposal)
}

/// One [`Change`] per finding that names a package, a current version, and a
/// different safe version.
///
/// Inventory-only ecosystems (every OS package manager, SBOMs, browser
/// extensions) have no fixer and produce no proposal; the finding's own
/// recommendation carries the manual step.
fn change_for(finding: &crate::model::Finding) -> Option<(String, Change)> {
    let package = finding.package.as_ref()?;
    let target = finding.fixed_version.as_deref()?;
    if target == package.version {
        return None;
    }
    ecosystems::fixer_for(&package.ecosystem)?;
    let mut change = Change::new(
        &package.name,
        &package.version,
        target,
        package.manifest_path.clone(),
    );
    change.finding_ids = vec![finding.id.clone()];
    change.severity = finding.severity;
    Some((package.ecosystem.clone(), change))
}

/// Merge every finding into one change per coordinate.
///
/// Several advisories routinely hit one package. Husk keeps the highest safe
/// version and the worst severity, and records the alternatives so the
/// explanation can say a choice was made rather than silently taking the
/// highest.
fn collect_changes(report: &ScanReport) -> Vec<(String, Change)> {
    let mut merged: BTreeMap<String, (String, Change)> = BTreeMap::new();
    for finding in &report.findings {
        let Some((ecosystem, change)) = change_for(finding) else {
            continue;
        };
        match merged.get_mut(&proposal_id(&ecosystem, &change)) {
            Some((_, existing)) => {
                existing.finding_ids.extend(change.finding_ids);
                existing.severity = existing.severity.max(change.severity);
                if !existing.alternatives.contains(&change.target) {
                    existing.alternatives.push(change.target.clone());
                }
                if crate::version::naive_vercmp(&change.target, &existing.target)
                    == std::cmp::Ordering::Greater
                {
                    existing.target = change.target;
                    existing.direction = Direction::between(&existing.current, &existing.target);
                }
            }
            None => {
                let mut change = change;
                change.alternatives.push(change.target.clone());
                merged.insert(proposal_id(&ecosystem, &change), (ecosystem, change));
            }
        }
    }
    merged
        .into_values()
        .map(|(ecosystem, mut change)| {
            change.finding_ids.sort();
            change.finding_ids.dedup();
            change.alternatives.sort();
            if change.alternatives.len() < 2 {
                change.alternatives.clear();
            }
            (ecosystem, change)
        })
        .collect()
}

fn proposal_id(ecosystem: &str, change: &Change) -> String {
    format!(
        "dep:{ecosystem}:{}:{}",
        change.name,
        change.manifest.display()
    )
}

/// Resolve each change's fixer and workspace, then plan every workspace's
/// changes together.
fn plan_changes(changes: Vec<(String, Change)>, tools: &Toolbox) -> Vec<RemediationProposal> {
    let mut grouped: BTreeMap<(String, PathBuf), Vec<Change>> = BTreeMap::new();
    for (ecosystem, change) in changes {
        grouped
            .entry((ecosystem, change.manifest.clone()))
            .or_default()
            .push(change);
    }

    let mut proposals = Vec::new();
    for ((ecosystem, manifest), changes) in grouped {
        let Some(fixer) = ecosystems::fixer_for(&ecosystem) else {
            continue;
        };
        let Some(workspace) = Workspace::read(fixer, &manifest) else {
            continue;
        };
        let program = fixer.program(&workspace);
        for change in &changes {
            // Whether the advisories can be reconciled at all is a fact about
            // the advisory set, not about the ecosystem, so it is settled here
            // rather than in every fixer.
            let planned = ecosystems::plan_change(fixer, change, &workspace, tools).block_if(
                change.targets_conflict(),
                Blocker::ConflictingTargets {
                    targets: change.alternatives.clone(),
                },
            );
            proposals.push(dependency_proposal(&ecosystem, change, planned, program));
        }
    }
    proposals
}

fn dependency_proposal(
    ecosystem: &str,
    change: &Change,
    planned: plan::Plan,
    program: &'static str,
) -> RemediationProposal {
    let plan::Plan { recipe, blockers } = planned;
    let tool_available = !blockers.contains(&Blocker::ToolMissing {
        program: program.to_string(),
    });
    let mut reason = recipe.explain.render();
    if let Some(blocker) = blockers.first() {
        reason = format!("{reason} One click is blocked: {blocker}");
    }

    RemediationProposal {
        id: proposal_id(ecosystem, change),
        control_id: "dependency-security".to_string(),
        finding_ids: change.finding_ids.clone(),
        title: format!(
            "{} {} to {}",
            change.direction.verb(),
            change.name,
            change.target
        ),
        severity: change.severity,
        class: ExecutionClass::Confirm,
        reason,
        action: RemediationOperation::DependencyUpdate {
            ecosystem: ecosystem.to_string(),
            name: change.name.clone(),
            current_version: change.current.clone(),
            target_version: change.target.clone(),
            manifest_path: change.manifest.clone(),
            command: recipe.ops.iter().find_map(FixOp::argv).unwrap_or_default(),
            tool_available,
            tool_advice: (!tool_available).then(|| install_advice_for(program).to_string()),
            blocker: blockers.first().map(Blocker::render),
        },
        preview: exec::preview(&recipe),
        recipe,
        overrides: plan::overrides_for(&blockers).unwrap_or_default(),
        blockers,
        ready: false,
    }
}

fn proposal(
    id: String,
    finding_ids: Vec<String>,
    title: String,
    severity: Severity,
    recipe: Recipe,
    action: RemediationOperation,
) -> RemediationProposal {
    debug_assert!(
        recipe.safety_is_consistent(),
        "recipe for {id} mixes a process spawn into the auto-safe tier"
    );
    RemediationProposal {
        id,
        control_id: SECRETS_CONTROL.to_string(),
        finding_ids,
        title,
        severity,
        class: recipe.safety.into(),
        reason: recipe.explain.render(),
        action,
        preview: exec::preview(&recipe),
        recipe,
        blockers: Vec::new(),
        overrides: Vec::new(),
        ready: false,
    }
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

/// One-line install guidance for a package-manager binary, so a "not
/// installed" state is actionable rather than a dead end. Advice only: Husk
/// never runs an installer itself, because a security scanner does not execute
/// remote shell scripts.
///
/// Every program a recipe may run has an entry here, asserted by a test.
pub fn install_advice_for(program: &str) -> &'static str {
    match program {
        "npm" => "Install Node.js (includes npm): https://nodejs.org",
        "yarn" => {
            "Install Yarn: `npm install -g yarn` (needs Node.js and npm first) or see \
             https://yarnpkg.com/getting-started/install"
        }
        "pnpm" => "Install pnpm: see https://pnpm.io/installation",
        "bun" => "Install Bun: see https://bun.sh",
        "pip" => "Install Python (includes pip): https://www.python.org/downloads",
        "uv" => "Install uv: see https://docs.astral.sh/uv/getting-started/installation",
        "cargo" => "Install Rust (includes cargo): see https://rustup.rs",
        "go" => "Install Go: https://go.dev/dl",
        _ => "Install the package manager this ecosystem needs, then rescan.",
    }
}

/// True for files that are *meant* to be git-ignored (dotenv-style). Husk only
/// ever auto-gitignores these, never a source file that holds a secret.
pub fn is_dotenv_path(path: &Path) -> bool {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => {
            name == ".env"
                || name.starts_with(".env.")
                || name.ends_with(".env")
                || name == ".envrc"
        }
        None => false,
    }
}

/// Extract validated variable names from a dotenv body into a value-free
/// template. Comments, unknown syntax, and continuation lines are deliberately
/// omitted: any of them may hold part of a multiline secret.
pub fn env_template_from(contents: &str) -> String {
    let mut out = String::new();
    for line in contents.lines() {
        let trimmed = line.trim_start();
        let (prefix, body) = match trimmed.strip_prefix("export ") {
            Some(rest) => ("export ", rest),
            None => ("", trimmed),
        };
        let Some((key, _value)) = body.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let valid = key
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
            && key
                .chars()
                .all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        if valid {
            out.push_str(prefix);
            out.push_str(key);
            out.push('=');
            out.push('\n');
        }
    }
    out
}

/// Where a dotenv path stands against git.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GitignoreStatus {
    /// Not yet ignored and not tracked; safe to append.
    Applicable,
    /// Already ignored by git's own rules; nothing to do.
    AlreadyIgnored,
    /// Tracked by git: appending would not stop tracking.
    Tracked,
}

/// How many paths one `git` invocation is handed, so a tree with thousands of
/// secret-bearing files cannot build a command line the kernel refuses.
const GIT_PATH_BATCH: usize = 128;

/// Repository state for every dotenv path in one scan, resolved in bulk.
///
/// A scan can carry hundreds of secret-bearing files, and a `git` invocation
/// costs about a millisecond, so anything per-path dominates the whole report.
/// Both halves are therefore per-repository: discovery walks up to the nearest
/// `.git` in-process and asks git once per repository it finds, and the
/// tracked/ignored queries take every path of a repository at once.
#[derive(Default)]
struct RepoCache {
    /// Directory to the repository root containing it, when there is one.
    roots: BTreeMap<PathBuf, Option<PathBuf>>,
    /// Canonical secret path to its state inside its repository.
    entries: BTreeMap<PathBuf, (GitignoreStatus, PathBuf, String)>,
}

impl RepoCache {
    /// Resolve every path's repository and tracked/ignored state up front.
    ///
    /// Read-only: runs only `git` query subcommands, never a mutation.
    fn prime(&mut self, paths: &[PathBuf]) {
        let mut by_root: BTreeMap<PathBuf, Vec<(PathBuf, String)>> = BTreeMap::new();
        for path in paths {
            let Ok(abs) = path.canonicalize() else {
                continue;
            };
            if self.entries.contains_key(&abs) {
                continue;
            }
            let dir = abs.parent().unwrap_or(&abs).to_path_buf();
            let Some(root) = self.root_of(&dir) else {
                continue;
            };
            let Ok(relative) = abs.strip_prefix(&root) else {
                continue;
            };
            let relative = relative.to_string_lossy().replace('\\', "/");
            by_root.entry(root).or_default().push((abs, relative));
        }
        for (root, mut members) in by_root {
            members.sort();
            members.dedup();
            let relatives = members
                .iter()
                .map(|(_, relative)| relative.as_str())
                .collect::<Vec<_>>();
            let tracked = git_tracked(&root, &relatives);
            let ignored = git_ignored(&root, &relatives);
            for (abs, relative) in members {
                // Tracked wins: a tracked file is not made safe by an ignore
                // rule, and appending one would change nothing.
                let status = if tracked.contains(&relative) {
                    GitignoreStatus::Tracked
                } else if ignored.contains(&relative) {
                    GitignoreStatus::AlreadyIgnored
                } else {
                    GitignoreStatus::Applicable
                };
                self.entries.insert(abs, (status, root.clone(), relative));
            }
        }
    }

    /// The repository state for one path, primed by [`RepoCache::prime`].
    /// `None` when the file is not in a repository, where a `.gitignore` entry
    /// would mean nothing.
    fn resolve(&self, secret_path: &Path) -> Option<(GitignoreStatus, PathBuf, String)> {
        let abs = secret_path.canonicalize().ok()?;
        self.entries.get(&abs).cloned()
    }

    /// The repository root containing `dir`, memoizing every directory walked
    /// through so sibling directories cost a `stat` rather than a subprocess.
    /// The walk stops at the first `.git`, so a repository nested inside
    /// another still resolves to the inner one.
    fn root_of(&mut self, dir: &Path) -> Option<PathBuf> {
        if let Some(known) = self.roots.get(dir) {
            return known.clone();
        }
        let mut walked = Vec::new();
        let mut found = None;
        for ancestor in dir.ancestors() {
            if let Some(known) = self.roots.get(ancestor) {
                found = known.clone();
                break;
            }
            walked.push(ancestor.to_path_buf());
            if ancestor.join(".git").exists() {
                found = git_toplevel(ancestor);
                break;
            }
        }
        for seen in walked {
            self.roots.insert(seen, found.clone());
        }
        found
    }
}

fn git_toplevel(dir: &Path) -> Option<PathBuf> {
    // `-C <dir>` alone is not enough: an inherited `GIT_DIR` would silently
    // redirect discovery onto another repository.
    let out = crate::gitcmd::git_command()
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let top = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if top.is_empty() {
        None
    } else {
        std::fs::canonicalize(top).ok()
    }
}

fn git_in(root: &Path) -> std::process::Command {
    let mut command = crate::gitcmd::git_command();
    command.arg("-C").arg(root);
    command
}

/// Which of `relatives` git tracks. A query that fails contributes nothing,
/// the same answer a non-zero exit gave per path.
fn git_tracked(root: &Path, relatives: &[&str]) -> BTreeSet<String> {
    let mut matched = BTreeSet::new();
    for batch in relatives.chunks(GIT_PATH_BATCH) {
        // `ls-files` reads its arguments as pathspecs, so a path holding `*` or
        // a leading `:` needs saying that it is a literal name. `check-ignore`
        // below takes plain pathnames and rejects the option.
        let Ok(out) = git_in(root)
            .args(["--literal-pathspecs", "ls-files", "-z", "--"])
            .args(batch)
            .stderr(std::process::Stdio::null())
            .output()
        else {
            continue;
        };
        matched.extend(split_nul(&out.stdout));
    }
    matched
}

/// Which of `relatives` git's own ignore rules already cover. `check-ignore`
/// takes its paths on stdin, which is also what keeps a repository holding
/// thousands of them off the command line.
fn git_ignored(root: &Path, relatives: &[&str]) -> BTreeSet<String> {
    use std::io::Write;
    let mut matched = BTreeSet::new();
    for batch in relatives.chunks(GIT_PATH_BATCH) {
        let Ok(mut child) = git_in(root)
            .args(["check-ignore", "-z", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let mut payload = Vec::new();
            for relative in batch {
                payload.extend_from_slice(relative.as_bytes());
                payload.push(0);
            }
            let _ = stdin.write_all(&payload);
        }
        let Ok(out) = child.wait_with_output() else {
            continue;
        };
        matched.extend(split_nul(&out.stdout));
    }
    matched
}

fn split_nul(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect()
}

/// Outcome for one applied or previewed proposal.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActionResult {
    pub id: String,
    pub status: ActionStatus,
    pub detail: String,
    /// Verbatim transcript of any program the proposal ran. A user who is
    /// offered a "run it" button is owed the tool's own output, including the
    /// shell's error when the tool is not there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl ActionResult {
    pub(crate) fn with_output(mut self, output: &[String]) -> Self {
        if !output.is_empty() {
            self.output = Some(output.join("\n"));
        }
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    /// Would apply (dry-run); included so callers can render a preview.
    WouldApply,
    Applied,
    /// Nothing to do (already satisfied).
    Skipped,
    /// Needs the user: blocked, manual, or above this run's authority.
    NeedsUser,
    Failed,
}

/// What one apply run actually did, counted per outcome.
///
/// `skipped` is deliberately not folded into `applied`: "the change was already
/// there" is a different answer from "husk changed it", and a click where
/// fifteen of sixteen proposals were already satisfied must never read as
/// sixteen fixes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct ApplyTally {
    pub applied: usize,
    /// Already satisfied, so the run changed nothing for them.
    pub skipped: usize,
    /// Blocked, manual, or above this run's authority.
    pub needs_user: usize,
    pub failed: usize,
    /// Dry-run previews; zero on any real apply.
    pub previewed: usize,
}

impl ApplyTally {
    pub fn of(results: &[ActionResult]) -> Self {
        let mut tally = Self::default();
        for result in results {
            let counter = match result.status {
                ActionStatus::Applied => &mut tally.applied,
                ActionStatus::Skipped => &mut tally.skipped,
                ActionStatus::NeedsUser => &mut tally.needs_user,
                ActionStatus::Failed => &mut tally.failed,
                ActionStatus::WouldApply => &mut tally.previewed,
            };
            *counter += 1;
        }
        tally
    }

    pub fn total(self) -> usize {
        self.applied + self.skipped + self.needs_user + self.failed + self.previewed
    }

    /// Nothing went wrong and nothing is still waiting on the user. A run that
    /// only skipped is fine: there was nothing to do.
    pub fn ok(self) -> bool {
        self.failed == 0 && self.needs_user == 0
    }

    /// Proposals husk did not carry out.
    pub fn unresolved(self) -> usize {
        self.needs_user + self.failed
    }
}

/// How a `Verify::Rescan` verdict opens. Shared so [`apply_summary`] can tell
/// that a result already asked for a rescan and not ask a second time.
pub(crate) const RESCAN_HINT: &str = "re-scan to confirm";

/// The sentence the web toast and the TUI fix pane both show once a run ends.
/// One wording for both surfaces, and it never counts a skip as a fix.
pub fn apply_summary(results: &[ActionResult]) -> String {
    // One proposal's own detail says more than any count could.
    if let [only] = results {
        return match only.status {
            ActionStatus::Applied if !only.detail.contains(RESCAN_HINT) => {
                format!("{}. Rescan to verify.", only.detail)
            }
            _ => only.detail.clone(),
        };
    }

    let tally = ApplyTally::of(results);
    let problem = results
        .iter()
        .find(|result| !matches!(result.status, ActionStatus::Applied | ActionStatus::Skipped))
        .map(|result| result.detail.as_str());

    let mut clauses = Vec::new();
    if tally.applied > 0 {
        let noun = if tally.applied == 1 { "fix" } else { "fixes" };
        clauses.push(format!("Applied {} {noun}", tally.applied));
    }
    if tally.skipped > 0 {
        clauses.push(format!("{} already in place", tally.skipped));
    }
    if tally.unresolved() > 0 {
        clauses.push(format!("{} could not run", tally.unresolved()));
    }
    if clauses.is_empty() {
        return "Nothing to do.".to_string();
    }
    let mut message = format!("{}.", clauses.join(". "));
    match problem {
        Some(detail) => {
            message.push(' ');
            message.push_str(detail);
        }
        // Nothing changed means nothing to re-verify.
        None if tally.applied > 0 => message.push_str(" Rescan to verify."),
        None => {}
    }
    message
}

#[cfg(test)]
mod tests;
