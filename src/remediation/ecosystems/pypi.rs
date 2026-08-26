//! Python: pip against a requirements file, and uv against its lockfile.
//!
//! - **Manifest, lockfile, or environment?** Both, and that is the difficulty.
//!   `pip install` changes the *environment* while the scan reads the
//!   *manifest*, so an install alone is re-flagged by the next scan. The recipe
//!   therefore always pairs the install with a surgical re-pin of the
//!   requirement line; where it cannot make that pair it blocks rather than
//!   reporting a half-success.
//! - **How is a transitive dependency pinned?** A new top-level pin or a
//!   constraints file. Not modelled yet: Husk only rewrites a requirement it
//!   can already see, and says so.
//!
//! On the uv path the project's own declared specifier is checked before the
//! fix is offered, because a target it excludes makes the whole resolution
//! unsatisfiable and `uv lock` exits without touching the lockfile. That check
//! reaches exactly as far as the files on disk: `uv.lock` records each
//! package's dependencies by **name only**, with no specifiers, so a target
//! excluded by some *dependency's* metadata (`requests==2.19.1` holding `idna`
//! below 2.8) cannot be known without resolving against PyPI, which planning
//! does not do. uv reports that case itself and `Verify::Recoordinate` sees the
//! lockfile did not move, so it fails loudly rather than claiming success.
//! - **Is a downgrade the same mechanism?** Yes, exactly. `pip install
//!   name==1.2.3` moves in either direction with no extra flag: `==` is a pin,
//!   not a floor.
//! - **What makes it stick across a rescan?** The rewritten `==` line, which
//!   the verify step re-parses.
//! - **Workspace root vs lockfile directory?** The same.

use super::EcosystemFixer;
use crate::remediation::op::{Direction, Explain, FixOp, Recipe, Safety, ToolPurpose, Verify};
use crate::remediation::plan::{Blocker, Change, Override, Plan, Toolbox, Workspace};
use std::path::Path;

pub(super) struct PypiFixer;

/// PEP 668 explicitly sanctions an override flag, and Husk offers it behind an
/// acknowledgement. The CLI spelling appears exactly once, here.
const BREAK_SYSTEM_PACKAGES: &str = "--break-system-packages";

impl EcosystemFixer for PypiFixer {
    fn ecosystem(&self) -> &'static str {
        "pypi"
    }

    fn probes(&self) -> &'static [&'static str] {
        &["pyproject.toml"]
    }

    fn flavor(&self, manifest: &Path, _text: Option<&str>) -> &'static str {
        match manifest.file_name().and_then(|name| name.to_str()) {
            Some("uv.lock") => "uv",
            Some("poetry.lock") => "poetry",
            Some("pdm.lock") => "pdm",
            Some("Pipfile.lock") => "pipenv",
            _ if std::env::var_os("VIRTUAL_ENV").is_some() => "venv",
            _ => "system",
        }
    }

    fn program(&self, ws: &Workspace) -> &'static str {
        if ws.flavor == "uv" { "uv" } else { "pip" }
    }

    fn plan(&self, change: &Change, ws: &Workspace, tools: &Toolbox) -> Plan {
        let explain = explain(change);
        let verify = Verify::Recoordinate {
            manifests: vec![ws.manifest.clone()],
            ecosystem: "pypi".to_string(),
            name: change.name.clone(),
            expect: change.target.clone(),
        };

        // uv owns its lockfile end to end: one command re-resolves and rewrites
        // it, so there is no manifest/environment split to bridge.
        if ws.flavor == "uv" {
            let declared = ws
                .file("pyproject.toml")
                .and_then(|manifest| declared_specifier(manifest, &change.name));
            return Plan::ready(
                Recipe::new(ws.root.clone(), Safety::NeedsConsent, explain, verify).op(
                    FixOp::RunTool {
                        program: "uv".to_string(),
                        args: vec![
                            "lock".to_string(),
                            "--upgrade-package".to_string(),
                            format!("{}=={}", change.name, change.target),
                        ],
                        cwd: ws.root.clone(),
                        purpose: ToolPurpose::Required,
                    },
                ),
            )
            // uv resolves the whole graph, so a declared specifier that
            // excludes the target makes the lock unsatisfiable and the command
            // exits without touching uv.lock. Say so instead of offering it.
            .block_unless(
                declared
                    .as_deref()
                    .is_none_or(|specifier| specifier_admits(specifier, &change.target)),
                Blocker::RangeConflict {
                    declared: declared.clone().unwrap_or_default(),
                    target: change.target.clone(),
                },
            );
        }
        if matches!(ws.flavor, "poetry" | "pdm" | "pipenv") {
            let command = match ws.flavor {
                "poetry" => "poetry add",
                "pdm" => "pdm update",
                _ => "pipenv install",
            };
            return Plan::blocked(
                ws.root.clone(),
                explain,
                Blocker::NotSupported {
                    hint: format!(
                        "this project is managed by {}, which owns its own lockfile. Run \
                         `{command} {}=={}` yourself so its resolver stays in charge.",
                        ws.flavor, change.name, change.target
                    ),
                },
            );
        }

        // pip installs into the environment, not the requirements file. Locate
        // the exact bytes of the pin now, so the edit is surgical and the
        // executor can detect a stale plan; without one, the next scan reads
        // the old requirement straight back and re-flags it.
        let Some(text) = ws.manifest_text() else {
            return Plan::blocked(
                ws.root.clone(),
                explain,
                Blocker::NoManifest {
                    expected: ws.manifest.clone(),
                    hint: "Restore the requirements file, then retry.".to_string(),
                },
            );
        };
        let Some((start, end)) = pin_span(text, &change.name, &change.current) else {
            return Plan::blocked(
                ws.root.clone(),
                explain,
                Blocker::UnrewritablePin {
                    manifest: ws.manifest.clone(),
                    found: format!(
                        "something other than a plain `{}=={}` line (a version range, an `-r` \
                         include, or a pin in another file)",
                        change.name, change.current
                    ),
                },
            );
        };

        // The environment refuses installs unless the user knowingly opts in.
        // Modelled as a blocker on a complete plan rather than an early
        // return, so acknowledging it re-runs every other check by
        // construction.
        let externally_managed = ws.flavor == "system" && tools.externally_managed_python();
        let accepted = tools.accepts(Override::BreakSystemPackages);
        let mut args = vec![
            "install".to_string(),
            format!("{}=={}", change.name, change.target),
        ];
        let mut explain = explain;
        if externally_managed && accepted {
            args.push(BREAK_SYSTEM_PACKAGES.to_string());
            explain = explain.note(
                "Writing into the system Python at your explicit request. A virtualenv or pipx \
                 would keep the distro's own packages intact.",
            );
        }

        Plan::ready(
            Recipe::new(ws.root.clone(), Safety::NeedsConsent, explain, verify)
                .op(FixOp::RunTool {
                    program: "pip".to_string(),
                    args,
                    cwd: ws.root.clone(),
                    purpose: ToolPurpose::Required,
                })
                .op(FixOp::ReplaceSpan {
                    path: ws.manifest.clone(),
                    start,
                    end,
                    expect: change.current.clone(),
                    replacement: change.target.clone(),
                })
                // pip had to build the target from source and the build blew
                // up. Common for an advisory's *minimum* fixed version: it
                // predates the running Python, PyPI has no wheel for it, and
                // its old sdist no longer builds (pyyaml 5.4 against Cython 3
                // is the classic). pip's own tail is useless here ("See above
                // for output", "not a problem with pip"), so name the cause and
                // the way out.
                .hint(
                    &[
                        "Getting requirements to build wheel did not run successfully",
                        "Preparing metadata (pyproject.toml) did not run successfully",
                        "Failed building wheel",
                    ],
                    format!(
                        "pip had to build {} {} from source (PyPI ships no wheel for it on this \
                         Python) and the build failed. {} is the oldest version the advisory \
                         calls safe; pin a newer release that ships a wheel, then reinstall.",
                        change.name, change.target, change.target
                    ),
                )
                .hint(
                    &["externally-managed-environment"],
                    "This system's Python blocks direct pip installs (PEP 668). Install it in a \
                     virtualenv or with pipx instead.",
                ),
        )
        .block_unless(!externally_managed || accepted, Blocker::ExternallyManaged)
    }
}

fn explain(change: &Change) -> Explain {
    let mut explain = Explain::new(format!(
        "An advisory names {} as safe (currently {}).",
        change.target, change.current
    ));
    if change.direction == Direction::Downgrade {
        explain = explain.note(
            "This is a downgrade: the safe release is older than the installed one. `==` pins \
             exactly, so pip moves down as readily as up.",
        );
    }
    explain.note("The requirement file is re-pinned too, so the next scan agrees.")
}

/// The version specifier `pyproject.toml` declares for `name`, if it declares
/// the distribution at all.
///
/// `None` means the project does not name it: it is transitive, and its
/// constraint lives in some dependency's metadata Husk was not given.
fn declared_specifier(manifest: &str, name: &str) -> Option<String> {
    let document = toml::from_str::<toml::Value>(manifest).ok()?;
    let project = document.get("project")?;
    let groups = project
        .get("optional-dependencies")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|table| table.values());
    project
        .get("dependencies")
        .into_iter()
        .chain(groups)
        .filter_map(toml::Value::as_array)
        .flatten()
        .filter_map(toml::Value::as_str)
        .find_map(|requirement| split_requirement(requirement, name))
}

/// The specifier part of a PEP 508 requirement, when it names `name`.
///
/// `flask [async] >= 2.0 ; python_version < "3.9"` is the full shape: an
/// environment marker after `;`, optional extras in brackets, then the
/// specifier set.
fn split_requirement(requirement: &str, name: &str) -> Option<String> {
    let requirement = requirement.split(';').next()?.trim();
    let end = requirement
        .find(|c: char| !c.is_ascii_alphanumeric() && !"-_.".contains(c))
        .unwrap_or(requirement.len());
    let (declared, rest) = requirement.split_at(end);
    if !normalized_name(declared).eq(&normalized_name(name)) {
        return None;
    }
    let rest = rest.trim_start();
    // Extras bind to the name, not the specifier.
    let rest = match rest.strip_prefix('[') {
        Some(after) => after.split_once(']')?.1.trim_start(),
        None => rest,
    };
    Some(rest.trim().to_string())
}

/// PEP 503 normalisation: runs of `-`, `_` and `.` collapse to one `-`, and
/// case is ignored, so `Jinja2` and `jinja-2` name the same distribution.
fn normalized_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.trim().chars() {
        if "-_.".contains(ch) {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out.trim_matches('-').to_string()
}

/// Whether every clause of a PEP 440 specifier set admits `version`.
///
/// Deliberately conservative: a clause Husk cannot evaluate confidently counts
/// as admitting, because a wrong block refuses a fix that would have worked,
/// while a missed one only leaves today's behaviour of letting uv report the
/// conflict itself.
fn specifier_admits(specifier: &str, version: &str) -> bool {
    specifier
        .split(',')
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
        .all(|clause| clause_admits(clause, version))
}

fn clause_admits(clause: &str, version: &str) -> bool {
    use std::cmp::Ordering;
    let (operator, bound) = ["===", "==", "!=", "~=", "<=", ">=", "<", ">"]
        .into_iter()
        .find_map(|operator| Some((operator, clause.strip_prefix(operator)?.trim())))
        // A bare version with no operator is not valid PEP 440; leave it be.
        .unwrap_or(("", clause));
    let order = || crate::version::naive_vercmp(version, bound);
    match operator {
        "===" => version == bound,
        // A trailing `.*` matches a release prefix rather than one version.
        "==" | "!=" => {
            let matches = match bound.strip_suffix(".*") {
                Some(prefix) => {
                    version == prefix
                        || version
                            .strip_prefix(prefix)
                            .is_some_and(|rest| rest.starts_with('.'))
                }
                None => order() == Ordering::Equal,
            };
            if operator == "==" { matches } else { !matches }
        }
        // `~=X.Y` is `>=X.Y` plus the release prefix one component shorter.
        "~=" => {
            let prefix = bound
                .rsplit_once('.')
                .map(|(head, _)| head)
                .unwrap_or(bound);
            order() != Ordering::Less
                && (version == prefix
                    || version
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('.')))
        }
        "<=" => order() != Ordering::Greater,
        ">=" => order() != Ordering::Less,
        "<" => order() == Ordering::Less,
        ">" => order() == Ordering::Greater,
        _ => true,
    }
}

/// Byte range of `current` on a plain `name==current` requirements line
/// (case-insensitive name, optional `[extras]`, optional trailing comment): the
/// only shape Husk rewrites. Ranges, `-r` includes, and `pyproject.toml` are
/// deliberately left alone.
///
/// Hand-parsed rather than a regex built per call, which is both faster and
/// avoids escaping a user-supplied package name into a pattern.
fn pin_span(contents: &str, name: &str, current: &str) -> Option<(usize, usize)> {
    let mut offset = 0usize;
    for line in contents.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if let Some(at) = pin_offset(trimmed, name, current) {
            return Some((offset + at, offset + at + current.len()));
        }
        offset += line.len();
    }
    None
}

/// Offset of the version within one requirements line, or `None` if the line is
/// not a plain equality pin of `name` at `current`.
fn pin_offset(line: &str, name: &str, current: &str) -> Option<usize> {
    let start = line.len() - line.trim_start().len();
    let rest = &line[start..];
    if !rest.get(..name.len())?.eq_ignore_ascii_case(name) {
        return None;
    }
    let mut cursor = start + name.len();
    // An optional `[extras]` marker.
    if line[cursor..].trim_start().starts_with('[') {
        let open = cursor + (line[cursor..].len() - line[cursor..].trim_start().len());
        let close = line[open..].find(']')? + open;
        cursor = close + 1;
    }
    let after_name = &line[cursor..];
    let equals = after_name.len() - after_name.trim_start().len();
    if !line[cursor + equals..].starts_with("==") {
        return None;
    }
    let mut version_at = cursor + equals + 2;
    version_at += line[version_at..].len() - line[version_at..].trim_start().len();
    if !line[version_at..].starts_with(current) {
        return None;
    }
    // Only a comment may follow the version.
    let tail = line[version_at + current.len()..].trim();
    (tail.is_empty() || tail.starts_with('#')).then_some(version_at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace(flavor: &'static str) -> Workspace {
        Workspace::fixture(
            "/proj",
            "/proj/requirements.txt",
            flavor,
            Some("flask==2.0.1\n"),
            &[],
        )
    }

    #[test]
    fn pin_span_points_at_the_version_bytes_only() {
        let body = "# deps\nflask == 2.0.1  # web\nrequests==2.31.0\n";
        let (start, end) = pin_span(body, "Flask", "2.0.1").unwrap();
        assert_eq!(&body[start..end], "2.0.1");
        // A range is not a plain pin; Husk refuses rather than guessing.
        assert!(pin_span("flask>=2.0.1\n", "flask", "2.0.1").is_none());
        // Extras and case differences still resolve.
        assert!(pin_span("Requests[socks]==2.31.0\n", "requests", "2.31.0").is_some());
        // A prefix must not match a different package.
        assert!(pin_span("flask-cors==2.0.1\n", "flask", "2.0.1").is_none());
        // Nor a version that merely starts with the current one.
        assert!(pin_span("flask==2.0.10\n", "flask", "2.0.1").is_none());
    }

    #[test]
    fn a_pip_fix_installs_then_repins_the_requirement() {
        let ws = workspace("venv");
        let change = Change::new(
            "flask",
            "2.0.1",
            "2.3.2",
            PathBuf::from("/proj/requirements.txt"),
        );
        // The manifest is read from `ws` when the real file is absent, so this
        // test needs no temporary directory.
        let plan = PypiFixer.plan(&change, &ws, &Toolbox::everything());
        assert_eq!(
            plan.recipe.ops,
            vec![
                FixOp::RunTool {
                    program: "pip".into(),
                    args: vec!["install".into(), "flask==2.3.2".into()],
                    cwd: PathBuf::from("/proj"),
                    purpose: ToolPurpose::Required,
                },
                FixOp::ReplaceSpan {
                    path: PathBuf::from("/proj/requirements.txt"),
                    start: 7,
                    end: 12,
                    expect: "2.0.1".into(),
                    replacement: "2.3.2".into(),
                },
            ]
        );
        assert!(plan.runnable());
    }

    #[test]
    fn a_downgrade_is_the_same_command_in_the_other_direction() {
        let ws = Workspace::fixture(
            "/proj",
            "/proj/requirements.txt",
            "venv",
            Some("chalk==5.6.1\n"),
            &[],
        );
        let change = Change::new(
            "chalk",
            "5.6.1",
            "5.6.0",
            PathBuf::from("/proj/requirements.txt"),
        );
        let plan = PypiFixer.plan(&change, &ws, &Toolbox::everything());
        assert_eq!(change.direction, Direction::Downgrade);
        assert!(matches!(
            &plan.recipe.ops[0],
            FixOp::RunTool { args, .. } if args[1] == "chalk==5.6.0"
        ));
    }

    #[test]
    fn a_requirement_husk_cannot_repin_is_blocked_not_half_applied() {
        // Installing without re-pinning would report success and be re-flagged
        // by the next scan.
        let ws = Workspace::fixture(
            "/proj",
            "/proj/requirements.txt",
            "venv",
            Some("flask>=2.0.1\n"),
            &[],
        );
        let change = Change::new(
            "flask",
            "2.0.1",
            "2.3.2",
            PathBuf::from("/proj/requirements.txt"),
        );
        let plan = PypiFixer.plan(&change, &ws, &Toolbox::everything());
        assert!(matches!(
            plan.blockers.as_slice(),
            [Blocker::UnrewritablePin { .. }]
        ));
    }

    #[test]
    fn pep668_is_a_typed_blocker_with_a_typed_opt_in() {
        let ws = workspace("system");
        let change = Change::new(
            "flask",
            "2.0.1",
            "2.3.2",
            PathBuf::from("/proj/requirements.txt"),
        );
        let managed = Toolbox::everything().with_externally_managed_python(true);

        let blocked = PypiFixer.plan(&change, &ws, &managed);
        assert_eq!(blocked.blockers, vec![Blocker::ExternallyManaged]);
        // No surface compares prose to learn the opt-in exists.
        assert_eq!(
            blocked.overrides(),
            Some(vec![Override::BreakSystemPackages])
        );
        // Even blocked, the row can show what would have run.
        assert!(!blocked.recipe.ops.is_empty());

        let accepted = managed.accepting(Override::BreakSystemPackages);
        let allowed = PypiFixer.plan(&change, &ws, &accepted);
        assert!(allowed.runnable());
        assert!(matches!(
            &allowed.recipe.ops[0],
            FixOp::RunTool { args, .. } if args.contains(&BREAK_SYSTEM_PACKAGES.to_string())
        ));
    }

    #[test]
    fn acknowledging_pep668_re_runs_every_other_preflight_check() {
        // The opt-in is an input to planning, not a patch on a finished
        // recipe, so a requirement Husk still cannot re-pin stays blocked.
        let ws = Workspace::fixture(
            "/proj",
            "/proj/requirements.txt",
            "system",
            Some("flask>=2.0.1\n"),
            &[],
        );
        let change = Change::new(
            "flask",
            "2.0.1",
            "2.3.2",
            PathBuf::from("/proj/requirements.txt"),
        );
        let tools = Toolbox::everything()
            .with_externally_managed_python(true)
            .accepting(Override::BreakSystemPackages);
        let plan = PypiFixer.plan(&change, &ws, &tools);
        assert!(matches!(
            plan.blockers.as_slice(),
            [Blocker::UnrewritablePin { .. }]
        ));
    }

    #[test]
    fn uv_projects_route_to_uv_rather_than_pip() {
        let ws = Workspace::fixture("/proj", "/proj/uv.lock", "uv", None, &[]);
        let change = Change::new("flask", "2.0.1", "2.3.2", PathBuf::from("/proj/uv.lock"));
        let plan = PypiFixer.plan(&change, &ws, &Toolbox::everything());
        assert_eq!(PypiFixer.program(&ws), "uv");
        assert!(matches!(
            &plan.recipe.ops[0],
            FixOp::RunTool { program, .. } if program == "uv"
        ));
        assert_eq!(
            crate::remediation::exec::preview(&plan.recipe).and_then(|preview| preview.command),
            Some("uv lock --upgrade-package flask==2.3.2".to_string())
        );
    }

    #[test]
    fn a_pip_fix_shows_the_install_and_leaves_the_repin_to_the_diff() {
        // Rewriting a byte range has no faithful one-liner, so the command is
        // the install alone and the diff beside it carries the re-pin.
        let ws = workspace("venv");
        let change = Change::new(
            "flask",
            "2.0.1",
            "2.3.2",
            PathBuf::from("/proj/requirements.txt"),
        );
        let plan = PypiFixer.plan(&change, &ws, &Toolbox::everything());
        let preview = crate::remediation::exec::preview(&plan.recipe).unwrap();
        assert_eq!(
            preview.command,
            Some("pip install flask==2.3.2".to_string())
        );
        // The re-pin edits a file that is not on disk here, so it contributes
        // neither a diff nor a fragment. The one-liner must not then read as
        // the whole fix.
        assert!(!preview.complete);
        assert_eq!(
            crate::remediation::render::shell_equivalent(
                &plan.recipe.ops[1],
                Some("flask==2.0.1\n"),
                Some("pip")
            ),
            None
        );
    }

    #[test]
    fn a_uv_pin_that_excludes_the_target_blocks_rather_than_failing_the_lock() {
        // `uv lock --upgrade-package jinja2==3.1.6` against a declared
        // `jinja2==2.11.2` exits with "No solution found" and leaves uv.lock
        // untouched, so the fix must not be offered as runnable.
        let pyproject = "[project]\nname = \"app\"\ndependencies = [\"jinja2==2.11.2\"]\n";
        let ws = Workspace::fixture(
            "/proj",
            "/proj/uv.lock",
            "uv",
            None,
            &[("pyproject.toml", pyproject)],
        );
        let change = Change::new("jinja2", "2.11.2", "3.1.6", PathBuf::from("/proj/uv.lock"));
        let plan = PypiFixer.plan(&change, &ws, &Toolbox::everything());
        assert_eq!(
            plan.blockers,
            vec![Blocker::RangeConflict {
                declared: "==2.11.2".into(),
                target: "3.1.6".into(),
            }]
        );
        assert!(!plan.runnable());
        // Blocked or not, the row still shows what would have run.
        assert_eq!(
            crate::remediation::exec::preview(&plan.recipe).and_then(|preview| preview.command),
            Some("uv lock --upgrade-package jinja2==3.1.6".to_string())
        );
    }

    #[test]
    fn a_uv_specifier_that_admits_the_target_stays_runnable() {
        let change = Change::new("jinja2", "2.11.2", "3.1.6", PathBuf::from("/proj/uv.lock"));
        for declared in [
            "jinja2>=2.0",
            "jinja2",
            "Jinja2 >= 2.0, < 4",
            "jinja-2~=3.1",
        ] {
            let pyproject = format!("[project]\nname = \"app\"\ndependencies = [\"{declared}\"]\n");
            let ws = Workspace::fixture(
                "/proj",
                "/proj/uv.lock",
                "uv",
                None,
                &[("pyproject.toml", Box::leak(pyproject.into_boxed_str()))],
            );
            assert!(
                PypiFixer
                    .plan(&change, &ws, &Toolbox::everything())
                    .runnable(),
                "`{declared}` admits 3.1.6"
            );
        }
        // A distribution the project never names is transitive: its constraint
        // is in metadata husk was not given, so nothing is claimed about it.
        let other = "[project]\nname = \"app\"\ndependencies = [\"requests==2.19.1\"]\n";
        let ws = Workspace::fixture(
            "/proj",
            "/proj/uv.lock",
            "uv",
            None,
            &[("pyproject.toml", other)],
        );
        assert!(
            PypiFixer
                .plan(&change, &ws, &Toolbox::everything())
                .runnable()
        );
    }

    #[test]
    fn specifier_clauses_are_evaluated_per_pep440_and_default_to_admitting() {
        assert!(specifier_admits(">=2.0,<4", "3.1.6"));
        assert!(!specifier_admits(">=2.0,<3", "3.1.6"));
        assert!(!specifier_admits("==2.11.2", "3.1.6"));
        assert!(specifier_admits("==3.1.*", "3.1.6"));
        assert!(!specifier_admits("==3.2.*", "3.1.6"));
        assert!(!specifier_admits("!=3.1.6", "3.1.6"));
        assert!(specifier_admits("~=3.1.0", "3.1.6"));
        assert!(!specifier_admits("~=3.2.0", "3.1.6"));
        assert!(specifier_admits("===3.1.6", "3.1.6"));
        // No specifier at all, and a clause husk does not model, both admit:
        // refusing a fix that would have worked is the worse mistake.
        assert!(specifier_admits("", "3.1.6"));
        assert!(specifier_admits("@ https://example.invalid/x.whl", "3.1.6"));
    }

    #[test]
    fn a_declared_specifier_is_found_past_extras_and_markers() {
        let pyproject = "[project]\nname = \"app\"\ndependencies = [\
            \"Flask [async] >= 2.0 ; python_version < '3.9'\"]\n\
            [project.optional-dependencies]\ndev = [\"jinja2==2.11.2\"]\n";
        assert_eq!(
            declared_specifier(pyproject, "flask"),
            Some(">= 2.0".to_string())
        );
        // Optional groups are declared dependencies too.
        assert_eq!(
            declared_specifier(pyproject, "Jinja2"),
            Some("==2.11.2".to_string())
        );
        assert_eq!(declared_specifier(pyproject, "requests"), None);
    }

    #[test]
    fn poetry_projects_are_refused_with_the_command_to_run() {
        let ws = Workspace::fixture("/proj", "/proj/poetry.lock", "poetry", None, &[]);
        let change = Change::new(
            "flask",
            "2.0.1",
            "2.3.2",
            PathBuf::from("/proj/poetry.lock"),
        );
        let plan = PypiFixer.plan(&change, &ws, &Toolbox::everything());
        assert!(
            plan.blockers[0]
                .render()
                .contains("poetry add flask==2.3.2")
        );
    }

    #[test]
    fn the_pip_source_build_heuristic_travels_with_the_recipe() {
        // pip pads a source-build failure with pointers to output husk does not
        // have, so the module that knows pip names the cause.
        let ws = Workspace::fixture(
            "/proj",
            "/proj/requirements.txt",
            "venv",
            Some("pyyaml==5.3\n"),
            &[],
        );
        let change = Change::new(
            "pyyaml",
            "5.3",
            "5.4",
            PathBuf::from("/proj/requirements.txt"),
        );
        let plan = PypiFixer.plan(&change, &ws, &Toolbox::everything());
        assert!(plan.recipe.failure_hints.iter().any(|hint| {
            hint.markers
                .iter()
                .any(|marker| marker.contains("build wheel"))
                && hint.detail.contains("ships no wheel")
        }));
    }
}
