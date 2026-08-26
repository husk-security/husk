//! Rust: `cargo update --precise` against `Cargo.lock`.
//!
//! - **Manifest, lockfile, or environment?** The *lockfile*, via cargo itself.
//!   Husk never edits `Cargo.lock` by hand.
//! - **How is a transitive dependency pinned?** `--precise` moves the locked
//!   version of any crate in the graph, transitive or not, but only within the
//!   range its dependents declared. Cargo's `[patch]`/`[replace]` could force it
//!   regardless; Husk does not use them, because they change what the crate
//!   *is*, not just its version.
//! - **Is a downgrade the same mechanism?** Yes. `--precise` sets an exact
//!   version in either direction, and the range check applies identically.
//! - **What makes it stick across a rescan?** `Cargo.lock`, which the verify
//!   step re-parses.
//! - **Workspace root vs lockfile directory?** The same: a Cargo workspace has
//!   exactly one `Cargo.lock`, at its root.

use super::EcosystemFixer;
use crate::remediation::op::{Direction, Explain, FixOp, Recipe, Safety, ToolPurpose, Verify};
use crate::remediation::plan::{Blocker, Change, Plan, Toolbox, Workspace};

pub(super) struct CargoFixer;

impl EcosystemFixer for CargoFixer {
    fn ecosystem(&self) -> &'static str {
        "cargo"
    }

    fn probes(&self) -> &'static [&'static str] {
        &["Cargo.toml"]
    }

    fn program(&self, _ws: &Workspace) -> &'static str {
        "cargo"
    }

    fn plan(&self, change: &Change, ws: &Workspace, _tools: &Toolbox) -> Plan {
        let explain = explain(change);
        let declared = ws
            .file("Cargo.toml")
            .and_then(|manifest| declared_requirement(manifest, &change.name));
        if !ws.has("Cargo.toml") {
            return Plan::blocked(
                ws.root.clone(),
                explain,
                Blocker::NoManifest {
                    expected: ws.path("Cargo.toml"),
                    hint: "`cargo update` only runs inside a package or workspace; restore the \
                           Cargo.toml that owns this lockfile."
                        .to_string(),
                },
            );
        }

        Plan::ready(
            Recipe::new(
                ws.root.clone(),
                Safety::NeedsConsent,
                explain
                    .note("Only the locked version moves, inside the range its dependents allow."),
                Verify::Recoordinate {
                    manifests: vec![ws.manifest.clone()],
                    ecosystem: "cargo".to_string(),
                    name: change.name.clone(),
                    expect: change.target.clone(),
                },
            )
            .op(FixOp::RunTool {
                program: "cargo".to_string(),
                args: vec![
                    "update".to_string(),
                    // The spec is positional: `-p` is an undocumented legacy
                    // alias that `cargo update --help` no longer lists.
                    // `name@current` disambiguates, because a lockfile
                    // routinely carries several versions of one crate and a
                    // bare `name` errors out as ambiguous.
                    format!("{}@{}", change.name, change.current),
                    "--precise".to_string(),
                    change.target.clone(),
                ],
                cwd: ws.root.clone(),
                purpose: ToolPurpose::Required,
            }),
        )
        // Cargo only moves a dependency within the range every crate requiring
        // it allows. A jump across that boundary would just error, so say so up
        // front rather than offering a doomed click, and never widen the
        // declared requirement silently on the user's behalf.
        .block_unless(
            reachable(declared.as_deref(), &change.current, &change.target),
            Blocker::RangeConflict {
                declared: declared.unwrap_or_else(|| format!("^{}", change.current)),
                target: change.target.clone(),
            },
        )
    }
}

/// Whether `--precise` can reach `target`.
///
/// An exact requirement (`=1.6.0`) admits one version and nothing else, so
/// `--precise` on anything else fails outright; that is the one shape the
/// compatibility rule below gets wrong. Every other requirement, and every
/// crate the manifest does not name at all (a transitive one, whose requirement
/// lives in a dependent's manifest Husk cannot read), falls back to cargo's
/// compatibility rule over the locked version.
fn reachable(declared: Option<&str>, current: &str, target: &str) -> bool {
    match declared.map(str::trim) {
        Some(requirement) if exact_requirement(requirement) => {
            requirement.trim_start_matches('=').trim() == target
        }
        _ => semver_compatible(current, target),
    }
}

/// A single `=1.2.3` requirement. A comma-separated set is a range even when
/// one of its parts is exact, so only a lone `=` clause counts.
fn exact_requirement(requirement: &str) -> bool {
    requirement.starts_with('=')
        && !requirement.starts_with("==")
        && !requirement.contains(',')
        && !requirement.contains('*')
}

/// The version requirement `Cargo.toml` declares for `name`.
///
/// `None` means the manifest does not name the crate: it is transitive here,
/// and its requirement is in a manifest Husk was not given.
fn declared_requirement(manifest: &str, name: &str) -> Option<String> {
    /// Cargo normalises `-` and `_` in crate names.
    fn same_crate(a: &str, b: &str) -> bool {
        a.len() == b.len()
            && a.bytes()
                .zip(b.bytes())
                .all(|(x, y)| x == y || (x == b'-' && y == b'_') || (x == b'_' && y == b'-'))
    }

    /// A dependency table entry is either the requirement itself or a table
    /// carrying it under `version`. A path or git entry has no version at all.
    fn requirement(entry: &toml::Value) -> Option<String> {
        match entry {
            toml::Value::String(requirement) => Some(requirement.clone()),
            toml::Value::Table(table) => Some(table.get("version")?.as_str()?.to_string()),
            _ => None,
        }
    }

    /// Dependency tables nest under `target.<cfg>` and `workspace`, so the
    /// search is over every table named like one, at any depth.
    fn search(value: &toml::Value, name: &str) -> Option<String> {
        const TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
        let table = value.as_table()?;
        for key in TABLES {
            if let Some(deps) = table.get(key).and_then(toml::Value::as_table)
                && let Some((_, entry)) = deps
                    .iter()
                    .find(|(crate_name, _)| same_crate(crate_name, name))
                && let Some(requirement) = requirement(entry)
            {
                return Some(requirement);
            }
        }
        for (key, nested) in table {
            if !TABLES.contains(&key.as_str())
                && let Some(found) = search(nested, name)
            {
                return Some(found);
            }
        }
        None
    }

    search(&toml::from_str::<toml::Value>(manifest).ok()?, name)
}

fn explain(change: &Change) -> Explain {
    let mut explain = Explain::new(format!(
        "An advisory names {} as safe (currently {}).",
        change.target, change.current
    ));
    if change.direction == Direction::Downgrade {
        explain = explain.note(
            "This is a downgrade: the safe release is older than the locked one. `--precise` \
             moves either way, and nothing from the newer release is built.",
        );
    }
    explain.note("Only the lockfile moves; no declared requirement is widened.")
}

/// Cargo's compatibility rule: same major, and for `0.x` also the same minor.
/// Conservative on purpose. A dependency with an unusually wide requirement
/// (`>=0.7`, `*`) could legitimately cross this boundary, but a blocked row
/// still shows the manual step, which is the safe way to be wrong.
fn semver_compatible(current: &str, target: &str) -> bool {
    let numbers = |version: &str| -> Vec<u64> {
        version
            .trim_start_matches(['v', 'V'])
            .split(['.', '-', '+'])
            .map_while(|part| part.parse().ok())
            .collect()
    };
    let segment = |version: &[u64], index: usize| version.get(index).copied().unwrap_or(0);
    let (current, target) = (numbers(current), numbers(target));
    segment(&current, 0) == segment(&target, 0)
        && (segment(&current, 0) > 0 || segment(&current, 1) == segment(&target, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    fn workspace(with_manifest: bool) -> Workspace {
        Workspace::fixture(
            "/proj",
            "/proj/Cargo.lock",
            "default",
            None,
            if with_manifest {
                &[("Cargo.toml", "[package]\nname = \"app\"\n")]
            } else {
                &[]
            },
        )
    }

    #[test]
    fn a_compatible_bump_becomes_one_precise_update() {
        let change = Change::new("time", "0.3.20", "0.3.36", PathBuf::new());
        let plan = CargoFixer.plan(&change, &workspace(true), &Toolbox::everything());
        assert_eq!(
            plan.recipe.ops,
            vec![FixOp::RunTool {
                program: "cargo".into(),
                args: vec![
                    "update".into(),
                    "time@0.3.20".into(),
                    "--precise".into(),
                    "0.3.36".into()
                ],
                cwd: PathBuf::from("/proj"),
                purpose: ToolPurpose::Required,
            }]
        );
        assert!(plan.runnable());
        assert_eq!(
            crate::remediation::exec::preview(&plan.recipe).and_then(|preview| preview.command),
            Some("cargo update time@0.3.20 --precise 0.3.36".to_string())
        );
    }

    /// A workspace whose `Cargo.toml` declares one dependency.
    fn declaring(requirement: &str) -> Workspace {
        Workspace::fixture(
            "/proj",
            "/proj/Cargo.lock",
            "default",
            None,
            &[(
                "Cargo.toml",
                Box::leak(
                    format!("[package]\nname = \"app\"\n\n[dependencies]\nsmallvec = \"{requirement}\"\n")
                        .into_boxed_str(),
                ),
            )],
        )
    }

    #[test]
    fn an_exact_requirement_blocks_rather_than_offering_a_fix_cargo_will_refuse() {
        // `=1.6.0` admits one version, so `--precise 1.6.1` exits without
        // touching the lockfile. Offering it teaches the user the tool is
        // broken.
        let change = Change::new("smallvec", "1.6.0", "1.6.1", PathBuf::new());
        let plan = CargoFixer.plan(&change, &declaring("=1.6.0"), &Toolbox::everything());
        assert_eq!(
            plan.blockers,
            vec![Blocker::RangeConflict {
                declared: "=1.6.0".into(),
                target: "1.6.1".into(),
            }],
            "the blocker names the requirement the manifest really holds"
        );
        assert!(!plan.runnable());
        // The blocked row still shows the command, and quotes the real
        // requirement rather than an invented one.
        assert!(plan.blockers[0].render().contains("`=1.6.0`"));
        assert!(!plan.recipe.ops.is_empty());
    }

    #[test]
    fn a_caret_requirement_that_admits_the_target_stays_runnable() {
        let change = Change::new("smallvec", "1.6.0", "1.6.1", PathBuf::new());
        for requirement in ["1.6.0", "^1.6", "=1.6.1", ">=1.5, <2.0"] {
            let plan = CargoFixer.plan(&change, &declaring(requirement), &Toolbox::everything());
            assert!(plan.runnable(), "`{requirement}` admits 1.6.1");
        }
    }

    #[test]
    fn a_requirement_is_read_from_every_shape_the_manifest_allows() {
        let table = "[package]\nname = \"app\"\n\n[dependencies]\nsmall_vec = { version = \"=2.0\", features = [\"x\"] }\n";
        assert_eq!(
            declared_requirement(table, "small-vec"),
            Some("=2.0".to_string()),
            "cargo treats `-` and `_` in a crate name as the same"
        );
        let nested = "[target.'cfg(unix)'.dev-dependencies]\nsmallvec = \"=3.0\"\n";
        assert_eq!(
            declared_requirement(nested, "smallvec"),
            Some("=3.0".into())
        );
        // A path or git dependency carries no version, and a crate the manifest
        // never names is transitive.
        let path_only = "[dependencies]\nsmallvec = { path = \"../smallvec\" }\n";
        assert_eq!(declared_requirement(path_only, "smallvec"), None);
        assert_eq!(
            declared_requirement("[dependencies]\nserde = \"1\"\n", "smallvec"),
            None
        );
    }

    #[test]
    fn a_transitive_crate_falls_back_to_the_compatibility_rule() {
        // Its requirement lives in a dependent's manifest husk cannot read, so
        // the caret estimate is all there is.
        let change = Change::new("time", "0.1.45", "0.3.36", PathBuf::new());
        let plan = CargoFixer.plan(&change, &workspace(true), &Toolbox::everything());
        assert_eq!(
            plan.blockers,
            vec![Blocker::RangeConflict {
                declared: "^0.1.45".into(),
                target: "0.3.36".into(),
            }]
        );
    }

    #[test]
    fn a_breaking_jump_is_a_typed_range_conflict_not_a_prose_sentence() {
        let change = Change::new("time", "0.1.45", "0.3.36", PathBuf::new());
        let plan = CargoFixer.plan(&change, &workspace(true), &Toolbox::everything());
        assert_eq!(
            plan.blockers,
            vec![Blocker::RangeConflict {
                declared: "^0.1.45".into(),
                target: "0.3.36".into(),
            }]
        );
        // The blocked row still shows the command it would have run.
        assert!(!plan.recipe.ops.is_empty());
        // 0.x treats the minor as the major; 1.x does not.
        assert!(semver_compatible("1.2.0", "1.9.0"));
        assert!(!semver_compatible("1.2.0", "2.0.0"));
    }

    #[test]
    fn a_downgrade_uses_the_same_precise_command() {
        let change = Change::new("serde", "1.0.220", "1.0.219", PathBuf::new());
        let plan = CargoFixer.plan(&change, &workspace(true), &Toolbox::everything());
        assert_eq!(change.direction, Direction::Downgrade);
        assert!(matches!(
            &plan.recipe.ops[0],
            FixOp::RunTool { args, .. } if args.last().unwrap() == "1.0.219"
        ));
        assert!(plan.runnable());
    }

    #[test]
    fn a_lockfile_without_its_manifest_is_blocked() {
        let change = Change::new("serde", "1.0.1", "1.0.2", PathBuf::new());
        let plan = CargoFixer.plan(&change, &workspace(false), &Toolbox::everything());
        assert!(matches!(
            plan.blockers.as_slice(),
            [Blocker::NoManifest { .. }]
        ));
    }
}
