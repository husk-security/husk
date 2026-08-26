//! JavaScript: npm, yarn (classic and berry), pnpm, bun.
//!
//! The five questions every fixer module answers:
//!
//! - **Manifest, lockfile, or environment?** The *manifest*. Husk writes an
//!   override entry and lets the package manager re-resolve the lockfile; it
//!   never reverse-engineers a lockfile format.
//! - **How is a transitive dependency pinned?** Through the override field,
//!   which forces a version regardless of what any dependent declared. A plain
//!   `npm install name@version` only adds or bumps a *direct* dependency, and
//!   most real vulnerable packages are nested transitive copies deep in
//!   `node_modules` that such a command never touches. Which field, and
//!   **which file**, differs per package manager: see [`override_target`].
//! - **Is a downgrade the same mechanism?** Yes. An override sets an exact
//!   version in either direction. The asymmetry is only in resolvability: a
//!   downgrade is far more likely to fall outside a direct dependent's
//!   declared range, so it carries an extra note.
//! - **What makes it stick across a rescan?** The lockfile, which the recipe's
//!   verify step re-parses. That is what catches an override written to a
//!   location the installed package manager no longer reads.
//! - **Workspace root vs lockfile directory?** The same. npm, yarn, pnpm and
//!   bun each keep exactly one lockfile, at the workspace root, and all four
//!   override fields are documented as root-only. A project can still have
//!   several of these lockfiles side by side (a leftover `package-lock.json`
//!   next to the `bun.lock` actually in use); each is a distinct fix target
//!   with its own install command, even though every one of them is tagged
//!   ecosystem `npm`.

use super::EcosystemFixer;
use crate::remediation::op::{
    Direction, DocFormat, Explain, FixOp, Recipe, Safety, ToolPurpose, Verify,
};
use crate::remediation::plan::{Blocker, Change, Plan, Toolbox, Workspace};
use std::path::Path;

pub(super) struct NpmFixer;

/// Where this package manager's override field actually lives.
///
/// **pnpm is the trap.** pnpm reads overrides from `pnpm-workspace.yaml`, not
/// `package.json`'s `pnpm` field: pnpm 11 removed that reader (silently on
/// early releases; newer ones print a warning), so writing there rewrites the
/// file, exits 0, and installs the vulnerable version anyway, which is the
/// worst failure a fix engine has. Confirmed on pnpm 11.17.0: `pnpm.overrides`
/// in `package.json` is ignored and warned about; `overrides:` in
/// `pnpm-workspace.yaml` takes effect and cascades. Yarn (both lines) and bun
/// read `package.json`.
fn override_target(flavor: &str) -> (&'static str, DocFormat, &'static str) {
    match flavor {
        "pnpm" => ("pnpm-workspace.yaml", DocFormat::YamlBlock, "overrides"),
        "yarn" | "yarn-berry" => ("package.json", DocFormat::Json, "resolutions"),
        // Bun reads npm's `overrides` field verbatim.
        _ => ("package.json", DocFormat::Json, "overrides"),
    }
}

/// The relock command, with lifecycle scripts **off** on every path.
///
/// A security scanner must not execute `preinstall`/`postinstall` code from the
/// very tree it just flagged as compromised. Where the manager can refresh the
/// lockfile without materialising `node_modules` at all it does, which is both
/// safer and faster; the user runs their own `npm ci` afterwards.
fn relock(flavor: &str) -> (&'static str, Vec<String>) {
    match flavor {
        "yarn" => ("yarn", vec!["install".into(), "--ignore-scripts".into()]),
        // Berry rejects unknown flags, and disables fetching and building
        // through the install mode rather than a script flag.
        "yarn-berry" => (
            "yarn",
            vec!["install".into(), "--mode=update-lockfile".into()],
        ),
        "pnpm" => (
            "pnpm",
            vec![
                "install".into(),
                "--lockfile-only".into(),
                "--ignore-scripts".into(),
            ],
        ),
        "bun" => (
            "bun",
            vec![
                "install".into(),
                "--lockfile-only".into(),
                "--ignore-scripts".into(),
            ],
        ),
        _ => (
            "npm",
            vec![
                "install".into(),
                "--package-lock-only".into(),
                "--ignore-scripts".into(),
            ],
        ),
    }
}

impl EcosystemFixer for NpmFixer {
    fn ecosystem(&self) -> &'static str {
        "npm"
    }

    fn probes(&self) -> &'static [&'static str] {
        &["package.json", "pnpm-workspace.yaml"]
    }

    fn flavor(&self, manifest: &Path, text: Option<&str>) -> &'static str {
        match manifest.file_name().and_then(|name| name.to_str()) {
            // Yarn's two lines need different install flags, and they are
            // distinguishable from the lockfile itself: berry writes a
            // YAML-ish file containing `__metadata:`, classic writes
            // `# yarn lockfile v1`.
            Some("yarn.lock") if text.is_some_and(|text| text.contains("__metadata:")) => {
                "yarn-berry"
            }
            Some("yarn.lock") => "yarn",
            Some("pnpm-lock.yaml") => "pnpm",
            Some("bun.lock") => "bun",
            _ => "npm",
        }
    }

    fn program(&self, ws: &Workspace) -> &'static str {
        relock(ws.flavor).0
    }

    fn plan(&self, change: &Change, ws: &Workspace, _tools: &Toolbox) -> Plan {
        // `package.json` is the project marker for every flavor, even when the
        // override itself goes elsewhere: without it there is no project to
        // install.
        let Some(package_json) = ws.file("package.json") else {
            return Plan::blocked(
                ws.root.clone(),
                explain(change, ws.flavor, "overrides", "package.json", false),
                Blocker::NoManifest {
                    expected: ws.path("package.json"),
                    hint: "Restore the project's package.json, then retry, or update the \
                           lockfile with your package manager by hand."
                        .to_string(),
                },
            );
        };
        let (file, format, field) = override_target(ws.flavor);
        // pnpm keeps its overrides outside package.json, so nothing there is
        // touched and no direct entry is in play.
        let direct = if format == DocFormat::Json {
            direct_sections(package_json, &change.name)
        } else {
            Vec::new()
        };

        let mut recipe = Recipe::new(
            ws.root.clone(),
            Safety::NeedsConsent,
            explain(change, ws.flavor, field, file, !direct.is_empty()),
            Verify::Recoordinate {
                manifests: vec![ws.manifest.clone()],
                ecosystem: "npm".to_string(),
                name: change.name.clone(),
                expect: change.target.clone(),
            },
        )
        .op(FixOp::SetValue {
            path: ws.path(file),
            format,
            key: vec![field.to_string(), change.name.clone()],
            value: change.target.clone(),
        });

        // npm rejects a manifest whose direct spec disagrees with its own
        // override: "you may not set an override for a package you directly
        // depend on unless both share the exact same spec" (EOVERRIDE). Bump
        // the matching direct entry so the pin actually installs.
        for section in direct {
            recipe = recipe.op(FixOp::SetValue {
                path: ws.path("package.json"),
                format: DocFormat::Json,
                key: vec![section.to_string(), change.name.clone()],
                value: change.target.clone(),
            });
        }

        let (program, args) = relock(ws.flavor);
        Plan::ready(
            recipe
                .op(FixOp::RunTool {
                    program: program.to_string(),
                    args,
                    cwd: ws.root.clone(),
                    purpose: ToolPurpose::Required,
                })
                .hint(
                    &["ERESOLVE", "EOVERRIDE"],
                    format!(
                        "The install could not satisfy the pin: something in the tree declares a \
                         range that excludes {} {}. Upgrade the package that declares it, or pin \
                         that one too.",
                        change.name, change.target
                    ),
                ),
        )
    }
}

fn explain(change: &Change, flavor: &str, field: &str, file: &str, direct: bool) -> Explain {
    let mut explain = Explain::new(format!(
        "An advisory names {} as safe (currently {}).",
        change.target, change.current
    ))
    .note(format!(
        "Pins it through {file}'s `{field}` field, which covers copies nested under other \
         packages, not just a top-level dependency."
    ))
    .note("Lifecycle scripts stay off during the reinstall, so nothing in the flagged tree runs.");
    if direct {
        explain = explain.note(format!(
            "{} is also declared as a direct dependency, so that declaration moves to the same \
             version. Left at the old one it would bring the old version back the moment the \
             `{field}` entry is removed.{}",
            change.name,
            if flavor == "npm" {
                " npm also refuses an override that disagrees with a direct dependency."
            } else {
                ""
            }
        ));
    }
    if flavor == "pnpm" {
        explain = explain.note(
            "pnpm reads overrides from pnpm-workspace.yaml, not package.json. On pnpm 9 or older \
             the entry has no effect, and the check after the fix will say so.",
        );
    }
    if change.direction == Direction::Downgrade {
        explain = explain.note(
            "This is a downgrade: the safe release is older than the installed one. An override \
             forces it regardless of ranges, so a package declaring a newer requirement may \
             refuse to install; the install step will say so if it does.",
        );
    }
    if !change.alternatives.is_empty() {
        explain = explain.note(format!(
            "More than one advisory applies. Husk pinned the highest safe version of {}.",
            change.alternatives.join(", ")
        ));
    }
    explain
}

/// The `package.json` sections that declare `name` directly.
fn direct_sections(package_json: &str, name: &str) -> Vec<&'static str> {
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(package_json) else {
        return Vec::new();
    };
    ["dependencies", "devDependencies", "optionalDependencies"]
        .into_iter()
        .filter(|section| doc.get(section).and_then(|deps| deps.get(name)).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace(lockfile: &str, flavor: &'static str, package_json: &str) -> Workspace {
        Workspace::fixture(
            "/proj",
            &format!("/proj/{lockfile}"),
            flavor,
            None,
            &[("package.json", package_json)],
        )
    }

    fn plan(lockfile: &str, flavor: &'static str, package_json: &str, change: &Change) -> Plan {
        let ws = workspace(lockfile, flavor, package_json);
        NpmFixer.plan(change, &ws, &Toolbox::everything())
    }

    #[test]
    fn npm_writes_an_override_and_relocks_without_running_lifecycle_scripts() {
        let change = Change::new("lodash", "4.17.20", "4.17.21", PathBuf::new());
        let plan = plan("package-lock.json", "npm", r#"{"name":"app"}"#, &change);
        assert_eq!(
            plan.recipe.ops,
            vec![
                FixOp::SetValue {
                    path: PathBuf::from("/proj/package.json"),
                    format: DocFormat::Json,
                    key: vec!["overrides".into(), "lodash".into()],
                    value: "4.17.21".into(),
                },
                FixOp::RunTool {
                    program: "npm".into(),
                    args: vec![
                        "install".into(),
                        "--package-lock-only".into(),
                        "--ignore-scripts".into()
                    ],
                    cwd: PathBuf::from("/proj"),
                    purpose: ToolPurpose::Required,
                },
            ]
        );
        assert!(plan.runnable());
    }

    #[test]
    fn a_direct_dependency_is_bumped_too_so_npm_does_not_reject_the_override() {
        let change = Change::new("lodash", "4.17.20", "4.17.21", PathBuf::new());
        let plan = plan(
            "package-lock.json",
            "npm",
            r#"{"dependencies":{"lodash":"^4.17.20"}}"#,
            &change,
        );
        assert!(plan.recipe.ops.contains(&FixOp::SetValue {
            path: PathBuf::from("/proj/package.json"),
            format: DocFormat::Json,
            key: vec!["dependencies".into(), "lodash".into()],
            value: "4.17.21".into(),
        }));
    }

    #[test]
    fn pnpm_writes_to_pnpm_workspace_yaml_not_package_json() {
        let change = Change::new("lodash", "4.17.20", "4.17.21", PathBuf::new());
        let plan = plan("pnpm-lock.yaml", "pnpm", r#"{"name":"app"}"#, &change);
        assert_eq!(
            plan.recipe.ops[0],
            FixOp::SetValue {
                path: PathBuf::from("/proj/pnpm-workspace.yaml"),
                format: DocFormat::YamlBlock,
                key: vec!["overrides".into(), "lodash".into()],
                value: "4.17.21".into(),
            }
        );
        assert!(
            !format!("{:?}", plan.recipe.ops).contains(r#""pnpm", "overrides""#),
            "the legacy package.json#pnpm.overrides location must never be written again"
        );
    }

    #[test]
    fn yarn_classic_and_berry_are_told_apart_by_their_lockfile() {
        let berry = NpmFixer.flavor(
            Path::new("/proj/yarn.lock"),
            Some("__metadata:\n  version: 8\n"),
        );
        let classic = NpmFixer.flavor(Path::new("/proj/yarn.lock"), Some("# yarn lockfile v1\n"));
        assert_eq!(berry, "yarn-berry");
        assert_eq!(classic, "yarn");
        // Berry errors on unknown flags; the install mode is how it skips
        // fetching and building.
        assert_eq!(relock(berry).1, vec!["install", "--mode=update-lockfile"]);
        assert_eq!(relock(classic).1, vec!["install", "--ignore-scripts"]);
        // Both lines still read `resolutions` from package.json; only pnpm
        // moved its settings out.
        assert_eq!(override_target(berry).0, "package.json");
    }

    #[test]
    fn every_relock_command_disables_lifecycle_scripts_or_builds() {
        for flavor in ["npm", "yarn", "yarn-berry", "pnpm", "bun", "deno"] {
            let (_, args) = relock(flavor);
            assert!(
                args.iter()
                    .any(|arg| arg == "--ignore-scripts" || arg == "--mode=update-lockfile"),
                "{flavor} would execute lifecycle scripts from the flagged tree"
            );
        }
    }

    #[test]
    fn every_relock_that_can_skip_node_modules_does() {
        // Refreshing the lockfile without materialising the tree is both safer
        // and faster; the user runs their own install afterwards. Only yarn
        // classic has no such mode, so it is the one flavor that writes
        // node_modules.
        for (flavor, flag) in [
            ("npm", "--package-lock-only"),
            ("pnpm", "--lockfile-only"),
            ("bun", "--lockfile-only"),
            ("yarn-berry", "--mode=update-lockfile"),
        ] {
            assert!(
                relock(flavor).1.iter().any(|arg| arg == flag),
                "{flavor} would install node_modules when it does not have to"
            );
        }
    }

    /// The one-liner each flavor's users are shown. Husk's claim is that
    /// running it by hand lands where applying would, so the exact string is
    /// part of the contract.
    #[test]
    fn each_flavor_is_shown_its_own_managers_commands() {
        let change = Change::new("minimist", "1.2.0", "1.2.6", PathBuf::new());
        let declared = r#"{"dependencies":{"minimist":"1.2.0"}}"#;
        let command = |lockfile: &str, flavor: &'static str| {
            crate::remediation::exec::preview(&plan(lockfile, flavor, declared, &change).recipe)
                .and_then(|preview| preview.command)
                .expect("a javascript fix always has a one-liner")
        };

        // Bun ships `bun pm pkg`, so its users are never sent to npm, which a
        // bun-only machine need not have.
        assert_eq!(
            command("bun.lock", "bun"),
            "bun pm pkg set overrides.minimist=1.2.6 && bun pm pkg set \
             dependencies.minimist=1.2.6 && bun install --lockfile-only --ignore-scripts"
        );
        assert_eq!(
            command("package-lock.json", "npm"),
            "npm pkg set overrides.minimist=1.2.6 && npm pkg set dependencies.minimist=1.2.6 && \
             npm install --package-lock-only --ignore-scripts"
        );
        assert_eq!(
            command("yarn.lock", "yarn"),
            "npm pkg set resolutions.minimist=1.2.6 && npm pkg set dependencies.minimist=1.2.6 && \
             yarn install --ignore-scripts"
        );
        assert_eq!(
            command("yarn.lock", "yarn-berry"),
            "npm pkg set resolutions.minimist=1.2.6 && npm pkg set dependencies.minimist=1.2.6 && \
             yarn install --mode=update-lockfile"
        );
        // pnpm's override lands in YAML, which no one-liner expresses, so the
        // command is the relock alone and the diff beside it carries the edit.
        assert_eq!(
            command("pnpm-lock.yaml", "pnpm"),
            "pnpm install --lockfile-only --ignore-scripts"
        );
    }

    #[test]
    fn a_bun_fix_edits_the_manifest_then_refreshes_only_the_lockfile() {
        let change = Change::new("minimist", "1.2.0", "1.2.6", PathBuf::new());
        let plan = plan(
            "bun.lock",
            "bun",
            r#"{"dependencies":{"minimist":"1.2.0"}}"#,
            &change,
        );
        assert_eq!(
            plan.recipe.ops,
            vec![
                FixOp::SetValue {
                    path: PathBuf::from("/proj/package.json"),
                    format: DocFormat::Json,
                    key: vec!["overrides".into(), "minimist".into()],
                    value: "1.2.6".into(),
                },
                FixOp::SetValue {
                    path: PathBuf::from("/proj/package.json"),
                    format: DocFormat::Json,
                    key: vec!["dependencies".into(), "minimist".into()],
                    value: "1.2.6".into(),
                },
                FixOp::RunTool {
                    program: "bun".into(),
                    args: vec![
                        "install".into(),
                        "--lockfile-only".into(),
                        "--ignore-scripts".into()
                    ],
                    cwd: PathBuf::from("/proj"),
                    purpose: ToolPurpose::Required,
                },
            ]
        );
        assert!(plan.runnable());
    }

    #[test]
    fn bumping_the_direct_declaration_says_why_it_is_part_of_the_fix() {
        // Two edits to one file reads as arbitrary without the reason, and the
        // reason is what tells a reader the override is not redundant.
        let change = Change::new("minimist", "1.2.0", "1.2.6", PathBuf::new());
        let direct = plan(
            "package-lock.json",
            "npm",
            r#"{"dependencies":{"minimist":"1.2.0"}}"#,
            &change,
        );
        assert!(
            direct
                .recipe
                .explain
                .notes
                .iter()
                .any(|note| note.contains("direct dependency"))
        );
        // A purely transitive coordinate gets one edit and no such note.
        let transitive = plan("package-lock.json", "npm", r#"{"name":"app"}"#, &change);
        assert!(
            !transitive
                .recipe
                .explain
                .notes
                .iter()
                .any(|note| note.contains("direct dependency"))
        );
        assert_eq!(transitive.recipe.ops.len(), 2);
    }

    #[test]
    fn a_downgrade_uses_the_same_mechanism_and_says_it_is_one() {
        // The compromised release is often the *newer* one; an override pins
        // in either direction.
        let change = Change::new("chalk", "5.6.1", "5.6.0", PathBuf::new());
        let plan = plan("package-lock.json", "npm", r#"{"name":"app"}"#, &change);
        assert!(matches!(plan.recipe.ops[0], FixOp::SetValue { .. }));
        assert!(
            plan.recipe
                .explain
                .notes
                .iter()
                .any(|note| note.contains("downgrade"))
        );
    }

    #[test]
    fn a_project_without_a_package_json_is_blocked_but_still_explains_itself() {
        let ws = Workspace::fixture("/proj", "/proj/package-lock.json", "npm", None, &[]);
        let change = Change::new("lodash", "4.17.20", "4.17.21", PathBuf::new());
        let plan = NpmFixer.plan(&change, &ws, &Toolbox::everything());
        assert!(matches!(
            plan.blockers.as_slice(),
            [Blocker::NoManifest { .. }]
        ));
        assert!(!plan.runnable());
        // A hard stop offers no opt-in button.
        assert_eq!(plan.overrides(), None);
    }
}
