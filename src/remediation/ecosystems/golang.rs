//! Go: `go get module@version` inside a module.
//!
//! - **Manifest, lockfile, or environment?** `go.mod` *and* `go.sum`, both
//!   rewritten by the go tool. Husk edits neither by hand.
//! - **How is a transitive dependency pinned?** `go get` raises the main
//!   module's requirement on the module directly, which minimal version
//!   selection then propagates. The `replace` directive could force it harder;
//!   Husk does not write one, because it silently redirects a module for every
//!   future build.
//! - **Is a downgrade the same mechanism?** The same *command*, but not the
//!   same *operation*. Per go.dev/ref/mod, downgrading a module also lowers or
//!   removes anything requiring a version above the target, so `go get` can
//!   move modules nobody asked about. Husk therefore re-parses `go.mod` and
//!   `go.sum` afterwards rather than assuming only one coordinate moved.
//! - **What makes it stick across a rescan?** `go mod tidy`. Without it
//!   `go.sum` keeps the old module's lines and the scanner re-flags the stale
//!   entry, so the prune is part of the recipe, as a step whose failure is a
//!   warning rather than a failed fix.
//! - **Workspace root vs lockfile directory?** The directory holding `go.mod`.

use super::EcosystemFixer;
use crate::remediation::op::{Direction, Explain, FixOp, Recipe, Safety, ToolPurpose, Verify};
use crate::remediation::plan::{Blocker, Change, Plan, Toolbox, Workspace};

pub(super) struct GoFixer;

impl EcosystemFixer for GoFixer {
    fn ecosystem(&self) -> &'static str {
        "go"
    }

    fn probes(&self) -> &'static [&'static str] {
        &["go.mod"]
    }

    fn program(&self, _ws: &Workspace) -> &'static str {
        "go"
    }

    fn plan(&self, change: &Change, ws: &Workspace, _tools: &Toolbox) -> Plan {
        let explain = explain(change);
        // A go.sum can outlive its go.mod (a vendored copy, a partial
        // checkout), and there `go get` dies with "go.mod file not found"
        // instead of upgrading anything.
        if !ws.has("go.mod") {
            return Plan::blocked(
                ws.root.clone(),
                explain,
                Blocker::NoManifest {
                    expected: ws.path("go.mod"),
                    hint: format!(
                        "`go get` only runs inside a module. Restore the go.mod, or update {} to \
                         {} in the module that owns it.",
                        change.name, change.target
                    ),
                },
            );
        }
        let target = change.target.strip_prefix('v').unwrap_or(&change.target);

        Plan::ready(
            Recipe::new(
                ws.root.clone(),
                Safety::NeedsConsent,
                explain,
                Verify::Recoordinate {
                    manifests: vec![ws.path("go.mod"), ws.path("go.sum")],
                    ecosystem: "go".to_string(),
                    name: change.name.clone(),
                    expect: change.target.clone(),
                },
            )
            .op(FixOp::RunTool {
                program: "go".to_string(),
                args: vec!["get".to_string(), format!("{}@v{target}", change.name)],
                cwd: ws.root.clone(),
                purpose: ToolPurpose::Required,
            })
            .op(FixOp::RunTool {
                program: "go".to_string(),
                args: vec!["mod".to_string(), "tidy".to_string()],
                cwd: ws.root.clone(),
                purpose: ToolPurpose::BestEffort,
            }),
        )
    }
}

fn explain(change: &Change) -> Explain {
    let mut explain = Explain::new(format!(
        "An advisory names {} as safe (currently {}).",
        change.target, change.current
    ));
    if change.direction == Direction::Downgrade {
        explain = explain.note(
            "This is a downgrade, and in Go that is a graph operation: modules requiring a higher \
             version of this one are lowered or dropped too. Husk re-reads go.mod and go.sum \
             afterwards and reports what actually moved.",
        );
    }
    explain.note("`go mod tidy` prunes the superseded go.sum lines so the next scan agrees.")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    fn module(with_go_mod: bool) -> Workspace {
        Workspace::fixture(
            "/proj",
            "/proj/go.sum",
            "default",
            None,
            if with_go_mod {
                &[("go.mod", "module example.com/app\n")]
            } else {
                &[]
            },
        )
    }

    #[test]
    fn a_go_fix_pins_then_prunes_the_stale_go_sum_lines() {
        let change = Change::new("golang.org/x/net", "v0.35.0", "0.36.0", PathBuf::new());
        let plan = GoFixer.plan(&change, &module(true), &Toolbox::everything());
        assert_eq!(
            plan.recipe.ops,
            vec![
                FixOp::RunTool {
                    program: "go".into(),
                    // The `v` is normalised exactly once, whichever form the
                    // advisory used.
                    args: vec!["get".into(), "golang.org/x/net@v0.36.0".into()],
                    cwd: PathBuf::from("/proj"),
                    purpose: ToolPurpose::Required,
                },
                FixOp::RunTool {
                    program: "go".into(),
                    args: vec!["mod".into(), "tidy".into()],
                    cwd: PathBuf::from("/proj"),
                    purpose: ToolPurpose::BestEffort,
                },
            ]
        );
        assert_eq!(
            crate::remediation::exec::preview(&plan.recipe).and_then(|preview| preview.command),
            Some("go get golang.org/x/net@v0.36.0 && go mod tidy".to_string())
        );
    }

    #[test]
    fn the_verify_step_re_reads_both_files_because_a_downgrade_moves_more_than_one_module() {
        let change = Change::new("golang.org/x/net", "v0.36.0", "0.35.0", PathBuf::new());
        let plan = GoFixer.plan(&change, &module(true), &Toolbox::everything());
        assert_eq!(change.direction, Direction::Downgrade);
        let Verify::Recoordinate { manifests, .. } = &plan.recipe.verify else {
            panic!("a go fix must verify by re-parsing");
        };
        assert_eq!(manifests.len(), 2, "go.mod and go.sum both move");
        assert!(
            plan.recipe
                .explain
                .notes
                .iter()
                .any(|note| note.contains("graph"))
        );
    }

    #[test]
    fn a_go_sum_that_outlived_its_go_mod_is_blocked() {
        let change = Change::new("golang.org/x/net", "v0.35.0", "0.36.0", PathBuf::new());
        let plan = GoFixer.plan(&change, &module(false), &Toolbox::everything());
        assert!(matches!(
            plan.blockers.as_slice(),
            [Blocker::NoManifest { .. }]
        ));
    }
}
