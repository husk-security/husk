//! Pluggable per-ecosystem *fix* knowledge, the sibling of
//! [`crate::scan::targets`].
//!
//! A [`ScanTarget`](crate::scan::targets::ScanTarget) answers "which files, and
//! which coordinates are in them". An [`EcosystemFixer`] answers "how do I move
//! one of those coordinates to another version inside a real project". Both
//! registries are keyed on the **same ecosystem id** and linked by a test
//! ([`tests::every_fixer_targets_a_scanned_ecosystem`]), which is what lets a
//! fix verify itself by re-running the scanner's own parser.
//!
//! They are separate traits on purpose:
//!
//! - `ScanTarget`'s read-only invariant is a *type* property today (the
//!   parallel scan walk holds those trait objects). Hanging `fn fix()` off it
//!   would put a write capability on the object graph the scan walks.
//! - The cardinalities differ in both directions: five `ScanTarget`s
//!   (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`,
//!   `deno.lock`) emit ecosystem `npm` and share one fix strategy, while ~90
//!   targets (dpkg, rpm, browser extensions, SBOMs) will never have a fixer.
//! - A fix needs an axis a scan does not: the [`Workspace`], the *project* that
//!   owns a file, which for a JS override is the repo root rather than the
//!   lockfile's own directory.
//!
//! **Planning is pure by signature.** A fixer is handed data (a `Workspace`
//! whose files are already read, a `Toolbox` already probed) and returns
//! data. It cannot read, write, or spawn, exactly as a `ScanTarget` parse
//! function cannot. Only [`crate::remediation::exec`] touches the world.
//!
//! **Adding fix support for an ecosystem is one module plus one line in
//! [`default_fixers`].** The contributor checklist is in `AGENTS.md`.

use super::op::FixOp;
use super::plan::{Blocker, Change, Plan, Toolbox, Workspace};
use std::path::Path;

// Private on purpose: a fixer that is never registered in `default_fixers` is
// then never constructed, which `-D warnings` turns into a build failure. The
// registry line is not something you can forget.
mod cargo;
mod golang;
mod npm;
mod pypi;

/// One ecosystem's remediation knowledge.
pub trait EcosystemFixer: Send + Sync {
    /// The [`PackageRef::ecosystem`](crate::model::PackageRef) id this fixer
    /// serves. Must be one of
    /// [`supported_ecosystems`](crate::scan::targets::supported_ecosystems).
    fn ecosystem(&self) -> &'static str;

    /// Files, relative to the workspace root, the planner needs read for it.
    /// The IO shell reads exactly these and nothing else.
    fn probes(&self) -> &'static [&'static str] {
        &[]
    }

    /// Which toolchain this workspace uses. Given the manifest's text because
    /// some flavors are only distinguishable from the file's contents (yarn
    /// classic versus berry).
    fn flavor(&self, _manifest: &Path, _text: Option<&str>) -> &'static str {
        "default"
    }

    /// The binary a fix in `ws` needs. One ecosystem id can resolve to several
    /// tools: `npm` covers npm, yarn, pnpm and bun.
    fn program(&self, ws: &Workspace) -> &'static str;

    /// Plan one change.
    ///
    /// Infallible: an unfixable situation is a [`Blocker`] on a successful
    /// [`Plan`], not an error. That keeps the recipe visible on a blocked row
    /// and lets blockers accumulate, which they genuinely do.
    ///
    /// Recipes are self-sufficient and the executor runs identical `RunTool`
    /// invocations only once per apply run, so N changes in one workspace
    /// already collapse to N manifest edits and one `npm install`. Nothing here
    /// needs to know about batching.
    fn plan(&self, change: &Change, ws: &Workspace, tools: &Toolbox) -> Plan;
}

/// Every ecosystem Husk can fix, wired in one place.
///
/// Deliberately short. OS and distro package managers (dpkg, rpm, pacman, apk,
/// homebrew, ...) are **not** here and should not be: those fixes need root,
/// change machine-global state, and cannot be undone by a file snapshot. They
/// get [`Blocker::NotSupported`] and a copy-pasteable command in the guide.
pub fn default_fixers() -> &'static [&'static dyn EcosystemFixer] {
    &[
        &npm::NpmFixer,
        &pypi::PypiFixer,
        &cargo::CargoFixer,
        &golang::GoFixer,
    ]
}

/// The fixer for an ecosystem id, if Husk has one.
pub fn fixer_for(ecosystem: &str) -> Option<&'static dyn EcosystemFixer> {
    default_fixers()
        .iter()
        .copied()
        .find(|fixer| fixer.ecosystem() == ecosystem)
}

/// Plan one change, then apply the check every fixer would otherwise have to
/// remember: a recipe that runs a package manager needs that manager installed.
///
/// The entry point callers use, rather than [`EcosystemFixer::plan`] directly.
pub fn plan_change(
    fixer: &dyn EcosystemFixer,
    change: &Change,
    ws: &Workspace,
    tools: &Toolbox,
) -> Plan {
    let plan = fixer.plan(change, ws, tools);
    let program = fixer.program(ws);
    let spawns = plan
        .recipe
        .ops
        .iter()
        .any(|op| matches!(op, FixOp::RunTool { program: actual, .. } if actual == program));
    plan.block_if(
        spawns && !tools.has(program),
        Blocker::ToolMissing {
            program: program.to_string(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn every_fixer_targets_a_scanned_ecosystem() {
        // A fixer for coordinates the scanner cannot see is dead code, and a
        // typo'd id would be a silent capability gap rather than a build
        // error. This is the link between the two registries.
        let scanned = crate::scan::targets::supported_ecosystems();
        for fixer in default_fixers() {
            assert!(
                scanned.contains(&fixer.ecosystem()),
                "fixer `{}` has no matching ScanTarget",
                fixer.ecosystem()
            );
        }
    }

    #[test]
    fn fixer_ids_are_unique() {
        let mut ids: Vec<&str> = default_fixers()
            .iter()
            .map(|fixer| fixer.ecosystem())
            .collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "two fixers claim the same ecosystem id");
    }

    #[test]
    fn os_package_managers_have_no_fixer_and_never_will() {
        // Those upgrades need root, change machine-global state, and cannot be
        // undone by a file snapshot. The coordinates stay inventory-only and the
        // finding's own recommendation carries the command.
        for ecosystem in ["debian:12", "alpine:v3.19", "homebrew", "rpm"] {
            assert!(fixer_for(ecosystem).is_none());
        }
    }

    #[test]
    fn a_missing_package_manager_blocks_rather_than_inviting_a_doomed_click() {
        let change = Change::new(
            "lodash",
            "4.17.20",
            "4.17.21",
            PathBuf::from("/p/package-lock.json"),
        );
        let ws = Workspace::fixture(
            "/p",
            "/p/package-lock.json",
            "npm",
            None,
            &[("package.json", "{}")],
        );
        let plan = plan_change(&npm::NpmFixer, &change, &ws, &Toolbox::default());
        assert!(plan.blockers.contains(&Blocker::ToolMissing {
            program: "npm".into()
        }));
        // The recipe survives, so the UI can still show what would have run.
        assert!(!plan.recipe.ops.is_empty());
    }
}
