//! The pure planning inputs and outputs.
//!
//! Planning is a function of **data**, not of the filesystem. The IO shell
//! reads a [`Workspace`] once and probes a [`Toolbox`] once; every planner
//! after that is pure, exactly as a [`ScanTarget`](crate::scan::targets::ScanTarget)
//! parse function is pure over already-read text. That is why an ecosystem's
//! tests need no temporary directory and no filesystem mock.
//!
//! The two IO constructors ([`Workspace::read`], [`Toolbox::probe`]) are the
//! only functions in this module that touch the world.

use super::op::{Direction, Explain, Recipe};
use crate::model::Severity;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// One package moving from `current` to `target`, with the findings it closes.
///
/// Always derived from a `Finding` plus its `PackageRef` and the advisory's
/// fixed version, never from a client request, so no surface can ask Husk to
/// install an arbitrary package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub name: String,
    pub current: String,
    pub target: String,
    /// The file the coordinate was read from (`PackageRef::manifest_path`).
    pub manifest: PathBuf,
    pub finding_ids: Vec<String>,
    pub severity: Severity,
    pub direction: Direction,
    /// Every safe version the advisories named, when more than one, so the
    /// explanation can say a choice was made rather than silently taking the
    /// highest.
    pub alternatives: Vec<String>,
}

impl Change {
    pub fn new(
        name: impl Into<String>,
        current: impl Into<String>,
        target: impl Into<String>,
        manifest: PathBuf,
    ) -> Self {
        let (name, current, target) = (name.into(), current.into(), target.into());
        let direction = Direction::between(&current, &target);
        Self {
            name,
            current,
            target,
            manifest,
            finding_ids: Vec::new(),
            severity: Severity::Medium,
            direction,
            alternatives: Vec::new(),
        }
    }

    /// Whether the advisories disagree in a way no single pin can satisfy: one
    /// names a safe version above the installed one, another below it.
    ///
    /// Husk otherwise takes the highest safe version, which is the right
    /// default and silently wrong here.
    pub fn targets_conflict(&self) -> bool {
        self.alternatives
            .iter()
            .any(|candidate| Direction::between(&self.current, candidate) != self.direction)
    }
}

/// The project on disk, read **once** by the IO shell so that every planner is
/// a pure function of data.
///
/// A planner never sees an IO error: a file that could not be read is simply
/// absent, which is the same thing it means for planning.
#[derive(Clone, Debug)]
pub struct Workspace {
    /// Directory the tool runs in and every edit lands under.
    pub root: PathBuf,
    /// The file the coordinate came from. What [`Verify::Recoordinate`]
    /// re-parses.
    pub manifest: PathBuf,
    /// Which toolchain this workspace uses (npm/yarn/pnpm/bun, venv/uv/poetry).
    /// A `&'static str` from each fixer's own closed set rather than a shared
    /// enum: the sets have nothing in common.
    pub flavor: &'static str,
    manifest_text: Option<String>,
    /// Files the fixer declared in `probes()`, relative to `root`, already
    /// read. A missing key means the file is absent.
    files: BTreeMap<&'static str, String>,
}

impl Workspace {
    /// The only IO here: the manifest plus exactly what the fixer asked for,
    /// and nothing else.
    pub fn read(
        fixer: &dyn super::ecosystems::EcosystemFixer,
        manifest: &Path,
    ) -> Option<Workspace> {
        let root = manifest.parent()?.to_path_buf();
        let manifest_text = std::fs::read_to_string(manifest).ok();
        let files = fixer
            .probes()
            .iter()
            .filter_map(|relative| {
                std::fs::read_to_string(root.join(relative))
                    .ok()
                    .map(|text| (*relative, text))
            })
            .collect();
        Some(Workspace {
            flavor: fixer.flavor(manifest, manifest_text.as_deref()),
            root,
            manifest: manifest.to_path_buf(),
            manifest_text,
            files,
        })
    }

    /// Build a workspace from literals. Every fixer test uses this instead of
    /// a temporary directory.
    pub fn fixture(
        root: &str,
        manifest: &str,
        flavor: &'static str,
        manifest_text: Option<&str>,
        files: &[(&'static str, &str)],
    ) -> Self {
        Workspace {
            root: PathBuf::from(root),
            manifest: PathBuf::from(manifest),
            flavor,
            manifest_text: manifest_text.map(str::to_string),
            files: files
                .iter()
                .map(|(name, text)| (*name, (*text).to_string()))
                .collect(),
        }
    }

    /// The text of the file the coordinate was read from.
    pub fn manifest_text(&self) -> Option<&str> {
        self.manifest_text.as_deref()
    }

    pub fn file(&self, relative: &str) -> Option<&str> {
        self.files.get(relative).map(String::as_str)
    }

    pub fn has(&self, relative: &str) -> bool {
        self.files.contains_key(relative)
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

/// The machine, probed once per run: which package managers exist, and whether
/// the system Python refuses installs.
///
/// Pure data thereafter. `Toolbox::default()` is an empty machine, which is
/// what most tests want.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Toolbox {
    available: BTreeSet<&'static str>,
    externally_managed_python: bool,
    /// Escape hatches the user explicitly acknowledged. Carried into planning
    /// rather than patched onto a finished recipe, so an acknowledgement
    /// clears exactly the blocker it names and every other preflight check
    /// runs again from scratch.
    accepted: BTreeSet<Override>,
}

/// Every program a recipe may run. Closed, and every entry has install advice
/// (asserted by a test), so a "not installed" state is never a dead end.
pub const PROGRAMS: &[&str] = &["npm", "yarn", "pnpm", "bun", "pip", "uv", "cargo", "go"];

impl Toolbox {
    /// The other IO call: a `PATH` scan (no subprocess spawn) plus the PEP 668
    /// marker read.
    pub fn probe() -> Self {
        Self {
            available: PROGRAMS
                .iter()
                .filter(|program| super::exec::program_on_path(program))
                .copied()
                .collect(),
            externally_managed_python: system_python_is_externally_managed(),
            accepted: BTreeSet::new(),
        }
    }

    /// A machine where everything is installed. For tests that care about
    /// planning, not availability.
    pub fn everything() -> Self {
        Self {
            available: PROGRAMS.iter().copied().collect(),
            externally_managed_python: false,
            accepted: BTreeSet::new(),
        }
    }

    pub fn has(&self, program: &str) -> bool {
        self.available.contains(program)
    }

    /// Whether the user has knowingly taken this opt-in for the current
    /// request.
    pub fn accepts(&self, offer: Override) -> bool {
        self.accepted.contains(&offer)
    }

    pub fn accepting(&self, offer: Override) -> Self {
        let mut next = self.clone();
        next.accepted.insert(offer);
        next
    }

    /// PEP 668: a distro-managed interpreter drops an `EXTERNALLY-MANAGED`
    /// marker beside its stdlib and pip then refuses to install into it.
    pub fn externally_managed_python(&self) -> bool {
        self.externally_managed_python
    }

    pub fn with_externally_managed_python(mut self, externally_managed: bool) -> Self {
        self.externally_managed_python = externally_managed;
        self
    }
}

/// Read from the marker file alone, with no subprocess, so the blocker is known
/// at plan time instead of surfacing as pip's refusal only after a click. An
/// active virtualenv is exempt: its own prefix carries no marker.
fn system_python_is_externally_managed() -> bool {
    if std::env::var_os("VIRTUAL_ENV").is_some() {
        return false;
    }
    let Some(pip) = super::exec::program_path("pip").or_else(|| super::exec::program_path("pip3"))
    else {
        return false;
    };
    // `<prefix>/bin/pip` -> `<prefix>`.
    let Some(prefix) = pip.parent().and_then(Path::parent) else {
        return false;
    };
    let Ok(entries) = std::fs::read_dir(prefix.join("lib")) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry.file_name().to_string_lossy().starts_with("python3")
            && entry.path().join("EXTERNALLY-MANAGED").is_file()
    })
}

/// A one-flag opt-in the user may knowingly take to clear a blocker.
///
/// Typed rather than a flag string in a set: the pip CLI spelling appears
/// exactly once, inside `PypiFixer`, and a typo cannot silently disable the
/// opt-in.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Override {
    /// PEP 668 sanctions an escape hatch for a distro-managed interpreter.
    BreakSystemPackages,
}

/// Why a fix cannot be one click.
///
/// A **successful** planning outcome, never an error: "not one click, here is
/// what you do instead" is an answer. Keeping it out of the `Err` position is
/// what stops it decaying back into a string, and it lets a blocked row still
/// show the command Husk would have run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "blocker", rename_all = "snake_case")]
pub enum Blocker {
    /// The file that must hold the change is missing.
    NoManifest { expected: PathBuf, hint: String },
    /// The target is outside the range the project's dependents declared, and
    /// Husk will not silently widen a declared range.
    RangeConflict { declared: String, target: String },
    /// The environment refuses installs (PEP 668).
    ExternallyManaged,
    /// The manifest pins the package in a shape Husk cannot rewrite safely, so
    /// the fix would not survive a rescan.
    UnrewritablePin { manifest: PathBuf, found: String },
    /// Two advisories name safe versions no single pin can satisfy: one above
    /// the installed version, one below it.
    ConflictingTargets { targets: Vec<String> },
    /// The package manager is not installed.
    ToolMissing { program: String },
    /// Inventory-only: Husk sees the coordinate but has no safe local fix.
    /// Every OS package manager is here by design.
    NotSupported { hint: String },
}

impl Blocker {
    /// The single opt-in that clears this blocker, when the user may knowingly
    /// take it. `None` is a hard stop.
    ///
    /// The one place that decides whether an escape hatch exists. Nothing
    /// compares prose to find out.
    pub fn override_offer(&self) -> Option<Override> {
        match self {
            Blocker::ExternallyManaged => Some(Override::BreakSystemPackages),
            _ => None,
        }
    }

    /// The sentence a surface shows when it has nothing better to render.
    pub fn render(&self) -> String {
        match self {
            Blocker::NoManifest { expected, hint } => {
                format!(
                    "there is no {} to hold the change. {hint}",
                    file_label(expected)
                )
            }
            Blocker::RangeConflict { declared, target } => format!(
                "{target} is outside the declared requirement `{declared}`, and Husk will not \
                 widen a declared range for you. Raise it to admit {target} (or upgrade the \
                 parent that sets it), then retry."
            ),
            Blocker::ExternallyManaged => {
                "this system's Python blocks direct pip installs (PEP 668). Install the fixed \
                 version in a virtualenv or with pipx, or upgrade anyway if you accept writing \
                 into the system Python."
                    .to_string()
            }
            Blocker::UnrewritablePin { manifest, found } => format!(
                "{} pins it as {found}, which Husk cannot rewrite safely, so the next scan would \
                 read the old requirement straight back. Change it yourself, then reinstall.",
                file_label(manifest)
            ),
            Blocker::ConflictingTargets { targets } => format!(
                "one advisory calls for a newer release and another for an older one ({}), so no \
                 single pin satisfies both. Triage them individually.",
                targets.join(", ")
            ),
            Blocker::ToolMissing { program } => format!(
                "{program} is not installed on this machine. {}",
                super::install_advice_for(program)
            ),
            Blocker::NotSupported { hint } => hint.clone(),
        }
    }
}

impl std::fmt::Display for Blocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

/// The result of planning one change.
///
/// **Always carries the recipe**, so a UI can show what Husk would run even
/// when it cannot run it, plus every reason it cannot run as-is. An empty
/// `blockers` is the definition of "one click is safe".
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Plan {
    pub recipe: Recipe,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<Blocker>,
}

impl Plan {
    pub fn ready(recipe: Recipe) -> Self {
        Self {
            recipe,
            blockers: Vec::new(),
        }
    }

    /// Nothing to run, and a reason. The recipe is a manual stub so every plan
    /// has one shape and the executor can never run a blocked proposal.
    pub fn blocked(scope: PathBuf, explain: Explain, blocker: Blocker) -> Self {
        Self {
            recipe: Recipe::manual(scope, explain, Vec::new()),
            blockers: vec![blocker],
        }
    }

    pub fn block(mut self, blocker: Blocker) -> Self {
        if !self.blockers.contains(&blocker) {
            self.blockers.push(blocker);
        }
        self
    }

    /// Add `blocker` unless `condition` holds. Reads as a preflight assertion
    /// at the end of a planner.
    pub fn block_unless(self, condition: bool, blocker: Blocker) -> Self {
        self.block_if(!condition, blocker)
    }

    pub fn block_if(self, condition: bool, blocker: Blocker) -> Self {
        if condition { self.block(blocker) } else { self }
    }

    pub fn runnable(&self) -> bool {
        self.blockers.is_empty() && !self.recipe.ops.is_empty()
    }

    /// The opt-ins that would clear **every** blocker. `None` when any of them
    /// is a hard stop, so a surface never offers a button that cannot work.
    pub fn overrides(&self) -> Option<Vec<Override>> {
        overrides_for(&self.blockers)
    }
}

/// The opt-ins that would clear every blocker in `blockers`, or `None` when one
/// of them cannot be opted out of (including the empty case, where there is
/// nothing to offer).
pub fn overrides_for(blockers: &[Blocker]) -> Option<Vec<Override>> {
    if blockers.is_empty() {
        return None;
    }
    blockers.iter().map(Blocker::override_offer).collect()
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation::op::{FixOp, Safety, ToolPurpose, Verify};

    fn plan() -> Plan {
        Plan::ready(
            Recipe::new(
                PathBuf::from("/proj"),
                Safety::NeedsConsent,
                Explain::new("x"),
                Verify::UserConfirms,
            )
            .op(FixOp::RunTool {
                program: "pip".into(),
                args: vec!["install".into()],
                cwd: PathBuf::from("/proj"),
                purpose: ToolPurpose::Required,
            }),
        )
    }

    #[test]
    fn a_blocked_plan_still_carries_the_command_husk_would_have_run() {
        let blocked = plan().block(Blocker::ToolMissing {
            program: "pip".into(),
        });
        assert!(!blocked.runnable());
        assert_eq!(
            blocked.recipe.ops[0].argv(),
            Some(vec!["pip".to_string(), "install".to_string()])
        );
    }

    #[test]
    fn blockers_accumulate_because_they_genuinely_co_occur() {
        // A pypi fix can be externally-managed *and* unrepinnable at once.
        let blocked = plan()
            .block(Blocker::ExternallyManaged)
            .block(Blocker::UnrewritablePin {
                manifest: PathBuf::from("/proj/requirements.txt"),
                found: "a range".into(),
            });
        assert_eq!(blocked.blockers.len(), 2);
        // One of them has no escape hatch, so no opt-in is offered at all.
        assert_eq!(blocked.overrides(), None);
    }

    #[test]
    fn an_override_is_only_offered_when_it_clears_everything() {
        let blocked = plan().block(Blocker::ExternallyManaged);
        assert_eq!(
            blocked.overrides(),
            Some(vec![Override::BreakSystemPackages])
        );
        assert_eq!(plan().overrides(), None, "a runnable plan offers no opt-in");
    }

    #[test]
    fn block_unless_reads_as_a_preflight_assertion() {
        let missing = Blocker::ToolMissing {
            program: "pip".into(),
        };
        assert!(plan().block_unless(true, missing.clone()).runnable());
        assert!(!plan().block_unless(false, missing).runnable());
    }

    #[test]
    fn a_workspace_fixture_needs_no_filesystem() {
        let ws = Workspace::fixture(
            "/proj",
            "/proj/package-lock.json",
            "npm",
            None,
            &[("package.json", r#"{"name":"app"}"#)],
        );
        assert!(ws.has("package.json"));
        assert!(!ws.has("pnpm-workspace.yaml"));
        assert_eq!(ws.path("package.json"), PathBuf::from("/proj/package.json"));
    }
}
