//! What Husk may do, as data.
//!
//! A planner returns a [`Recipe`]: an ordered list of [`FixOp`]s, the
//! [`Safety`] tier they need, a structured [`Explain`], and the [`Verify`] that
//! proves afterwards they worked. Only [`super::exec`] executes them.
//!
//! The set is deliberately **closed**, because the security argument depends on
//! it being closed: "anything not in this enum is not something Husk does" is a
//! claim you can audit in one screen. Nothing here reads, writes, or spawns;
//! this module is pure data.
//!
//! It is also what makes fixes that are not dependency bumps ordinary:
//!
//! | Fix | Ops | Safety |
//! |---|---|---|
//! | `.env` into `.gitignore` | `AppendUniqueLine` | `SafeEdit` |
//! | `.env.template` generation | `CreateFile` | `SafeEdit` |
//! | npm lifecycle scripts off | `SetValue{.npmrc, KeyValue, ["ignore-scripts"], "true"}` | `SafeEdit` |
//! | pin a GitHub Action to a SHA | `ReplaceSpan` over the `uses:` token | `SafeEdit` |
//! | enable commit signing | `RunTool{git, ["config", ...]}` | `NeedsConsent` |
//! | rotate a leaked credential | none, plus [`Recipe::step`]s | `Manual` |
//!
//! Note the last two rows. Spawning a process is never auto-safe, even for
//! `git`, because the auto-safe tier's value is that it provably runs no
//! third-party code. And "manual" is the *absence* of ops, so the executor
//! cannot run it by construction.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One deterministic filesystem or process operation.
///
/// These cross the wire outward (the CLI's `--json`, the web API, MCP) and come
/// back in through the durable scan cache, which round-trips a whole
/// `ScanReport`, so both serde directions are load-bearing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FixOp {
    /// Append `line` to `path` when no line already equals it, creating the
    /// file (with `header` first) when absent. Idempotent by construction: an
    /// already-present line reports `Skipped`.
    AppendUniqueLine {
        path: PathBuf,
        line: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        header: Option<String>,
    },

    /// Create `path` with exactly `contents`. An existing path is `Skipped`,
    /// never `Failed`, and never overwritten.
    CreateFile { path: PathBuf, contents: String },

    /// Set one key in a structured document, preserving the rest of the file
    /// as far as the format's editor allows. `key` is a path into the document
    /// (`["overrides", "lodash"]`).
    SetValue {
        path: PathBuf,
        format: DocFormat,
        key: Vec<String>,
        value: String,
    },

    /// Replace exactly `expect` at byte range `[start, end)`. The executor
    /// re-reads the file and refuses when those bytes are no longer `expect`,
    /// so a plan serialised into a report and acted on a minute later cannot
    /// corrupt a file the user edited meanwhile.
    ReplaceSpan {
        path: PathBuf,
        start: usize,
        end: usize,
        expect: String,
        replacement: String,
    },

    /// Run `program` with `args` in `cwd`. No shell, no interpolation, no
    /// fetch-and-execute. `program` is resolved on `PATH` at *apply* time.
    RunTool {
        program: String,
        args: Vec<String>,
        cwd: PathBuf,
        purpose: ToolPurpose,
    },
}

impl FixOp {
    /// The file this op writes, when it writes one. Drives the pre-write
    /// backup snapshot and the containment check.
    pub fn write_target(&self) -> Option<&PathBuf> {
        match self {
            FixOp::AppendUniqueLine { path, .. }
            | FixOp::CreateFile { path, .. }
            | FixOp::SetValue { path, .. }
            | FixOp::ReplaceSpan { path, .. } => Some(path),
            FixOp::RunTool { .. } => None,
        }
    }

    /// The argv, for display. Never used to run anything.
    pub fn argv(&self) -> Option<Vec<String>> {
        match self {
            FixOp::RunTool { program, args, .. } => Some(
                std::iter::once(program.clone())
                    .chain(args.iter().cloned())
                    .collect(),
            ),
            _ => None,
        }
    }

    /// One line of preview, shown verbatim by `--dry-run`.
    pub fn preview(&self) -> String {
        match self {
            FixOp::AppendUniqueLine { path, line, .. } => {
                format!("append `{line}` to {}", path.display())
            }
            FixOp::CreateFile { path, .. } => format!("write {}", path.display()),
            FixOp::SetValue {
                path, key, value, ..
            } => format!("set {} to {value} in {}", key.join("."), path.display()),
            FixOp::ReplaceSpan {
                path,
                expect,
                replacement,
                ..
            } => format!(
                "replace `{expect}` with `{replacement}` in {}",
                path.display()
            ),
            FixOp::RunTool { cwd, .. } => format!(
                "run `{}` in {}",
                self.argv().unwrap_or_default().join(" "),
                cwd.display()
            ),
        }
    }
}

/// Which format-preserving editor [`FixOp::SetValue`] uses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DocFormat {
    /// `serde_json` with `preserve_order`: key order survives, whitespace does
    /// not.
    Json,
    /// A top-level `key:` block of indented `"name": "value"` pairs
    /// (`pnpm-workspace.yaml`'s `overrides`). Line-oriented, so every
    /// unrelated line survives byte-for-byte. Husk has no YAML serialiser and
    /// deliberately does not add one: a round-trip would reformat the file.
    YamlBlock,
    /// Line-oriented `key=value` (`.npmrc`).
    KeyValue,
}

/// Whether a tool's failure fails the fix.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPurpose {
    /// The fix does not stand without it.
    Required,
    /// Housekeeping after the pin already landed (`go mod tidy`): a failure is
    /// a warning the user can act on, not a failed fix.
    BestEffort,
}

/// How much trust an op sequence needs.
///
/// Deliberately **not** ordered: the tiers are kinds, not a scale. Ordering
/// them would make "authorized up to `Manual`" expressible, and `Manual` means
/// Husk does not act at all. What a run may execute is [`Authority`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Safety {
    /// Reversible, idempotent, touches no credential, runs no third-party
    /// code. **File writes only**, so anything that spawns is at least
    /// `NeedsConsent`, even `git`.
    SafeEdit,
    /// Runs a package manager (which executes third-party code) or changes
    /// global tool state.
    NeedsConsent,
    /// Husk does not act. Instructions only.
    Manual,
}

/// What one apply run is permitted to execute.
///
/// There is deliberately no value that authorizes [`Safety::Manual`], so "Husk
/// ran a manual fix" is not representable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Authority {
    /// `husk fix --apply`.
    #[default]
    SafeEditsOnly,
    /// `--deps`, the web button, the TUI `u` key.
    SafeEditsAndConsented,
}

impl Authority {
    pub fn permits(self, safety: Safety) -> bool {
        matches!(
            (self, safety),
            (_, Safety::SafeEdit) | (Authority::SafeEditsAndConsented, Safety::NeedsConsent)
        )
    }
}

/// Upgrade or downgrade.
///
/// First-class, not a fallback branch: the compromised release is often the
/// *newer* one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Upgrade,
    Downgrade,
}

impl Direction {
    pub fn verb(self) -> &'static str {
        match self {
            Direction::Upgrade => "Upgrade",
            Direction::Downgrade => "Downgrade",
        }
    }

    /// Which way `target` moves from `current`, by the generic comparator.
    pub fn between(current: &str, target: &str) -> Self {
        match crate::version::naive_vercmp(target, current) {
            std::cmp::Ordering::Greater => Direction::Upgrade,
            _ => Direction::Downgrade,
        }
    }
}

/// Why Husk proposes a recipe: one headline plus the caveats the user must see
/// (a downgrade's range risk, a second advisory naming a different target, a
/// mechanism an old tool version ignores).
///
/// Two fields rather than a pre-composed sentence, so a surface can show the
/// caveats separately from the claim; [`Explain::render`] is the shared prose
/// fallback.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Explain {
    pub headline: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Explain {
    pub fn new(headline: impl Into<String>) -> Self {
        Self {
            headline: headline.into(),
            notes: Vec::new(),
        }
    }

    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    pub fn render(&self) -> String {
        let mut out = self.headline.clone();
        for note in &self.notes {
            out.push(' ');
            out.push_str(note);
        }
        out
    }
}

/// How the executor proves a recipe took effect, without a full rescan.
///
/// This is the payoff for keying the fixer registry on the same ecosystem id as
/// the scan targets: `Recoordinate` re-runs the *scanner's own parser* over the
/// files the fix touched, at zero ecosystem-specific cost. A package manager
/// exiting 0 is not proof: it can resolve to a version Husk did not ask for, or
/// accept a manifest edit it no longer reads at all.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "verify", rename_all = "snake_case")]
pub enum Verify {
    Recoordinate {
        manifests: Vec<PathBuf>,
        ecosystem: String,
        name: String,
        expect: String,
    },
    /// Settled by the owning guide control on the next scan. Named rather than
    /// invoked: `remediation` must not call back into `guide`.
    Rescan { control_id: String },
    /// Nothing observable locally; the user confirms.
    UserConfirms,
}

/// A stderr marker plus the explanation to show when a tool's failure matches
/// it.
///
/// Ecosystem knowledge that only becomes relevant *after* a tool fails, carried
/// as data so the executor stays generic. A package manager's own failure tail
/// often names no cause (pip's "See above for output", "not a problem with
/// pip"), so the module that knows the ecosystem supplies it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailureHint {
    pub markers: Vec<String>,
    pub detail: String,
}

/// One instruction plus every place it applies to.
///
/// N places needing the same treatment is one instruction and a list of N
/// places, not N instructions: a sentence repeated once per path buries the
/// only part that varies, and a narrow column truncates it away entirely.
/// `subjects` is ordered by the planner and never reordered downstream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Step {
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<String>,
}

/// An ordered op sequence plus why Husk proposes it and how it checks itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Recipe {
    /// Applied in order; the executor stops at the first hard failure.
    pub ops: Vec<FixOp>,
    pub safety: Safety,
    /// The directory every write must stay inside. Derived from the scan (a
    /// repo root, an ecosystem workspace root), never from client input, so
    /// containment needs no plumbing at the call site.
    pub scope: PathBuf,
    pub explain: Explain,
    pub verify: Verify,
    /// Steps for the user when `safety` is [`Safety::Manual`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failure_hints: Vec<FailureHint>,
}

impl Recipe {
    pub fn new(scope: PathBuf, safety: Safety, explain: Explain, verify: Verify) -> Self {
        Self {
            ops: Vec::new(),
            safety,
            scope,
            explain,
            verify,
            steps: Vec::new(),
            failure_hints: Vec::new(),
        }
    }

    pub fn op(mut self, op: FixOp) -> Self {
        self.ops.push(op);
        self
    }

    /// Add an instruction for the user. Only meaningful on a manual recipe,
    /// which is the only kind that carries steps.
    pub fn step(self, text: impl Into<String>) -> Self {
        self.step_over(text, Vec::new())
    }

    /// Add one instruction that applies to every place in `subjects`.
    pub fn step_over(mut self, text: impl Into<String>, subjects: Vec<String>) -> Self {
        self.steps.push(Step {
            text: text.into(),
            subjects,
        });
        self
    }

    /// Explain a tool failure the planner can recognise but the executor
    /// cannot. Package managers pad failures with pointers to output husk does
    /// not have, so the module that knows the ecosystem supplies the cause.
    pub fn hint(mut self, markers: &[&str], detail: impl Into<String>) -> Self {
        self.failure_hints.push(FailureHint {
            markers: markers.iter().map(|marker| marker.to_string()).collect(),
            detail: detail.into(),
        });
        self
    }

    /// Instructions only: no ops, nothing to execute.
    pub fn manual(scope: PathBuf, explain: Explain, steps: Vec<Step>) -> Self {
        Self {
            ops: Vec::new(),
            safety: Safety::Manual,
            scope,
            explain,
            verify: Verify::UserConfirms,
            steps,
            failure_hints: Vec::new(),
        }
    }

    pub fn spawns(&self) -> bool {
        self.ops
            .iter()
            .any(|op| matches!(op, FixOp::RunTool { .. }))
    }

    /// The auto-safe tier is file-writes only, and a manual recipe carries no
    /// ops. Both directions are asserted where proposals are built.
    pub fn safety_is_consistent(&self) -> bool {
        match self.safety {
            Safety::SafeEdit => !self.spawns(),
            Safety::NeedsConsent => true,
            Safety::Manual => self.ops.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe(safety: Safety, ops: Vec<FixOp>) -> Recipe {
        Recipe {
            ops,
            safety,
            scope: PathBuf::from("/proj"),
            explain: Explain::new("x"),
            verify: Verify::UserConfirms,
            steps: Vec::new(),
            failure_hints: Vec::new(),
        }
    }

    fn run_tool() -> FixOp {
        FixOp::RunTool {
            program: "git".into(),
            args: vec!["add".into()],
            cwd: PathBuf::from("/proj"),
            purpose: ToolPurpose::Required,
        }
    }

    fn append() -> FixOp {
        FixOp::AppendUniqueLine {
            path: PathBuf::from("/proj/.gitignore"),
            line: ".env".into(),
            header: None,
        }
    }

    #[test]
    fn safe_edit_may_not_spawn_a_process() {
        // The auto-safe tier's whole value is that it provably runs no
        // third-party code; letting anything spawn there erodes it.
        assert!(recipe(Safety::SafeEdit, vec![append()]).safety_is_consistent());
        assert!(!recipe(Safety::SafeEdit, vec![append(), run_tool()]).safety_is_consistent());
        assert!(recipe(Safety::NeedsConsent, vec![run_tool()]).safety_is_consistent());
    }

    #[test]
    fn manual_recipes_carry_no_ops() {
        assert!(recipe(Safety::Manual, vec![]).safety_is_consistent());
        assert!(!recipe(Safety::Manual, vec![append()]).safety_is_consistent());
    }

    #[test]
    fn no_authority_can_execute_a_manual_fix() {
        for authority in [Authority::SafeEditsOnly, Authority::SafeEditsAndConsented] {
            assert!(!authority.permits(Safety::Manual));
            assert!(authority.permits(Safety::SafeEdit));
        }
        assert!(!Authority::SafeEditsOnly.permits(Safety::NeedsConsent));
        assert!(Authority::SafeEditsAndConsented.permits(Safety::NeedsConsent));
        assert_eq!(Authority::default(), Authority::SafeEditsOnly);
    }

    #[test]
    fn direction_is_computed_from_the_version_algebra_not_string_order() {
        assert_eq!(Direction::between("1.9.0", "1.10.0"), Direction::Upgrade);
        assert_eq!(Direction::between("1.10.0", "1.9.0"), Direction::Downgrade);
        // Go's `v` prefix must not turn every fix into a "downgrade".
        assert_eq!(Direction::between("v0.35.0", "0.36.0"), Direction::Upgrade);
    }
}
