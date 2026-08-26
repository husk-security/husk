//! Committed project policy: `<project>/.husk/policy.toml`.
//!
//! `husk init` writes this file; it is committed to git and travels with the
//! codebase, so everyone who clones inherits the team's security decisions.
//! Every scan path (scan/web/ci/tui/mcp)
//! loads it and applies it to the findings:
//!
//! - **`[packages] block`**: coordinates the team forbids; any installed match
//!   becomes a high-severity finding even with no advisory.
//! - **`[packages] allow`**: coordinates explicitly accepted; advisory/intel
//!   findings for them are suppressed (the team has reviewed and approved them).
//! - **`[[suppress]]`**: specific finding ids to silence, with a reason.
//! - **`[ci] fail_on`**: the minimum severity that fails `husk ci`.
//!
//! A coordinate is `ecosystem:name` (any version) or `ecosystem:name@version`
//! (exact). Loading walks up from each scan root to the nearest `.husk/`.

use crate::model::{Finding, PackageRef, Severity};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const POLICY_DIR: &str = ".husk";
pub const POLICY_FILE: &str = "policy.toml";

/// The parsed `policy.toml`. All sections are optional (`#[serde(default)]`) so
/// a sparse or partial file is always valid.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub schema_version: u32,
    pub packages: PackagePolicy,
    pub suppress: Vec<Suppression>,
    pub ci: CiPolicy,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct PackagePolicy {
    /// Coordinates the team forbids (`ecosystem:name[@version]`).
    pub block: Vec<String>,
    /// Coordinates the team has reviewed and accepts despite advisories.
    pub allow: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CiPolicy {
    /// Minimum severity that fails `husk ci` (`critical`/`high`/`medium`/…).
    pub fail_on: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Suppression {
    pub id: String,
    pub reason: Option<String>,
}

/// A loaded project policy plus the `.husk` directory it came from.
#[derive(Debug)]
pub struct Policy {
    pub dir: PathBuf,
    pub config: PolicyConfig,
}

/// What applying a policy changed, for an honest "policy applied" summary.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub suppressed: usize,
    pub allowed: usize,
    pub blocked: usize,
}

impl Policy {
    /// Find and load the nearest `.husk/policy.toml`, walking up from each scan
    /// root. Returns `Ok(None)` when no project policy exists (the common case).
    pub fn discover(roots: &[PathBuf]) -> Result<Option<Policy>> {
        for root in roots {
            let start = if root.is_dir() {
                Some(root.as_path())
            } else {
                root.parent()
            };
            let mut cur = start;
            while let Some(dir) = cur {
                let file = dir.join(POLICY_DIR).join(POLICY_FILE);
                if file.is_file() {
                    return Ok(Some(Policy::load(&dir.join(POLICY_DIR))?));
                }
                cur = dir.parent();
            }
        }
        Ok(None)
    }

    /// Load a policy from a specific `.husk` directory. A policy that sets an
    /// invalid `[ci] fail_on` value is a hard error: a typo must never
    /// silently change the CI gate.
    pub fn load(husk_dir: &Path) -> Result<Policy> {
        let file = husk_dir.join(POLICY_FILE);
        let contents =
            std::fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))?;
        let config: PolicyConfig =
            toml::from_str(&contents).with_context(|| format!("parse {}", file.display()))?;
        if let Some(value) = config.ci.fail_on.as_deref() {
            parse_fail_on(value).with_context(|| format!("in {}", file.display()))?;
        }
        Ok(Policy {
            dir: husk_dir.to_path_buf(),
            config,
        })
    }

    /// The CI fail-severity threshold, if the policy sets one. [`Policy::load`]
    /// already rejected invalid values, so this cannot silently misread a typo.
    pub fn ci_fail_on(&self) -> Option<Severity> {
        self.config
            .ci
            .fail_on
            .as_deref()
            .and_then(|value| parse_fail_on(value).ok())
    }

    /// Apply the policy to a finding set: move suppressed ids and allowed-package
    /// advisories out of `findings` and into the returned `ignored` list (so the
    /// UI can show them under "Ignored" instead of silently dropping them), and
    /// add findings for any installed package on the block list.
    pub fn apply(
        &self,
        findings: &mut Vec<Finding>,
        packages: &[PackageRef],
    ) -> (PolicyOutcome, Vec<Finding>) {
        let mut outcome = PolicyOutcome::default();
        let mut ignored = Vec::new();

        if !self.config.suppress.is_empty() {
            let ids: Vec<&str> = self.config.suppress.iter().map(|s| s.id.as_str()).collect();
            findings.retain(|f| {
                if ids.iter().any(|id| *id == f.id) {
                    ignored.push(f.clone());
                    false
                } else {
                    true
                }
            });
            outcome.suppressed = ignored.len();
        }

        if !self.config.packages.allow.is_empty() {
            let allow = &self.config.packages.allow;
            let before = ignored.len();
            findings.retain(|f| {
                let accepted = f
                    .package
                    .as_ref()
                    .is_some_and(|p| allow.iter().any(|entry| coordinate_matches(entry, p)));
                // Only advisory-style findings are waived by an allow; local
                // risk findings (secrets, lifecycle, etc.) are never silenced.
                if accepted && is_advisory(f) {
                    ignored.push(f.clone());
                    false
                } else {
                    true
                }
            });
            outcome.allowed = ignored.len() - before;
        }

        for package in packages {
            if self
                .config
                .packages
                .block
                .iter()
                .any(|entry| coordinate_matches(entry, package))
            {
                findings.push(blocked_finding(package));
                outcome.blocked += 1;
            }
        }

        (outcome, ignored)
    }
}

/// Move findings the user has personally silenced via the trust ledger
/// (`~/.husk/ledger.jsonl`: `approve.suppress` finding ids + `approve.allow`
/// package coordinates) out of `findings` and into `ignored`. Mirrors the
/// project-policy suppress/allow above, but sourced from the personal ledger so
/// it applies across every project. Best-effort: a missing/unreadable ledger
/// silences nothing.
pub fn apply_ledger_ignores(findings: &mut Vec<Finding>, ignored: &mut Vec<Finding>) {
    let entries = crate::ledger::load().unwrap_or_default();
    if entries.is_empty() {
        return;
    }
    let suppressed: std::collections::HashSet<&str> = entries
        .iter()
        .filter(|e| e.action == "approve.suppress")
        .map(|e| e.target.as_str())
        .collect();
    let allowed: Vec<&str> = entries
        .iter()
        .filter(|e| e.action == "approve.allow")
        .map(|e| e.target.as_str())
        .collect();
    findings.retain(|f| {
        let ignore = suppressed.contains(f.id.as_str())
            || (is_advisory(f)
                && f.package
                    .as_ref()
                    .is_some_and(|p| allowed.iter().any(|entry| coordinate_matches(entry, p))));
        if ignore {
            ignored.push(f.clone());
            false
        } else {
            true
        }
    });
}

/// Discover the nearest policy for each scan root and apply it, scoped to that
/// root's own project tree. Returns the ignored findings plus any load errors
/// (a malformed `policy.toml`), each paired with the offending file path, so the
/// scan path can surface them loudly instead of silently failing open. Every
/// project (whether one or many in a single scan) governs only its own
/// subtree, so one project's rules never silently apply to (or vanish from)
/// another's.
pub fn apply_for_roots(
    roots: &[PathBuf],
    findings: &mut Vec<Finding>,
    packages: &[PackageRef],
) -> (Vec<Finding>, Vec<(PathBuf, anyhow::Error)>) {
    let mut ignored = Vec::new();
    let mut errors = Vec::new();

    // One policy per distinct `.husk/policy.toml`, remembering the project root
    // it governs (the directory that contains `.husk`). Deduping on the file
    // path means N roots inside one project neither re-load nor re-report it.
    let mut policies: Vec<(PathBuf, Policy)> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for root in roots {
        let Some(file) = discover_file(root) else {
            continue;
        };
        if !seen.insert(file.clone()) {
            continue;
        }
        let husk_dir = file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| file.clone());
        match Policy::load(&husk_dir) {
            Ok(policy) => {
                let project_root = husk_dir
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| husk_dir.clone());
                policies.push((canon(&project_root), policy));
            }
            // Keep the failed file path so the surfaced finding is stable and
            // uniquely attributable per policy file.
            Err(err) => errors.push((file, err)),
        }
    }

    if policies.is_empty() {
        return (ignored, errors);
    }

    // Deepest project root first so a nested project's policy wins for paths
    // inside it.
    policies.sort_by_key(|(root, _)| std::cmp::Reverse(root.as_os_str().len()));
    let govern = |path: Option<&Path>| -> Option<usize> {
        let raw = path?;
        let canonical = canon(raw);
        policies
            .iter()
            .position(|(root, _)| canonical.starts_with(root) || raw.starts_with(root))
    };

    let count = policies.len();
    let mut finding_buckets: Vec<Vec<Finding>> = vec![Vec::new(); count];
    let mut ungoverned: Vec<Finding> = Vec::new();
    for finding in findings.drain(..) {
        let path = finding
            .path
            .clone()
            .or_else(|| finding.package.as_ref().map(|p| p.manifest_path.clone()));
        match govern(path.as_deref()) {
            Some(index) => finding_buckets[index].push(finding),
            None => ungoverned.push(finding),
        }
    }
    let mut package_buckets: Vec<Vec<PackageRef>> = vec![Vec::new(); count];
    for package in packages {
        if let Some(index) = govern(Some(&package.manifest_path)) {
            package_buckets[index].push(package.clone());
        }
    }
    for (index, (_root, policy)) in policies.iter().enumerate() {
        let (_outcome, ig) = policy.apply(&mut finding_buckets[index], &package_buckets[index]);
        ignored.extend(ig);
    }

    *findings = ungoverned;
    for bucket in finding_buckets {
        findings.extend(bucket);
    }

    (ignored, errors)
}

/// Best-effort canonicalization; falls back to the input path so a relative or
/// vanished path still compares deterministically.
fn canon(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// A visible finding raised when a `.husk/policy.toml` failed to load, so a
/// typo in the committed moat file never silently disables the team's
/// block/allow/suppress rules. Fail-safe: the user is told the policy is NOT
/// being enforced rather than proceeding as if there were none.
pub fn load_error_finding(path: &Path, err: &anyhow::Error) -> Finding {
    let mut finding = Finding::new(
        "policy-error",
        "Project policy failed to load and is NOT being enforced".to_string(),
        Severity::High,
        crate::rule::Category::Policy,
        "project policy (.husk)",
        Some(path.to_path_buf()),
        None,
        format!(
            "`{}` could not be parsed, so its block/allow/suppress rules were not \
             applied to this scan: {err:#}",
            path.display()
        ),
        None,
        "Fix the error in the `.husk/policy.toml` above (run `husk policy` to validate) \
         so the project's security rules take effect again.",
    );
    // Minted after the scan's central pass, so it locates its own id.
    finding.locate_id();
    finding
}

/// Does a policy coordinate match a package? `ecosystem:name` matches any
/// version; `ecosystem:name@version` matches that exact version. Ecosystem and
/// name compare case-insensitively; the version is exact.
fn coordinate_matches(entry: &str, package: &PackageRef) -> bool {
    let entry = entry.trim();
    let (eco_name, version) = match entry.rsplit_once('@') {
        // Avoid splitting a leading scope `@` (npm): require a non-empty left.
        Some((left, ver)) if !left.is_empty() && !left.ends_with(':') => (left, Some(ver)),
        _ => (entry, None),
    };
    let Some((eco, name)) = eco_name.split_once(':') else {
        return false;
    };
    if !eco.eq_ignore_ascii_case(&package.ecosystem) || !name.eq_ignore_ascii_case(&package.name) {
        return false;
    }
    match version {
        Some(v) => v == package.version,
        None => true,
    }
}

/// Advisory-style findings are the ones an `allow` entry waives: vulnerability
/// and intel/malware matches that carry a package reference.
fn is_advisory(finding: &Finding) -> bool {
    finding.package.is_some()
        && matches!(
            finding.category,
            crate::rule::Category::Vulnerability
                | crate::rule::Category::Malware
                | crate::rule::Category::Typosquat
        )
}

fn blocked_finding(package: &PackageRef) -> Finding {
    let mut finding = Finding::new(
        format!("policy-block:{}", package.key()),
        format!("{} is blocked by project policy", package.name),
        Severity::High,
        crate::rule::Category::Policy,
        "project policy (.husk)",
        Some(package.manifest_path.clone()),
        package.line,
        format!(
            "{} {} ({}) is on the project's `.husk/policy.toml` block list.",
            package.name, package.version, package.ecosystem
        ),
        None,
        "Remove this dependency, or remove it from `[packages] block` in \
         `.husk/policy.toml` if it is now allowed.",
    )
    .with_package(package.clone());
    // Minted after the scan's central pass, so it locates its own id.
    finding.locate_id();
    finding
}

/// Locate the nearest `.husk/policy.toml`, walking up from `start`. Returns the
/// file path (for editing) rather than a parsed policy.
pub fn discover_file(start: &Path) -> Option<PathBuf> {
    let mut cur = if start.is_dir() {
        Some(start)
    } else {
        start.parent()
    };
    while let Some(dir) = cur {
        let file = dir.join(POLICY_DIR).join(POLICY_FILE);
        if file.is_file() {
            return Some(file);
        }
        cur = dir.parent();
    }
    None
}

/// Strictly parse a `[ci] fail_on` severity. Unlike `Severity::from_external`
/// (lenient by design for third-party advisory feeds), a user-authored config
/// value must parse exactly: an unknown word is an error, never a silent
/// remap to the strictest gate.
fn parse_fail_on(value: &str) -> Result<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Ok(Severity::Critical),
        "high" => Ok(Severity::High),
        "medium" => Ok(Severity::Medium),
        "low" => Ok(Severity::Low),
        "info" => Ok(Severity::Info),
        _ => anyhow::bail!(
            "invalid `[ci] fail_on` value `{value}` (expected critical | high | medium | low | info)"
        ),
    }
}

/// Read-modify-write a `policy.toml` under an advisory lock, writing the
/// result atomically. `edit` returns whether it changed the document; the file
/// is only rewritten when it did.
///
/// The lock serializes the common race (two concurrent `husk approve` /
/// web-mute writers reading the same starting state); the atomic write
/// guarantees a crash can never leave a torn file in the user's git working
/// tree. Because the atomic write replaces the inode, a third writer arriving
/// mid-rename can still lock the fresh inode concurrently; an accepted limit
/// for a hand-edited config, matching the ledger's advisory-lock posture.
fn edit_policy(
    policy_file: &Path,
    edit: impl FnOnce(&mut toml_edit::DocumentMut) -> Result<bool>,
) -> Result<bool> {
    let lock = std::fs::File::open(policy_file)
        .with_context(|| format!("open {}", policy_file.display()))?;
    lock.lock()
        .with_context(|| format!("lock {}", policy_file.display()))?;
    // Re-read by path under the lock: an earlier writer may have already
    // replaced the file since we opened the lock handle.
    let text = std::fs::read_to_string(policy_file)
        .with_context(|| format!("read {}", policy_file.display()))?;
    let mut doc = text
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("parse {}", policy_file.display()))?;
    let changed = edit(&mut doc)?;
    if changed {
        crate::paths::write_atomic(policy_file, doc.to_string().as_bytes())
            .with_context(|| format!("write {}", policy_file.display()))?;
    }
    Ok(changed)
}

/// A one-command policy edit (`husk approve`). Each variant appends to the
/// committed `policy.toml`, preserving its comments and layout.
#[derive(Debug, Clone)]
pub enum Approval {
    /// Add a coordinate to `[packages] allow` (accept despite advisories).
    Allow(String),
    /// Add a coordinate to `[packages] block` (forbid this package).
    Block(String),
    /// Add a `[[suppress]]` entry silencing a finding id, with a reason.
    Suppress { id: String, reason: Option<String> },
}

/// Apply an [`Approval`] to a `policy.toml`, preserving comments/formatting via
/// `toml_edit`. Returns `true` if a new entry was added, `false` if it was
/// already present (idempotent).
pub fn approve(policy_file: &Path, approval: &Approval) -> Result<bool> {
    use toml_edit::{Array, ArrayOfTables, Item, Table, Value, value};

    edit_policy(policy_file, |doc| {
        let added = match approval {
            Approval::Allow(coord) | Approval::Block(coord) => {
                let key = if matches!(approval, Approval::Block(_)) {
                    "block"
                } else {
                    "allow"
                };
                let packages = doc
                    .entry("packages")
                    .or_insert_with(|| Item::Table(Table::new()))
                    .as_table_mut()
                    .context("`[packages]` is not a table")?;
                let array = packages
                    .entry(key)
                    .or_insert_with(|| Item::Value(Value::Array(Array::new())))
                    .as_array_mut()
                    .with_context(|| format!("`packages.{key}` is not an array"))?;
                if array.iter().any(|v| v.as_str() == Some(coord.as_str())) {
                    false
                } else {
                    array.push(coord.as_str());
                    true
                }
            }
            Approval::Suppress { id, reason } => {
                let suppress = doc
                    .entry("suppress")
                    .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()))
                    .as_array_of_tables_mut()
                    .context("`suppress` is not an array of tables")?;
                if suppress
                    .iter()
                    .any(|t| t.get("id").and_then(|v| v.as_str()) == Some(id.as_str()))
                {
                    false
                } else {
                    let mut table = Table::new();
                    table["id"] = value(id.as_str());
                    if let Some(reason) = reason {
                        table["reason"] = value(reason.as_str());
                    }
                    suppress.push(table);
                    true
                }
            }
        };
        Ok(added)
    })
}

/// Remove a `[[suppress]]` entry by finding id (the inverse of an
/// `Approval::Suppress`). Returns `true` if an entry was removed, `false` if the
/// id wasn't suppressed. Comment/format-preserving, like [`approve`].
#[cfg(feature = "web")]
pub fn revoke_suppress(policy_file: &Path, id: &str) -> Result<bool> {
    edit_policy(policy_file, |doc| {
        let Some(suppress) = doc
            .get_mut("suppress")
            .and_then(|i| i.as_array_of_tables_mut())
        else {
            return Ok(false);
        };
        let before = suppress.len();
        suppress.retain(|t| t.get("id").and_then(|v| v.as_str()) != Some(id));
        Ok(suppress.len() != before)
    })
}

/// Validate a policy coordinate string (`ecosystem:name[@version]`).
pub fn validate_coordinate(coord: &str) -> Result<()> {
    let core = coord.rsplit_once('@').map(|(l, _)| l).unwrap_or(coord);
    let Some((eco, name)) = core.split_once(':') else {
        anyhow::bail!("expected `ecosystem:name` or `ecosystem:name@version`, got `{coord}`");
    };
    if eco.is_empty() || name.is_empty() {
        anyhow::bail!("coordinate `{coord}` has an empty ecosystem or name");
    }
    Ok(())
}

/// Create `<dir>/.husk/policy.toml` (and a short README) with a documented
/// default template. Returns the policy file path. Refuses to overwrite an
/// existing `policy.toml`.
pub fn init_project(dir: &Path) -> Result<PathBuf> {
    let husk_dir = dir.join(POLICY_DIR);
    let policy_path = husk_dir.join(POLICY_FILE);
    if policy_path.exists() {
        anyhow::bail!("{} already exists", policy_path.display());
    }
    std::fs::create_dir_all(&husk_dir).with_context(|| format!("create {}", husk_dir.display()))?;
    crate::paths::write_atomic(&policy_path, DEFAULT_POLICY_TEMPLATE.as_bytes())
        .with_context(|| format!("write {}", policy_path.display()))?;
    let readme = husk_dir.join("README.md");
    if !readme.exists() {
        let _ = std::fs::write(&readme, README_TEMPLATE);
    }
    Ok(policy_path)
}

/// Outcome of [`mute_findings`].
#[cfg(feature = "web")]
#[derive(Debug)]
pub struct MuteOutcome {
    /// Newly written suppressions (already-suppressed ids are idempotent no-ops).
    pub muted: usize,
    /// The `.husk` directory holding the policy file the suppressions landed in.
    pub policy_dir: PathBuf,
}

/// Suppress `ids` in the project policy discovered from `roots` (creating
/// `.husk/policy.toml` in the first scanned directory when none exists), and
/// mirror each new suppression on the personal trust ledger (the same compound
/// a CLI `husk approve --suppress` records).
#[cfg(feature = "web")]
pub fn mute_findings(
    roots: &[PathBuf],
    ids: &[String],
    reason: Option<&str>,
) -> Result<MuteOutcome> {
    let policy_file = match roots.iter().find_map(|root| discover_file(root)) {
        Some(file) => file,
        None => {
            let dir = roots
                .iter()
                .find(|root| root.is_dir())
                .context("no writable project directory to store the policy")?;
            init_project(dir)?
        }
    };
    let project = policy_file
        .parent()
        .and_then(Path::parent)
        .map(|p| p.display().to_string());

    let mut muted = 0;
    for id in ids {
        let approval = Approval::Suppress {
            id: id.clone(),
            reason: reason.map(str::to_string),
        };
        if approve(&policy_file, &approval).context("could not write policy")? {
            muted += 1;
            // Every trust decision compounds on the ledger, same as the CLI.
            let _ = crate::ledger::append("finding.suppress", id, reason, project.as_deref());
        }
    }
    let policy_dir = policy_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    Ok(MuteOutcome { muted, policy_dir })
}

/// Un-suppress `ids` in the project policy discovered from `roots` (the
/// inverse of [`mute_findings`]), mirroring each removal on the personal trust
/// ledger. Only touches an existing policy (errors when none is discovered);
/// ids that were not suppressed are idempotent no-ops. The returned
/// [`MuteOutcome::muted`] counts removed suppressions.
#[cfg(feature = "web")]
pub fn unmute_findings(roots: &[PathBuf], ids: &[String]) -> Result<MuteOutcome> {
    let policy_file = roots
        .iter()
        .find_map(|root| discover_file(root))
        .context("no project policy to unmute from")?;
    let project = policy_file
        .parent()
        .and_then(Path::parent)
        .map(|p| p.display().to_string());

    let mut muted = 0;
    for id in ids {
        if revoke_suppress(&policy_file, id).context("could not write policy")? {
            muted += 1;
            // Every trust decision compounds on the ledger, same as the CLI.
            let _ = crate::ledger::append("finding.unmute", id, None, project.as_deref());
        }
    }
    let policy_dir = policy_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    Ok(MuteOutcome { muted, policy_dir })
}

const DEFAULT_POLICY_TEMPLATE: &str = r#"# Husk project policy: committed to git, shared by the whole team.
# Every `husk scan` / `husk ci` in this project reads this file.
# Docs: https://github.com/husk-security/husk

schema_version = 1

[packages]
# Coordinates the team forbids. `ecosystem:name` blocks every version;
# `ecosystem:name@version` blocks one exact version. A match becomes a
# high-severity finding even when there is no advisory.
#   block = ["npm:event-stream", "pypi:colorama@0.4.6"]
block = []

# Coordinates the team has reviewed and accepts despite advisories. Advisory /
# malware findings for these are suppressed (recorded approvals, not silence).
#   allow = ["npm:lodash@4.17.21"]
allow = []

# Silence specific finding ids the team has triaged. Always say why.
#   [[suppress]]
#   id = "secret:AWS-access-key:src/legacy/fixture.txt"
#   reason = "test fixture, not a real credential"

[ci]
# Minimum severity that fails `husk ci` (critical | high | medium | low).
fail_on = "high"
"#;

const README_TEMPLATE: &str = "# `.husk/`: committed Husk project policy\n\n\
This directory holds the team's security policy for this project. It is meant to\n\
be committed to git. `policy.toml` pins blocked/allowed packages, triaged\n\
suppressions, and the CI failure threshold; every `husk scan` and `husk ci` run\n\
in this repository reads it, so anyone who clones inherits the same decisions.\n\n\
Edit `policy.toml` to change the policy. Run `husk scan` to see it applied.\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(eco: &str, name: &str, version: &str) -> PackageRef {
        PackageRef {
            ecosystem: eco.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: PathBuf::from("package-lock.json"),
            line: None,
        }
    }

    fn advisory_finding(id: &str, package: PackageRef) -> Finding {
        Finding::new(
            id,
            "vuln",
            Severity::High,
            crate::rule::Category::Vulnerability,
            "OSV.dev",
            None,
            None,
            "x",
            None,
            "y",
        )
        .with_package(package)
    }

    #[test]
    fn coordinate_matching() {
        let p = pkg("npm", "lodash", "4.17.21");
        assert!(coordinate_matches("npm:lodash", &p));
        assert!(coordinate_matches("NPM:Lodash", &p)); // case-insensitive
        assert!(coordinate_matches("npm:lodash@4.17.21", &p)); // exact version
        assert!(!coordinate_matches("npm:lodash@4.17.20", &p)); // wrong version
        assert!(!coordinate_matches("pypi:lodash", &p)); // wrong ecosystem
        // Scoped npm name with an explicit version still parses.
        let scoped = pkg("npm", "@scope/pkg", "1.0.0");
        assert!(coordinate_matches("npm:@scope/pkg@1.0.0", &scoped));
        assert!(coordinate_matches("npm:@scope/pkg", &scoped));
    }

    /// Suppression matches an id by exact string, so two matches of one rule in
    /// one file must not share an id: triaging the first private key in a file
    /// would otherwise silence every other key in it, permanently and for the
    /// whole team, without ever showing them.
    #[test]
    fn suppressing_one_match_leaves_the_others_in_the_same_file_visible() {
        let path = PathBuf::from("/repo/deploy-keys.pem");
        let key_at = |line: usize| {
            let mut finding = Finding::new(
                "secret:private-key",
                "private key exposed",
                Severity::Critical,
                crate::rule::Category::Secret,
                "local",
                Some(path.clone()),
                Some(line),
                "x",
                None,
                "y",
            );
            finding.locate_id();
            finding
        };
        let mut findings = vec![key_at(1), key_at(4), key_at(7)];
        let triaged = findings[1].id.clone();

        let policy = Policy {
            dir: PathBuf::from(".husk"),
            config: PolicyConfig {
                suppress: vec![Suppression {
                    id: triaged,
                    reason: Some("reviewed".to_string()),
                }],
                ..PolicyConfig::default()
            },
        };
        let (outcome, ignored) = policy.apply(&mut findings, &[]);

        assert_eq!(outcome.suppressed, 1);
        assert_eq!(ignored.len(), 1);
        assert_eq!(ignored[0].line, Some(4));
        let lines: Vec<Option<usize>> = findings.iter().map(|f| f.line).collect();
        assert_eq!(lines, vec![Some(1), Some(7)]);
    }

    #[test]
    fn applies_block_allow_and_suppress() {
        let config = PolicyConfig {
            schema_version: 1,
            packages: PackagePolicy {
                block: vec!["npm:evil".to_string()],
                allow: vec!["npm:lodash@4.17.21".to_string()],
            },
            suppress: vec![Suppression {
                id: "secret:test".to_string(),
                reason: Some("fixture".to_string()),
            }],
            ci: CiPolicy {
                fail_on: Some("medium".to_string()),
            },
        };
        let policy = Policy {
            dir: PathBuf::from(".husk"),
            config,
        };

        let lodash = pkg("npm", "lodash", "4.17.21");
        let evil = pkg("npm", "evil", "1.0.0");
        let mut findings = vec![
            advisory_finding("osv:GHSA-1", lodash.clone()), // allowed -> suppressed
            advisory_finding("osv:GHSA-2", pkg("npm", "other", "1.0")), // kept
            Finding::new(
                "secret:test",
                "secret",
                Severity::Critical,
                crate::rule::Category::Secret,
                "local",
                None,
                None,
                "x",
                None,
                "y",
            ), // suppressed by id
        ];
        let packages = vec![lodash, evil, pkg("npm", "other", "1.0")];

        let (outcome, ignored) = policy.apply(&mut findings, &packages);
        assert_eq!(
            ignored.len(),
            2,
            "suppressed + allowed captured, not dropped"
        );
        assert_eq!(outcome.suppressed, 1);
        assert_eq!(outcome.allowed, 1);
        assert_eq!(outcome.blocked, 1);

        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"osv:GHSA-2"), "non-allowed advisory kept");
        assert!(!ids.contains(&"osv:GHSA-1"), "allowed advisory suppressed");
        assert!(!ids.contains(&"secret:test"), "suppressed id removed");
        assert!(
            findings
                .iter()
                .any(|f| f.id.starts_with("policy-block:npm:evil@1.0.0@")),
            "blocked package flagged"
        );
        assert_eq!(policy.ci_fail_on(), Some(Severity::Medium));
    }

    #[test]
    fn allow_does_not_silence_local_risk() {
        let config = PolicyConfig {
            packages: PackagePolicy {
                allow: vec!["npm:lodash".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = Policy {
            dir: PathBuf::from(".husk"),
            config,
        };
        // A secret finding that happens to carry a package ref is NOT waived.
        let mut findings = vec![
            Finding::new(
                "secret:x",
                "secret",
                Severity::Critical,
                crate::rule::Category::Secret,
                "local",
                None,
                None,
                "x",
                None,
                "y",
            )
            .with_package(pkg("npm", "lodash", "4.17.21")),
        ];
        let (outcome, ignored) = policy.apply(&mut findings, &[]);
        assert_eq!(outcome.allowed, 0);
        assert_eq!(findings.len(), 1);
        assert!(ignored.is_empty(), "local risk not silenced by allow");
    }

    #[test]
    fn approve_appends_and_is_idempotent_preserving_comments() {
        let dir = tempfile::tempdir().unwrap();
        let file = init_project(dir.path()).unwrap();

        assert!(approve(&file, &Approval::Allow("npm:lodash@4.17.21".into())).unwrap());
        assert!(approve(&file, &Approval::Block("npm:event-stream".into())).unwrap());
        assert!(
            approve(
                &file,
                &Approval::Suppress {
                    id: "secret:test".into(),
                    reason: Some("fixture".into())
                }
            )
            .unwrap()
        );
        // Re-applying the same entries is a no-op.
        assert!(!approve(&file, &Approval::Allow("npm:lodash@4.17.21".into())).unwrap());
        assert!(
            !approve(
                &file,
                &Approval::Suppress {
                    id: "secret:test".into(),
                    reason: None
                }
            )
            .unwrap()
        );

        let text = std::fs::read_to_string(&file).unwrap();
        // Comments from the template survive the edit.
        assert!(text.contains("# Husk project policy"));

        let loaded = Policy::load(&dir.path().join(".husk")).unwrap();
        assert_eq!(loaded.config.packages.allow, vec!["npm:lodash@4.17.21"]);
        assert_eq!(loaded.config.packages.block, vec!["npm:event-stream"]);
        assert_eq!(loaded.config.suppress.len(), 1);
        assert_eq!(loaded.config.suppress[0].id, "secret:test");
        assert_eq!(loaded.config.suppress[0].reason.as_deref(), Some("fixture"));
    }

    #[test]
    #[cfg(feature = "web")]
    fn revoke_suppress_removes_entry_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let file = init_project(dir.path()).unwrap();
        approve(
            &file,
            &Approval::Suppress {
                id: "secret:test".into(),
                reason: Some("fixture".into()),
            },
        )
        .unwrap();

        assert!(revoke_suppress(&file, "secret:test").unwrap());
        assert!(
            Policy::load(&dir.path().join(".husk"))
                .unwrap()
                .config
                .suppress
                .is_empty()
        );
        // Revoking again (or an unknown id) is a no-op.
        assert!(!revoke_suppress(&file, "secret:test").unwrap());
        assert!(!revoke_suppress(&file, "never:muted").unwrap());
    }

    #[test]
    fn load_rejects_invalid_fail_on() {
        let dir = tempfile::tempdir().unwrap();
        let husk_dir = dir.path().join(".husk");
        std::fs::create_dir_all(&husk_dir).unwrap();
        std::fs::write(husk_dir.join("policy.toml"), "[ci]\nfail_on = \"hgih\"\n").unwrap();
        let err = Policy::load(&husk_dir).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("hgih"), "error names the bad value: {msg}");
        assert!(msg.contains("policy.toml"), "error names the file: {msg}");
    }

    #[test]
    fn fail_on_parses_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let husk_dir = dir.path().join(".husk");
        std::fs::create_dir_all(&husk_dir).unwrap();
        std::fs::write(
            husk_dir.join("policy.toml"),
            "[ci]\nfail_on = \"Critical\"\n",
        )
        .unwrap();
        let policy = Policy::load(&husk_dir).unwrap();
        assert_eq!(policy.ci_fail_on(), Some(Severity::Critical));
    }

    #[test]
    fn malformed_policy_surfaces_error_and_does_not_fail_open() {
        let dir = tempfile::tempdir().unwrap();
        let husk_dir = dir.path().join(".husk");
        std::fs::create_dir_all(&husk_dir).unwrap();
        // A merge-conflict marker / typo: not valid TOML.
        std::fs::write(husk_dir.join("policy.toml"), "<<<<<<< HEAD\nblock = [\n").unwrap();

        // A real scan finding must survive a malformed policy: the policy error
        // is surfaced ALONGSIDE the scan's results, never in place of them.
        let sentinel = advisory_finding("osv:SENTINEL", pkg("npm", "keep-me", "1.0"));
        let mut findings = vec![sentinel];
        let roots = vec![dir.path().to_path_buf()];
        let (ignored, errors) = apply_for_roots(&roots, &mut findings, &[]);

        assert!(ignored.is_empty());
        assert!(
            findings.iter().any(|f| f.id == "osv:SENTINEL"),
            "a malformed policy must not swallow the scan's real findings"
        );
        assert_eq!(
            errors.len(),
            1,
            "a malformed policy must not silently vanish"
        );
        let (path, err) = &errors[0];
        let finding = load_error_finding(path, err);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.category, crate::rule::Category::Policy);
        // The finding id and path are keyed on the offending file, not a generic
        // constant, so distinct malformed policies stay distinct findings.
        assert_eq!(finding.id, format!("policy-error@{}", path.display()));
        assert_eq!(finding.path.as_deref(), Some(path.as_path()));
        assert!(path.ends_with(".husk/policy.toml"));
    }

    #[test]
    fn per_root_policy_scopes_to_its_own_tree() {
        // Two independent projects scanned in one run. Only project A blocks
        // `npm:shared`; a `shared` package exists in BOTH trees. Correct
        // scoping blocks exactly the one under A.
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(a.path().join(".husk")).unwrap();
        std::fs::create_dir_all(b.path().join(".husk")).unwrap();
        std::fs::write(
            a.path().join(".husk/policy.toml"),
            "[packages]\nblock = [\"npm:shared\"]\n",
        )
        .unwrap();
        std::fs::write(b.path().join(".husk/policy.toml"), "schema_version = 1\n").unwrap();

        let in_a = pkg("npm", "shared", "1.0");
        let mut in_a = in_a;
        in_a.manifest_path = a.path().join("package-lock.json");
        let mut in_b = pkg("npm", "shared", "1.0");
        in_b.manifest_path = b.path().join("package-lock.json");

        let mut findings = Vec::new();
        let roots = vec![a.path().to_path_buf(), b.path().to_path_buf()];
        let (_ignored, errors) = apply_for_roots(&roots, &mut findings, &[in_a, in_b]);

        assert!(errors.is_empty());
        let blocked = findings
            .iter()
            .filter(|f| f.id.starts_with("policy-block:"))
            .count();
        assert_eq!(blocked, 1, "A's block must not leak onto B's tree");
    }

    #[test]
    fn single_root_still_applies_its_policy() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join(".husk")).unwrap();
        std::fs::write(
            project.path().join(".husk/policy.toml"),
            "[packages]\nblock = [\"npm:evil\"]\nallow = [\"npm:lodash@4.17.21\"]\n",
        )
        .unwrap();

        let mut evil = pkg("npm", "evil", "6.6.6");
        evil.manifest_path = project.path().join("package-lock.json");
        let mut lodash = pkg("npm", "lodash", "4.17.21");
        lodash.manifest_path = project.path().join("package-lock.json");

        // An advisory on the allowed lodash (attached to a path in the project)
        // must be waived; the blocked package must produce a block finding.
        let mut waived = advisory_finding("osv:GHSA-lodash", lodash.clone());
        waived.path = Some(project.path().join("package-lock.json"));
        let mut findings = vec![waived];
        let roots = vec![project.path().to_path_buf()];
        let (ignored, errors) = apply_for_roots(&roots, &mut findings, &[evil, lodash]);

        assert!(errors.is_empty());
        assert_eq!(ignored.len(), 1, "the allowed advisory is waived");
        assert_eq!(ignored[0].id, "osv:GHSA-lodash");
        let blocked = findings
            .iter()
            .filter(|f| f.id.starts_with("policy-block:"))
            .count();
        assert_eq!(blocked, 1, "the blocked package still produces a finding");
    }

    #[test]
    fn validates_coordinates() {
        assert!(validate_coordinate("npm:lodash").is_ok());
        assert!(validate_coordinate("npm:@scope/pkg@1.0.0").is_ok());
        assert!(validate_coordinate("lodash").is_err()); // no ecosystem
        assert!(validate_coordinate(":lodash").is_err()); // empty ecosystem
    }

    #[test]
    fn init_writes_template_and_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = init_project(dir.path()).expect("init");
        assert!(path.ends_with(".husk/policy.toml"));
        let loaded = Policy::load(&dir.path().join(".husk")).expect("load");
        assert_eq!(loaded.config.schema_version, 1);
        assert_eq!(loaded.ci_fail_on(), Some(Severity::High));
        // Second init must not clobber an existing policy.
        assert!(init_project(dir.path()).is_err());
    }
}
