//! Scan history: one compact JSONL row per completed scan, so every surface
//! can show the security score over time and what husk concretely fixed, not
//! just the single previous-scan delta.
//!
//! Rows live in `~/.husk/history.jsonl` (durable per-user *state*, unlike the
//! re-fetchable `~/.cache/husk` artifacts; deleting it loses the trend).
//! A row is a summary only, never a full report: rows are keyed by the
//! normalized scan roots so a home scan and a per-project scan never
//! interleave into one fake trend, and the per-repo surfaces group on that key.
//!
//! Value attribution is honest by construction: `fixes_applied` counts the
//! ledger's husk-executed remediations between the previous scan and this
//! one, and `husk_resolved` counts resolved findings whose id matches a
//! ledger fix target; everything else resolved is "resolved (other)", never
//! claimed as husk's doing.

use crate::ledger::LedgerEntry;
use crate::model::{Finding, ScanReport, Severity};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Bump when a row's meaning changes incompatibly; readers skip other
/// versions (no migration; old rows just stop informing the trend).
const HISTORY_SCHEMA: u32 = 1;

/// Ledger actions that are husk-executed remediations (vs. user decisions
/// like `approve.suppress` or `approve.allow`).
fn is_fix_action(action: &str) -> bool {
    action == "dependency.update" || action.starts_with("fix.")
}

/// A resolved or new finding, compacted for a history row: enough to tell the
/// user *which* vulnerability changed (title, severity, package) without
/// embedding the full `Finding`; history rows must stay small.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FindingSummary {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// Stable kebab category id (`"vulnerability"`, `"secret"`, …).
    pub category: String,
    /// `name@version`, for package/advisory findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// On resolved findings: the resolution matched a husk-executed ledger
    /// fix (same attribution rule as `husk_resolved`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub by_husk: bool,
}

impl FindingSummary {
    fn from_finding(finding: &Finding, by_husk: bool) -> Self {
        Self {
            id: finding.id.clone(),
            title: finding.title.clone(),
            severity: finding.severity,
            category: finding.category.id().to_string(),
            package: finding
                .package
                .as_ref()
                .map(|p| format!("{}@{}", p.name, p.version)),
            path: finding.path.as_ref().map(|p| p.display().to_string()),
            by_husk,
        }
    }
}

/// One completed scan, summarized. The unit every history surface renders.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HistoryEntry {
    pub v: u32,
    pub at: DateTime<Utc>,
    pub roots_key: String,
    /// The husk version that produced the scan. A score drop right after an
    /// upgrade usually means new detections shipped, not a worse machine;
    /// UIs annotate those steps instead of letting the chart read as a regression.
    pub husk_version: String,
    /// Posture score (0-100), same grading as every other surface.
    pub score: u32,
    pub findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub packages: usize,
    /// Since-previous-scan movement (0 on a first scan / roots change).
    pub new_count: usize,
    pub resolved_count: usize,
    /// Categories of the resolved findings (from the delta's capped list).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resolved_by_category: BTreeMap<String, usize>,
    /// The resolved findings themselves (worst-first, capped upstream at
    /// `model::RESOLVED_CAP`); what the per-scan drill-down renders.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved: Vec<FindingSummary>,
    /// The findings that appeared in this scan (same cap).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new: Vec<FindingSummary>,
    /// Husk-executed fixes recorded on the ledger since the previous scan.
    pub fixes_applied: usize,
    /// What those fixes were, one label per fix ("name (eco)" for dependency
    /// updates, otherwise the fix target id); empty on rows written before
    /// this field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fixes: Vec<String>,
    /// Resolved findings confirmed to be husk fixes (ledger target match).
    pub husk_resolved: usize,
}

/// Human-readable "what was fixed" for a ledger fix row: dependency targets
/// (`dep:{eco}:{name}:{manifest}`) become "name (eco)"; anything else keeps
/// its target id, which is already the most specific name recorded.
fn fix_label(entry: &LedgerEntry) -> String {
    if let Some(rest) = entry.target.strip_prefix("dep:") {
        let mut parts = rest.splitn(3, ':');
        if let (Some(eco), Some(name)) = (parts.next(), parts.next()) {
            return format!("{name} ({eco})");
        }
    }
    entry.target.clone()
}

pub fn history_path() -> Result<PathBuf> {
    Ok(crate::paths::husk_home()?.join("history.jsonl"))
}

/// The identity of a scan target set: sorted roots joined on a unit
/// separator (never valid inside a path), matching the cache's
/// order-insensitive roots comparison.
pub fn roots_key(roots: &[PathBuf]) -> String {
    let mut parts = roots
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    parts.sort();
    parts.join("\u{1f}")
}

/// Build the history row for a finished report. Pure: ledger entries are
/// passed in so the attribution math is testable without disk.
pub fn entry_from_report(report: &ScanReport, ledger: &[LedgerEntry]) -> HistoryEntry {
    // A row grades the scanned target only. The report can also carry
    // home-inventory findings (paths outside every root); counting those makes
    // the same target's trend flap between scans that toggle
    // --no-home-inventory, so they stay out of the row entirely.
    let under_roots = |p: &std::path::Path| report.roots.iter().any(|root| p.starts_with(root));
    let in_target = |f: &Finding| match (&f.path, &f.package) {
        (Some(path), _) if under_roots(path) => true,
        (_, Some(pkg)) if under_roots(&pkg.manifest_path) => true,
        (None, None) => true,
        _ => false,
    };
    let target_findings: Vec<Finding> = report
        .findings
        .iter()
        .filter(|f| in_target(f))
        .cloned()
        .collect();
    let stats = crate::model::ScanStats::from_findings(report.stats.packages, &target_findings);
    // Off-target findings past the delta's cap can't be re-scoped (the capped
    // lists are all we have); counts are exact under the cap.
    let (new_count, resolved_count) = report
        .delta
        .as_ref()
        .map(|d| {
            let dropped = |list: &[Finding]| list.iter().filter(|f| !in_target(f)).count();
            (
                d.new_count.saturating_sub(dropped(&d.new)),
                d.resolved_count.saturating_sub(dropped(&d.resolved)),
            )
        })
        .unwrap_or((0, 0));

    // Fixes husk executed in this scan's window (previous scan → now), with a
    // label each so every surface can say *what* was fixed, not just a count.
    // A first scan has no window, so nothing is claimed.
    let fixes: Vec<String> = report
        .delta
        .as_ref()
        .map(|delta| {
            ledger
                .iter()
                .filter(|e| is_fix_action(&e.action))
                .filter(|e| e.timestamp > delta.previous_at && e.timestamp <= report.generated_at)
                .map(fix_label)
                .collect()
        })
        .unwrap_or_default();

    // Resolved findings a ledger fix targeted, ever; a fixed finding's id
    // never comes back, so all-time matching can't overclaim. Targets come in
    // two shapes: the finding id (web/TUI one-click appends) and the fix
    // plan's `dep:{eco}:{name}:{manifest}` id (`husk fix --apply` appends);
    // the latter is matched via the finding's package coordinate.
    let fix_targets: std::collections::BTreeSet<&str> = ledger
        .iter()
        .filter(|e| is_fix_action(&e.action))
        .map(|e| e.target.as_str())
        .collect();
    let matches_fix = |f: &Finding| {
        if fix_targets.contains(f.id.as_str()) {
            return true;
        }
        f.package.as_ref().is_some_and(|p| {
            fix_targets.contains(
                format!(
                    "dep:{}:{}:{}",
                    p.ecosystem,
                    p.name,
                    p.manifest_path.display()
                )
                .as_str(),
            )
        })
    };
    let (husk_resolved, resolved_by_category, resolved, new) = report
        .delta
        .as_ref()
        .map(|delta| {
            let resolved: Vec<FindingSummary> = delta
                .resolved
                .iter()
                .filter(|f| in_target(f))
                .map(|f| FindingSummary::from_finding(f, matches_fix(f)))
                .collect();
            let confirmed = resolved.iter().filter(|f| f.by_husk).count();
            let mut by_category = BTreeMap::new();
            for finding in delta.resolved.iter().filter(|f| in_target(f)) {
                *by_category
                    .entry(finding.category.id().to_string())
                    .or_insert(0) += 1;
            }
            let new = delta
                .new
                .iter()
                .filter(|f| in_target(f))
                .map(|f| FindingSummary::from_finding(f, false))
                .collect();
            (confirmed, by_category, resolved, new)
        })
        .unwrap_or_default();

    HistoryEntry {
        v: HISTORY_SCHEMA,
        at: report.generated_at,
        roots_key: roots_key(&report.roots),
        husk_version: env!("CARGO_PKG_VERSION").to_string(),
        score: crate::score::posture_score(&stats),
        findings: stats.findings,
        critical: stats.critical,
        high: stats.high,
        medium: stats.medium,
        low: stats.low,
        info: stats.info,
        packages: stats.packages,
        new_count,
        resolved_count,
        resolved_by_category,
        resolved,
        new,
        fixes_applied: fixes.len(),
        fixes,
        husk_resolved,
    }
}

/// Append the history row for a finished scan. Best-effort at every call
/// site (`let _ =`): history must never fail a scan.
pub fn record_scan(report: &ScanReport) -> Result<()> {
    let ledger = crate::ledger::load().unwrap_or_default();
    append(&entry_from_report(report, &ledger))
}

fn append(entry: &HistoryEntry) -> Result<()> {
    use std::io::Write;
    let path = history_path()?;
    if let Some(parent) = path.parent() {
        // Owner-only (0700), like every other `~/.husk` writer.
        crate::paths::ensure_dir_private(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    // Exclusive advisory lock so a daemon tick and a manual scan finishing
    // together can't interleave half-lines (released on drop).
    file.lock()
        .with_context(|| format!("lock {}", path.display()))?;
    let mut line = serde_json::to_string(entry)?;
    line.push('\n');
    file.write_all(line.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// The history of the given roots, oldest first. Unparseable or
/// other-schema lines are skipped, never an error; a schema bump just
/// restarts the trend.
pub fn load(roots: &[PathBuf]) -> Vec<HistoryEntry> {
    let key = roots_key(roots);
    load_all()
        .into_iter()
        .filter(|entry| entry.roots_key == key)
        .collect()
}

/// Every recorded scan across all roots, oldest first; the per-repo history
/// surfaces group these by `roots_key` themselves.
pub fn load_all() -> Vec<HistoryEntry> {
    let Ok(path) = history_path() else {
        return Vec::new();
    };
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    parse(&contents)
        .into_iter()
        .filter(is_durable_target)
        .collect()
}

/// A scan target worth trending: every root is an absolute path, still a
/// directory on disk, and outside the system temp dir. Drops the noise other
/// flows record (a single edited file, AI-agent
/// scratch projects under /tmp), each of which otherwise lingers as a
/// one-scan "target" of its own in every history surface.
fn is_durable_target(entry: &HistoryEntry) -> bool {
    // TMPDIR can point somewhere else (nix shells do), but scratch projects
    // written under a plain /tmp are just as ephemeral; treat both as temp.
    let tmp = std::env::temp_dir();
    entry.roots_key.split('\u{1f}').all(|root| {
        let path = std::path::Path::new(root);
        path.is_absolute()
            && !path.starts_with(&tmp)
            && !(cfg!(unix) && path.starts_with("/tmp"))
            && path.is_dir()
    })
}

/// Pure JSONL parse (testable without disk); keeps only current-schema rows.
pub fn parse(contents: &str) -> Vec<HistoryEntry> {
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<HistoryEntry>(line).ok())
        .filter(|entry| entry.v == HISTORY_SCHEMA)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, ScanDelta, Severity};
    use crate::rule::Category;

    fn finding(id: &str, category: Category) -> Finding {
        Finding::new(
            id,
            "t",
            Severity::High,
            category,
            "test",
            None,
            None,
            "s",
            None,
            "r",
        )
    }

    fn report_with_delta(delta: Option<ScanDelta>) -> ScanReport {
        let mut report = ScanReport::new(
            vec![PathBuf::from("/proj")],
            Vec::new(),
            vec![finding("open-1", Category::Vulnerability)],
            Vec::new(),
        );
        report.delta = delta;
        report
    }

    fn ledger_fix(target: &str, timestamp: DateTime<Utc>) -> LedgerEntry {
        LedgerEntry {
            seq: 1,
            timestamp,
            action: "dependency.update".to_string(),
            target: target.to_string(),
            reason: None,
            project: None,
            prev_hash: String::new(),
            hash: String::new(),
        }
    }

    #[test]
    fn roots_key_is_order_insensitive() {
        let a = roots_key(&[PathBuf::from("/a"), PathBuf::from("/b")]);
        let b = roots_key(&[PathBuf::from("/b"), PathBuf::from("/a")]);
        assert_eq!(a, b);
        assert_ne!(a, roots_key(&[PathBuf::from("/a")]));
    }

    #[test]
    fn first_scan_claims_nothing() {
        let report = report_with_delta(None);
        let ledger = vec![ledger_fix("osv:X", Utc::now())];
        let entry = entry_from_report(&report, &ledger);
        assert_eq!(entry.fixes_applied, 0);
        assert_eq!(entry.husk_resolved, 0);
        assert_eq!(entry.new_count, 0);
        assert_eq!(entry.resolved_count, 0);
    }

    #[test]
    fn attribution_splits_husk_fixes_from_other_resolutions() {
        let previous_at = Utc::now() - chrono::Duration::hours(2);
        let report = report_with_delta(Some(ScanDelta {
            previous_at,
            previous_score: 60,
            score: 80,
            new_count: 1,
            unchanged_count: 3,
            resolved_count: 2,
            resolved: vec![
                finding("osv:fixed-by-husk", Category::Vulnerability),
                finding("secret:gone-by-hand", Category::Secret),
            ],
            new: vec![finding("osv:brand-new", Category::Vulnerability)],
        }));
        let ledger = vec![
            // In-window fix that matches a resolved finding.
            ledger_fix("osv:fixed-by-husk", Utc::now() - chrono::Duration::hours(1)),
            // Fix from before the window: not counted as applied-this-window.
            ledger_fix("osv:old", Utc::now() - chrono::Duration::hours(5)),
        ];
        let entry = entry_from_report(&report, &ledger);
        assert_eq!(entry.fixes_applied, 1);
        assert_eq!(entry.fixes, vec!["osv:fixed-by-husk".to_string()]);
        assert_eq!(entry.husk_resolved, 1);
        assert_eq!(entry.resolved_count, 2);
        assert_eq!(entry.resolved_by_category.get("vulnerability"), Some(&1));
        assert_eq!(entry.resolved_by_category.get("secret"), Some(&1));
        assert_eq!(entry.resolved.len(), 2);
        assert!(
            entry
                .resolved
                .iter()
                .any(|f| f.id == "osv:fixed-by-husk" && f.by_husk)
        );
        assert!(
            entry
                .resolved
                .iter()
                .any(|f| f.id == "secret:gone-by-hand" && !f.by_husk)
        );
        assert_eq!(entry.new.len(), 1);
        assert_eq!(entry.new[0].id, "osv:brand-new");
    }

    #[test]
    fn cli_dep_target_matches_via_package_coordinate() {
        // `husk fix --apply --deps` ledgers the plan id (`dep:…`), not the
        // finding id; the resolved finding must still be attributed to husk.
        let mut resolved = finding("osv:GHSA-x:npm:left-pad@1.0.0", Category::Vulnerability);
        resolved.package = Some(crate::model::PackageRef {
            ecosystem: "npm".to_string(),
            name: "left-pad".to_string(),
            version: "1.0.0".to_string(),
            manifest_path: PathBuf::from("/proj/package-lock.json"),
            line: None,
        });
        let report = report_with_delta(Some(ScanDelta {
            previous_at: Utc::now() - chrono::Duration::hours(2),
            previous_score: 60,
            score: 80,
            new_count: 0,
            unchanged_count: 0,
            resolved_count: 1,
            resolved: vec![resolved],
            new: Vec::new(),
        }));
        let ledger = vec![ledger_fix(
            "dep:npm:left-pad:/proj/package-lock.json",
            Utc::now() - chrono::Duration::hours(1),
        )];
        let entry = entry_from_report(&report, &ledger);
        assert_eq!(entry.husk_resolved, 1);
        assert_eq!(entry.fixes, vec!["left-pad (npm)".to_string()]);
    }

    #[test]
    fn rows_grade_the_target_only() {
        let mut home = finding("secret:home-token", Category::Secret);
        home.severity = Severity::Critical;
        home.path = Some(PathBuf::from("/home/u/.claude/file-history/x"));
        let mut proj = finding("osv:proj-vuln", Category::Vulnerability);
        proj.path = Some(PathBuf::from("/proj/package-lock.json"));
        let mut report = ScanReport::new(
            vec![PathBuf::from("/proj")],
            Vec::new(),
            vec![proj.clone(), home.clone()],
            Vec::new(),
        );
        report.delta = Some(ScanDelta {
            previous_at: Utc::now() - chrono::Duration::hours(1),
            previous_score: 90,
            score: 0,
            new_count: 2,
            unchanged_count: 0,
            resolved_count: 1,
            resolved: vec![home.clone()],
            new: vec![proj, home],
        });
        let entry = entry_from_report(&report, &[]);
        // The home-inventory secret sits outside the root: it must not touch
        // the score, the severity counts, or the new/resolved lists.
        assert_eq!(entry.findings, 1);
        assert_eq!(entry.high, 1);
        assert_eq!(entry.critical, 0);
        assert_eq!(entry.score, 90);
        assert_eq!(entry.new_count, 1);
        assert_eq!(entry.new.len(), 1);
        assert_eq!(entry.new[0].id, "osv:proj-vuln");
        assert_eq!(entry.resolved_count, 0);
        assert!(entry.resolved.is_empty());
    }

    #[test]
    fn durable_targets_are_absolute_existing_non_temp_dirs() {
        // Resolved at run time: `CARGO_MANIFEST_DIR` is baked in at compile
        // time and is not part of Cargo's fingerprint, so a `CARGO_TARGET_DIR`
        // shared across sibling worktrees serves a binary carrying another
        // worktree's path, which may since have moved or been deleted.
        let repo = std::env::current_dir().expect("test working directory is the crate root");
        let mut entry = entry_from_report(&report_with_delta(None), &[]);

        entry.roots_key = roots_key(std::slice::from_ref(&repo));
        assert!(is_durable_target(&entry));

        // A file, a vanished dir, a relative path, and anything under the
        // temp dir (hook checkouts, agent scratch projects) are all noise.
        entry.roots_key = roots_key(&[repo.join("Cargo.toml")]);
        assert!(!is_durable_target(&entry));

        entry.roots_key = roots_key(&[repo.join("no-such-dir-x7q9")]);
        assert!(!is_durable_target(&entry));

        entry.roots_key = roots_key(&[PathBuf::from("tst")]);
        assert!(!is_durable_target(&entry));

        let tmp = tempfile::tempdir().unwrap();
        entry.roots_key = roots_key(&[tmp.path().to_path_buf()]);
        assert!(!is_durable_target(&entry));
    }

    #[test]
    fn parse_skips_junk_and_other_schemas() {
        let report = report_with_delta(None);
        let entry = entry_from_report(&report, &[]);
        let mut other = entry.clone();
        other.v = HISTORY_SCHEMA + 1;
        let contents = format!(
            "{}\nnot json\n{}\n\n",
            serde_json::to_string(&entry).unwrap(),
            serde_json::to_string(&other).unwrap(),
        );
        let parsed = parse(&contents);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].roots_key, roots_key(&report.roots));
    }
}
