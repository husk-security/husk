//! Daemon local-alert state.
//!
//! The watch daemon scans on a schedule. Without memory it would notify the
//! same findings every cycle (noise); with memory it can alert ONLY on findings
//! that are *new* since the last scan: "a package you already have just became
//! dangerous". This is the free-tier, no-account half of retroactive alerts:
//! it needs no login and nothing leaves the machine.
//!
//! The state is a small JSON file at `~/.husk/daemon-state.json` holding the set
//! of finding ids seen on the previous run. [`reconcile`] is pure (no IO) so the
//! delta logic is fully unit-testable; [`load_state`]/[`save_state`] do the IO.

use crate::model::ScanReport;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Persisted memory of what the daemon has already alerted on.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DaemonState {
    pub updated_at: Option<DateTime<Utc>>,
    /// Finding ids seen on the previous scan.
    pub seen: BTreeSet<String>,
}

/// The delta between the previous run and the current scan.
///
/// On the first ever run there is no prior state, so the current set becomes the
/// baseline and both lists are empty: a fresh install must not alert on
/// everything it finds.
#[derive(Clone, Debug, Default)]
pub struct AlertDiff {
    /// Finding ids present now but not on the previous run.
    pub new_ids: Vec<String>,
    /// Finding ids present before but gone now (resolved).
    pub resolved_ids: Vec<String>,
}

/// Compute the new/resolved delta and the next state to persist. Pure: `now` is
/// injected so the result is deterministic and testable.
pub fn reconcile(
    prior: Option<DaemonState>,
    report: &ScanReport,
    now: DateTime<Utc>,
) -> (DaemonState, AlertDiff) {
    let current: BTreeSet<String> = report.findings.iter().map(|f| f.id.clone()).collect();
    let baseline = prior.is_none();
    let prior_seen = prior.map(|s| s.seen).unwrap_or_default();

    let diff = if baseline {
        AlertDiff {
            new_ids: Vec::new(),
            resolved_ids: Vec::new(),
        }
    } else {
        AlertDiff {
            new_ids: current
                .iter()
                .filter(|id| !prior_seen.contains(*id))
                .cloned()
                .collect(),
            resolved_ids: prior_seen
                .iter()
                .filter(|id| !current.contains(*id))
                .cloned()
                .collect(),
        }
    };

    let state = DaemonState {
        updated_at: Some(now),
        seen: current,
    };
    (state, diff)
}

fn state_path() -> Result<PathBuf> {
    Ok(crate::paths::husk_home()?.join("daemon-state.json"))
}

/// Load the prior daemon state, or `None` on first run. A corrupt/unreadable
/// state file is treated as `None` (re-baseline) rather than erroring; that
/// avoids an alert storm where every current finding looks "new".
pub fn load_state() -> Result<Option<DaemonState>> {
    load_state_at(&state_path()?)
}

pub fn load_state_at(path: &Path) -> Result<Option<DaemonState>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("read daemon state"),
    }
}

/// Persist the daemon state (creating `~/.husk` if needed).
pub fn save_state(state: &DaemonState) -> Result<()> {
    save_state_at(&state_path()?, state)
}

pub fn save_state_at(path: &Path, state: &DaemonState) -> Result<()> {
    if let Some(parent) = path.parent() {
        // Owner-only (0700), like every other `~/.husk` writer; the daemon
        // may be the first feature that ever creates the state dir.
        crate::paths::ensure_dir_private(parent)?;
    }
    crate::paths::write_atomic(path, &serde_json::to_vec_pretty(state)?)
        .context("write daemon state")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, ScanReport, Severity};

    fn report_with(ids: &[&str]) -> ScanReport {
        let findings = ids
            .iter()
            .map(|id| {
                Finding::new(
                    *id,
                    "t",
                    Severity::High,
                    crate::rule::Category::Secret,
                    "test",
                    None,
                    None,
                    "s",
                    None,
                    "r",
                )
            })
            .collect();
        let mut report = ScanReport::empty(vec![]);
        report.findings = findings;
        report
    }

    #[test]
    fn first_run_is_baseline_with_no_alerts() {
        let (state, diff) = reconcile(None, &report_with(&["a", "b"]), Utc::now());
        assert!(
            diff.new_ids.is_empty() && diff.resolved_ids.is_empty(),
            "baseline never reports new or resolved findings"
        );
        assert_eq!(state.seen.len(), 2);
    }

    #[test]
    fn only_genuinely_new_findings_are_reported() {
        let (prior, _) = reconcile(None, &report_with(&["a", "b"]), Utc::now());
        let (_, diff) = reconcile(Some(prior), &report_with(&["a", "b", "c"]), Utc::now());
        assert_eq!(diff.new_ids, vec!["c".to_string()]);
        assert!(diff.resolved_ids.is_empty());
    }

    #[test]
    fn resolved_findings_are_tracked() {
        let (prior, _) = reconcile(None, &report_with(&["a", "b"]), Utc::now());
        let (_, diff) = reconcile(Some(prior), &report_with(&["a"]), Utc::now());
        assert!(diff.new_ids.is_empty());
        assert_eq!(diff.resolved_ids, vec!["b".to_string()]);
    }

    #[test]
    fn steady_state_reports_nothing() {
        let (prior, _) = reconcile(None, &report_with(&["a", "b"]), Utc::now());
        let (_, diff) = reconcile(Some(prior), &report_with(&["a", "b"]), Utc::now());
        assert!(diff.new_ids.is_empty() && diff.resolved_ids.is_empty());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state").join("daemon-state.json");
        let (state, _) = reconcile(None, &report_with(&["a", "b"]), Utc::now());
        save_state_at(&path, &state).unwrap();
        let loaded = load_state_at(&path).unwrap().expect("state present");
        assert_eq!(loaded.seen, state.seen);
        // Corrupt file -> None (re-baseline), never an error.
        std::fs::write(&path, b"{not json").unwrap();
        assert!(load_state_at(&path).unwrap().is_none());
    }
}
