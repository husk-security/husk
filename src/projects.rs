//! Projects as the durable unit of attention, independent of any one scan.
//!
//! A project's result is never a stored artifact of its own. Every report
//! already carries the projects it covered ([`ScanReport::projects`]) and tags
//! each finding with the project it belongs to, so a machine scan of the whole
//! home directory *is* a scan of every project under it. The per-project view
//! is that slice, resolved on read: for each project, the newest stored report
//! that covered it wins, whether it came from `husk scan <project>` or from a
//! machine scan. Duplicating the slice to disk would only create a second copy
//! to keep fresh.
//!
//! Tracking is the one thing a scan cannot tell us. Which projects a developer
//! cares about is a decision, so it lives in `~/.husk/projects.json` (durable
//! state) rather than in the deletable cache. Everything else about a project,
//! including its very existence, is rediscovered by scanning.

use crate::model::{Finding, Project, ProjectId, ScanKind, ScanReport};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// One project's slice of the newest report that covered it.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectScan {
    pub project: Project,
    pub findings: Vec<Finding>,
    pub scanned_at: DateTime<Utc>,
    /// Which scan produced this slice. A machine-scan slice is as current as a
    /// project-scan slice; surfaces show the source so the age is explainable.
    pub source: ScanKind,
    pub roots: Vec<PathBuf>,
}

/// A project as every surface sees it: identity and tracking state always,
/// scan results when something has scanned it.
#[derive(Clone, Debug, Serialize)]
pub struct ProjectView {
    pub id: ProjectId,
    pub root: PathBuf,
    pub name: String,
    /// The user asked for this project by name. Untracked projects are the
    /// ones a scan merely walked past.
    pub tracked: bool,
    /// `None` until some scan has covered this root.
    pub scan: Option<ProjectScan>,
}

impl ProjectView {
    fn from_scan(scan: ProjectScan, tracked: bool) -> Self {
        Self {
            id: scan.project.id.clone(),
            root: scan.project.root.clone(),
            name: scan.project.name.clone(),
            tracked,
            scan: Some(scan),
        }
    }

    fn unscanned(root: PathBuf) -> Self {
        Self {
            id: ProjectId::from_root(&root),
            name: display_name(&root),
            root,
            tracked: true,
            scan: None,
        }
    }
}

fn display_name(root: &Path) -> String {
    root.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.display().to_string())
}

/// Every project husk knows about: tracked ones first, then the rest by worst
/// severity. Built by folding the stored reports newest-first, so the first
/// report to mention a project is the freshest one that covered it.
pub fn index() -> Result<Vec<ProjectView>> {
    Ok(index_from(&crate::cache::stored_reports()?, &tracked()?))
}

/// Pure core of [`index`]: `reports` newest-first, `tracked` as stored.
fn index_from(reports: &[ScanReport], tracked: &[PathBuf]) -> Vec<ProjectView> {
    let tracked_ids: Vec<ProjectId> = tracked.iter().map(|r| ProjectId::from_root(r)).collect();

    let mut freshest: HashMap<ProjectId, ProjectScan> = HashMap::new();
    for report in reports {
        for project in &report.projects {
            if !covers(&report.roots, &project.root) {
                continue;
            }
            let fresher = freshest
                .get(&project.id)
                .is_none_or(|held| report.generated_at > held.scanned_at);
            if !fresher {
                continue;
            }
            freshest.insert(
                project.id.clone(),
                ProjectScan {
                    project: project.clone(),
                    findings: report.project_findings(&project.id).cloned().collect(),
                    scanned_at: report.generated_at,
                    source: report.kind,
                    roots: report.roots.clone(),
                },
            );
        }
    }

    let mut views: Vec<ProjectView> = freshest
        .into_values()
        .map(|scan| {
            let tracked = tracked_ids.contains(&scan.project.id);
            ProjectView::from_scan(scan, tracked)
        })
        .collect();

    // A root the user tracked before anything scanned it still has to appear,
    // or the UI would silently drop what they just added.
    let known: Vec<ProjectId> = views.iter().map(|view| view.id.clone()).collect();
    for (root, id) in tracked.iter().zip(&tracked_ids) {
        if !known.contains(id) {
            views.push(ProjectView::unscanned(root.clone()));
        }
    }

    views.sort_by(|a, b| {
        b.tracked
            .cmp(&a.tracked)
            .then_with(|| severity_rank(b).cmp(&severity_rank(a)))
            .then_with(|| a.name.cmp(&b.name))
    });
    views
}

/// Whether a report's slice for this project is the *whole* project, rather
/// than whatever part of it happened to sit under the scan roots. `husk scan
/// src/` inside a repo attributes its findings to that repo, but it never
/// looked at the rest of it, so treating that slice as the project's current
/// state would hide every finding outside `src/`. Only a scan rooted at or
/// above the project speaks for it, which is why a machine scan speaks for
/// every project under the home directory.
fn covers(roots: &[PathBuf], project_root: &Path) -> bool {
    roots.iter().any(|root| project_root.starts_with(root))
}

/// Worst-severity rank for ordering; an unscanned project sorts last within
/// its tracking group because husk has nothing to say about it yet.
fn severity_rank(view: &ProjectView) -> i32 {
    view.scan
        .as_ref()
        .and_then(|scan| scan.project.rollup.worst_severity)
        .map_or(-1, |severity| severity as i32)
}

/// The freshest slice for one project, wherever it came from.
pub fn scan_for(id: &ProjectId) -> Result<Option<ProjectScan>> {
    Ok(index()?
        .into_iter()
        .find(|view| &view.id == id)
        .and_then(|view| view.scan))
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct TrackedFile {
    v: u32,
    /// Canonical absolute roots. Ids are derived, never stored: a stale id
    /// next to its root would be a second source of truth.
    roots: Vec<PathBuf>,
}

const TRACKED_SCHEMA: u32 = 1;

fn tracked_path() -> Result<PathBuf> {
    Ok(crate::paths::husk_home()?.join("projects.json"))
}

/// Roots the user explicitly tracks. A missing or unreadable file means
/// "nothing tracked yet", never an error: tracking is a preference, and losing
/// it must not stop a scan.
pub fn tracked() -> Result<Vec<PathBuf>> {
    tracked_in(&tracked_path()?)
}

fn tracked_in(path: &Path) -> Result<Vec<PathBuf>> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Ok(Vec::new());
    };
    let file: TrackedFile = serde_json::from_str(&contents).unwrap_or_default();
    if file.v != TRACKED_SCHEMA {
        return Ok(Vec::new());
    }
    Ok(file.roots)
}

/// Track or untrack one root. Idempotent, and canonicalizing first is what
/// makes the derived [`ProjectId`] match the one a scan produced.
pub fn set_tracked(root: &Path, on: bool) -> Result<()> {
    set_tracked_in(&tracked_path()?, root, on)
}

fn set_tracked_in(path: &Path, root: &Path, on: bool) -> Result<()> {
    let root = std::fs::canonicalize(root)
        .with_context(|| format!("no such directory: {}", root.display()))?;
    let mut roots = tracked_in(path)?;
    let held = roots.iter().position(|held| held == &root);
    match (on, held) {
        (true, None) => roots.push(root),
        (false, Some(at)) => {
            roots.remove(at);
        }
        _ => return Ok(()),
    }
    roots.sort();
    let file = TrackedFile {
        v: TRACKED_SCHEMA,
        roots,
    };
    crate::paths::write_private(path, &serde_json::to_vec_pretty(&file)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Activity, ProjectKind, ProjectRollup, Severity};
    use crate::rule::Category;

    fn project(root: &str) -> Project {
        let root = PathBuf::from(root);
        Project {
            id: ProjectId::from_root(&root),
            name: display_name(&root),
            root,
            kind: ProjectKind::GitRepo,
            submodule_of: None,
            git: None,
            last_modified: None,
            activity: Activity::Recent,
            ecosystems: Vec::new(),
            package_count: 0,
            rollup: ProjectRollup::default(),
            posture: None,
        }
    }

    fn finding(id: &str, project: &Project) -> Finding {
        let mut finding = Finding::new(
            id,
            "title",
            Severity::High,
            Category::Vulnerability,
            "test",
            None,
            None,
            "summary",
            None,
            "fix it",
        );
        finding.project_id = Some(project.id.clone());
        finding
    }

    fn report(kind: ScanKind, at: DateTime<Utc>, projects: Vec<Project>) -> ScanReport {
        rooted_report(kind, at, projects, "/home/dev")
    }

    fn rooted_report(
        kind: ScanKind,
        at: DateTime<Utc>,
        projects: Vec<Project>,
        root: &str,
    ) -> ScanReport {
        let mut report = ScanReport::empty(vec![PathBuf::from(root)]);
        report.kind = kind;
        report.generated_at = at;
        report.findings = projects.iter().map(|p| finding("f", p)).collect();
        report.projects = projects;
        report
    }

    fn at(hour: u32) -> DateTime<Utc> {
        chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .and_then(|d| d.and_hms_opt(hour, 0, 0))
            .expect("timestamp")
            .and_utc()
    }

    /// The point of the whole model: a machine scan yields a result for every
    /// project under it, with no per-project artifact stored anywhere.
    #[test]
    fn a_machine_scan_gives_every_project_it_covered_a_result() {
        let alpha = project("/home/dev/alpha");
        let beta = project("/home/dev/beta");
        let machine = report(ScanKind::Machine, at(9), vec![alpha.clone(), beta.clone()]);

        let views = index_from(&[machine], &[]);
        assert_eq!(views.len(), 2);
        for view in &views {
            let scan = view.scan.as_ref().expect("machine scan covered it");
            assert_eq!(scan.source, ScanKind::Machine);
            assert_eq!(scan.findings.len(), 1, "only this project's findings");
        }
    }

    #[test]
    fn the_freshest_result_wins_whichever_scan_produced_it() {
        let alpha = project("/home/dev/alpha");
        let beta = project("/home/dev/beta");
        // Newest-first, as the cache serves them.
        let reports = vec![
            report(ScanKind::Project, at(11), vec![alpha.clone()]),
            report(ScanKind::Machine, at(10), vec![alpha.clone(), beta.clone()]),
        ];

        let views = index_from(&reports, &[]);
        let by_name = |name: &str| {
            views
                .iter()
                .find(|view| view.name == name)
                .expect("project present")
                .scan
                .as_ref()
                .expect("scanned")
                .clone()
        };
        // The later project scan beats the machine scan for alpha...
        assert_eq!(by_name("alpha").source, ScanKind::Project);
        assert_eq!(by_name("alpha").scanned_at, at(11));
        // ...while beta keeps the machine scan, its only coverage.
        assert_eq!(by_name("beta").source, ScanKind::Machine);
    }

    /// Report order is by mtime, which a clock change can invert; the fold
    /// compares the scans' own timestamps rather than trusting the order.
    #[test]
    fn an_older_report_listed_first_does_not_overwrite_a_newer_slice() {
        let alpha = project("/home/dev/alpha");
        let reports = vec![
            report(ScanKind::Project, at(8), vec![alpha.clone()]),
            report(ScanKind::Machine, at(12), vec![alpha.clone()]),
        ];

        let scan = index_from(&reports, &[])[0].scan.clone().expect("scanned");
        assert_eq!(scan.scanned_at, at(12));
    }

    /// Scanning one subdirectory of a project must not replace the project's
    /// result with that subdirectory's findings, which would hide everything
    /// outside it.
    #[test]
    fn a_partial_scan_of_a_subdirectory_does_not_shadow_a_full_result() {
        let alpha = project("/home/dev/alpha");
        let reports = vec![
            rooted_report(
                ScanKind::Project,
                at(14),
                vec![alpha.clone()],
                "/home/dev/alpha/src",
            ),
            report(ScanKind::Machine, at(10), vec![alpha.clone()]),
        ];

        let scan = index_from(&reports, &[])[0].scan.clone().expect("scanned");
        assert_eq!(
            scan.scanned_at,
            at(10),
            "the covering machine scan still speaks for the project"
        );
        assert_eq!(scan.source, ScanKind::Machine);
    }

    #[test]
    fn a_project_only_ever_touched_by_a_partial_scan_has_no_result_yet() {
        let alpha = project("/home/dev/alpha");
        let partial = rooted_report(
            ScanKind::Project,
            at(14),
            vec![alpha.clone()],
            "/home/dev/alpha/src",
        );
        assert!(index_from(&[partial], &[]).is_empty());
    }

    #[test]
    fn tracking_marks_a_scanned_project_and_sorts_it_first() {
        let alpha = project("/home/dev/alpha");
        let beta = project("/home/dev/beta");
        let machine = report(ScanKind::Machine, at(9), vec![alpha.clone(), beta.clone()]);

        let views = index_from(&[machine], std::slice::from_ref(&beta.root));
        assert_eq!(views[0].name, "beta");
        assert!(views[0].tracked);
        assert!(!views[1].tracked);
    }

    #[test]
    fn a_tracked_root_nothing_has_scanned_still_appears() {
        let views = index_from(&[], &[PathBuf::from("/home/dev/fresh")]);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].name, "fresh");
        assert!(views[0].tracked);
        assert!(views[0].scan.is_none(), "nothing has scanned it yet");
    }

    #[test]
    fn tracking_round_trips_and_is_idempotent() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("projects.json");
        let root = temp.path().join("repo");
        std::fs::create_dir_all(&root).expect("repo");

        set_tracked_in(&file, &root, true).expect("track");
        set_tracked_in(&file, &root, true).expect("track again");
        assert_eq!(tracked_in(&file).expect("read").len(), 1);

        set_tracked_in(&file, &root, false).expect("untrack");
        assert!(tracked_in(&file).expect("read").is_empty());
        set_tracked_in(&file, &root, false).expect("untrack again");
    }

    #[test]
    fn a_corrupt_tracked_file_reads_as_nothing_tracked_not_an_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("projects.json");
        std::fs::write(&file, b"not json").expect("write");
        assert!(tracked_in(&file).expect("degrades quietly").is_empty());
    }
}
