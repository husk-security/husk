//! Project-aware scoring: turns raw findings into ranked, activity-weighted
//! priorities per project.
//!
//! Pure and offline-safe: consumes `finding.exploit` (KEV/EPSS, `None` offline) +
//! local project activity + `confidence`, so an offline scan still gets the full
//! ambient/exposure split and activity demotion; only the exploit *boost* needs
//! the network. **Owns both the project rank and the flat-list sort.** Integer
//! points throughout for deterministic, golden-testable ties.
//!
//! CI gating (`husk ci --fail-on`) keys on raw `finding.severity`, NEVER on these
//! activity-demoted action bands: a demotion must never un-fail a pipeline.

use crate::model::{
    Action, Activity, CategoryRollup, DemotionReason, Finding, PostureSummary, Priority,
    ProjectBucket, ProjectId, ProjectKind, ProjectPosture, ScanReport, Severity,
};
use crate::rule::{Confidence, RiskClass};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const fn severity_points(sev: Severity) -> i64 {
    match sev {
        Severity::Critical => 500,
        Severity::High => 300,
        Severity::Medium => 150,
        Severity::Low => 60,
        Severity::Info => 25,
    }
}

const KEV_BOOST: i64 = 1000; // pushes anything to `Act`
const EPSS_WEIGHT: i64 = 400; // EPSS (0..1) × this
const EXPOSURE_FLOOR: i64 = 200; // Firm exposure never below `Attend`

const BAND_ACT: i64 = 450;
const BAND_ATTEND: i64 = 200;
const BAND_TRACK: i64 = 60;

fn band(score: i64) -> Action {
    if score >= BAND_ACT {
        Action::Act
    } else if score >= BAND_ATTEND {
        Action::Attend
    } else if score >= BAND_TRACK {
        Action::Track
    } else {
        Action::Ambient
    }
}

// Ambient activity multiplier as (numerator, denominator). Never zero.
const fn ambient_mult(activity: Activity) -> (i64, i64) {
    match activity {
        Activity::Active => (100, 100),
        Activity::Recent => (85, 100),
        Activity::Dormant => (40, 100),
        Activity::Abandoned => (15, 100),
    }
}

// Recency boost added to a project's rank so fresher projects float up.
const fn recency_boost(activity: Activity) -> i64 {
    match activity {
        Activity::Active => 300,
        Activity::Recent => 150,
        Activity::Dormant => 50,
        Activity::Abandoned => 0,
    }
}

/// What one category contributes, before it becomes a [`CategoryRollup`]. The
/// subjects are carried as a set rather than a count so the aggregate can union
/// the projects instead of summing them.
struct Tally {
    count: usize,
    worst_severity: Severity,
    act_count: usize,
    subjects: BTreeSet<String>,
}

impl Default for Tally {
    fn default() -> Self {
        Tally {
            count: 0,
            worst_severity: Severity::Info,
            act_count: 0,
            subjects: BTreeSet::new(),
        }
    }
}

type CategoryTally = BTreeMap<crate::rule::Category, Tally>;

fn tally_category(
    map: &mut CategoryTally,
    category: crate::rule::Category,
    severity: Severity,
    act_count: usize,
    subjects: impl IntoIterator<Item = String>,
) {
    let entry = map.entry(category).or_default();
    entry.count += 1;
    if severity > entry.worst_severity {
        entry.worst_severity = severity;
    }
    entry.act_count += act_count;
    entry.subjects.extend(subjects);
}

/// A tally map → `Vec<CategoryRollup>`, sorted worst-first
/// (act count → worst severity → count), category id breaking ties so the order
/// is the same on every run.
fn rollup_categories(map: CategoryTally) -> Vec<CategoryRollup> {
    let mut by_category: Vec<CategoryRollup> = map
        .into_iter()
        .map(|(category, tally)| CategoryRollup {
            category,
            count: tally.count,
            subjects: tally.subjects.len(),
            worst_severity: tally.worst_severity,
            act_count: tally.act_count,
        })
        .collect();
    by_category.sort_by(|a, b| {
        b.act_count
            .cmp(&a.act_count)
            .then_with(|| b.worst_severity.cmp(&a.worst_severity))
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.category.id().cmp(b.category.id()))
    });
    by_category
}

/// The subfolder a finding sits in, relative to its project root, capped at two
/// segments. The same vulnerable package in `web/` and in `cli/` is two
/// lockfiles and two fixes, so it is two subjects.
fn subfolder(path: &std::path::Path, root: &std::path::Path) -> String {
    let Ok(relative) = path.strip_prefix(root) else {
        return String::new();
    };
    let mut segments: Vec<&str> = relative
        .parent()
        .into_iter()
        .flat_map(|dir| dir.components())
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    segments.truncate(2);
    segments.join("/")
}

/// The identity of the thing a finding is about (see [`Finding::subject`]).
///
/// A coordinate is named by the coordinate, so a package's advisories are one
/// subject however many feeds raised them; everything else is named by its rule
/// title. Both are qualified by the project and the subfolder within it,
/// because those are what separate two instances a reader must fix separately.
fn subject_of(finding: &Finding, root: Option<&std::path::Path>) -> String {
    let project = finding.project_id.as_ref().map_or("", |id| id.0.as_str());
    let location = finding
        .path
        .as_deref()
        .or(finding.package.as_ref().map(|p| p.manifest_path.as_path()))
        .zip(root)
        .map(|(path, root)| subfolder(path, root))
        .unwrap_or_default();
    let what = match &finding.package {
        Some(package) => format!("{}:{}", package.ecosystem, package.name),
        None => finding.title.clone(),
    };
    format!(
        "{project}\u{1f}{location}\u{1f}{}\u{1f}{what}",
        finding.category.id()
    )
}

fn exploit_points(f: &Finding) -> (i64, bool) {
    match &f.exploit {
        Some(e) => {
            let kev = e.kev;
            let epss = e.epss.unwrap_or(0.0);
            let boost =
                if kev { KEV_BOOST } else { 0 } + (epss * EPSS_WEIGHT as f64).round() as i64;
            (boost, kev)
        }
        None => (0, false),
    }
}

fn score_finding(f: &Finding, activity: Activity, is_submodule: bool) -> Priority {
    let risk_class = f.category.risk_class();
    let (boost, kev) = exploit_points(f);
    let raw = severity_points(f.severity) + boost;

    match risk_class {
        // Exposure: activity-invariant. Floor at `Attend` for confident matches.
        RiskClass::Exposure => {
            let (score, demoted_by) = match f.confidence {
                // A *tentative* match (a synthetic/low-entropy secret, a test
                // fixture) is exactly the false-positive that shouldn't scream:
                // no floor AND a hard dampener, so a placeholder `ghp_abcdef…` in
                // a `*.test.ts` never outranks a real leaked credential.
                Confidence::Tentative => (raw * 30 / 100, Some(DemotionReason::LowConfidence)),
                _ => (raw.max(EXPOSURE_FLOOR), None),
            };
            Priority {
                action: band(score),
                score,
                risk_class,
                demoted_by,
            }
        }
        // Ambient: demoted by inactivity, unless actively exploited (KEV → Act).
        RiskClass::Ambient => {
            if kev {
                return Priority {
                    action: Action::Act,
                    score: raw,
                    risk_class,
                    demoted_by: None,
                };
            }
            let (num, den) = ambient_mult(activity);
            let mut score = raw * num / den;
            let mut demoted_by = None;
            if matches!(activity, Activity::Dormant | Activity::Abandoned) {
                demoted_by = Some(DemotionReason::DormantProject);
            }
            if is_submodule {
                score = score * 30 / 100;
                demoted_by = Some(DemotionReason::SubmoduleNotOwned);
            }
            Priority {
                action: band(score),
                score,
                risk_class,
                demoted_by,
            }
        }
    }
}

/// Score the whole report: annotate every finding's `priority`, compute each
/// project's `posture`, fill `summary`, then sort findings (worst-first) and
/// projects (NeedsAttention → rank → recency → name).
pub fn score_report(report: &mut ScanReport) {
    let mut meta: HashMap<ProjectId, (Activity, bool)> = HashMap::new();
    let mut roots: HashMap<ProjectId, std::path::PathBuf> = HashMap::new();
    for p in &report.projects {
        meta.insert(p.id.clone(), (p.activity, p.kind == ProjectKind::Submodule));
        roots.insert(p.id.clone(), p.root.clone());
    }

    // 1. Score findings and name what each one is about.
    for f in &mut report.findings {
        let (activity, is_sub) = f
            .project_id
            .as_ref()
            .and_then(|id| meta.get(id))
            .copied()
            .unwrap_or((Activity::Recent, false));
        f.priority = Some(score_finding(f, activity, is_sub));
        f.subject = subject_of(
            f,
            f.project_id
                .as_ref()
                .and_then(|id| roots.get(id))
                .map(std::path::PathBuf::as_path),
        );
    }

    // 2. Per-project posture + category rollups.
    let mut by_project: HashMap<ProjectId, Vec<usize>> = HashMap::new();
    for (i, f) in report.findings.iter().enumerate() {
        if let Some(id) = &f.project_id {
            by_project.entry(id.clone()).or_default().push(i);
        }
    }
    // A subject already names its project, so the aggregate unions the projects
    // rather than summing them, and fills in alongside the per-project rollups.
    let mut cat_agg = CategoryTally::new();
    for p in &mut report.projects {
        let idxs = by_project.get(&p.id).cloned().unwrap_or_default();
        let mut act = 0;
        let mut attend = 0;
        let mut track = 0;
        let mut ambient = 0;
        let mut scores: Vec<i64> = Vec::new();
        let mut has_live_exposure = false;
        let mut cat_map = CategoryTally::new();
        for &i in &idxs {
            let f = &report.findings[i];
            let pr = f.priority.as_ref().expect("scored");
            match pr.action {
                Action::Act => act += 1,
                Action::Attend => attend += 1,
                Action::Track => track += 1,
                Action::Ambient => ambient += 1,
            }
            scores.push(pr.score);
            let cat = f.category;
            if cat.risk_class() == RiskClass::Exposure && f.confidence != Confidence::Tentative {
                has_live_exposure = true;
            }
            let is_act = usize::from(pr.action == Action::Act);
            tally_category(&mut cat_map, cat, f.severity, is_act, [f.subject.clone()]);
            tally_category(&mut cat_agg, cat, f.severity, is_act, [f.subject.clone()]);
        }
        p.rollup.by_category = rollup_categories(cat_map);

        let bucket = if act > 0 || attend > 0 || has_live_exposure {
            ProjectBucket::NeedsAttention
        } else {
            ProjectBucket::Dormant
        };
        scores.sort_unstable_by(|a, b| b.cmp(a));
        let rank_score: i64 = scores.iter().take(5).sum::<i64>() + recency_boost(p.activity);
        let worst_action = [
            (act, Action::Act),
            (attend, Action::Attend),
            (track, Action::Track),
            (ambient, Action::Ambient),
        ]
        .into_iter()
        .find(|(n, _)| *n > 0)
        .map(|(_, a)| a)
        .unwrap_or(Action::Ambient);
        p.posture = Some(ProjectPosture {
            bucket,
            rank_score,
            worst_action,
            act,
            attend,
            track,
            ambient,
        });
    }

    // 3. PostureSummary (aggregate).
    let mut summary = PostureSummary {
        projects_total: report.projects.len(),
        ..Default::default()
    };
    for p in &report.projects {
        if let Some(po) = &p.posture {
            if po.bucket == ProjectBucket::NeedsAttention {
                summary.projects_needing_attention += 1;
            }
            summary.act += po.act;
            summary.attend += po.attend;
            summary.track += po.track;
            summary.ambient += po.ambient;
        }
    }
    summary.by_category = rollup_categories(cat_agg);
    report.summary = summary;

    // 4. Sort findings worst-first by score, then severity, then title (stable).
    report.findings.sort_by(|a, b| {
        let sa = a.priority.as_ref().map(|p| p.score).unwrap_or(0);
        let sb = b.priority.as_ref().map(|p| p.score).unwrap_or(0);
        sb.cmp(&sa)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| a.title.cmp(&b.title))
    });

    // 5. Sort projects: NeedsAttention first → rank desc → recency desc → name.
    report.projects.sort_by(|a, b| {
        let attn_a = a
            .posture
            .as_ref()
            .map(|p| p.bucket == ProjectBucket::NeedsAttention)
            .unwrap_or(false);
        let attn_b = b
            .posture
            .as_ref()
            .map(|p| p.bucket == ProjectBucket::NeedsAttention)
            .unwrap_or(false);
        attn_b
            .cmp(&attn_a)
            .then_with(|| {
                let ra = a.posture.as_ref().map(|p| p.rank_score).unwrap_or(0);
                let rb = b.posture.as_ref().map(|p| p.rank_score).unwrap_or(0);
                rb.cmp(&ra)
            })
            .then_with(|| b.last_modified.cmp(&a.last_modified))
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// Per-severity penalties against a starting 100. Info never penalizes; it is
/// context, not risk.
const PENALTY_CRITICAL: i32 = 25;
const PENALTY_HIGH: i32 = 10;
const PENALTY_MEDIUM: i32 = 3;
const PENALTY_LOW: i32 = 1;

/// Weighted 0-100 posture score for a whole scan, higher is healthier. Every
/// surface that shows a score or a score delta derives it here, so they agree.
pub(crate) fn posture_score(stats: &crate::model::ScanStats) -> u32 {
    let penalty = stats.critical as i32 * PENALTY_CRITICAL
        + stats.high as i32 * PENALTY_HIGH
        + stats.medium as i32 * PENALTY_MEDIUM
        + stats.low as i32 * PENALTY_LOW;
    (100 - penalty).clamp(0, 100) as u32
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Category;

    fn finding(sev: Severity, cat: Category) -> Finding {
        let mut f = Finding::from_rule("score-test")
            .title("t")
            .severity(sev)
            .source("s");
        f.category = cat;
        f
    }

    #[test]
    fn exposure_is_activity_invariant() {
        // A live secret in an abandoned project still floors at Attend (Act here:
        // Critical secret = 500 → Act).
        let f = finding(Severity::Critical, Category::Secret);
        let p = score_finding(&f, Activity::Abandoned, false);
        assert_eq!(p.action, Action::Act);
    }

    #[test]
    fn dormant_critical_ambient_demotes_to_attend() {
        // Critical vuln in a dormant project: 500 × 0.40 = 200 → exactly Attend.
        let f = finding(Severity::Critical, Category::Vulnerability);
        let p = score_finding(&f, Activity::Dormant, false);
        assert_eq!(p.score, 200);
        assert_eq!(p.action, Action::Attend);
        assert_eq!(p.demoted_by, Some(DemotionReason::DormantProject));
    }

    #[test]
    fn abandoned_ambient_sinks_to_ambient_band() {
        // High vuln, abandoned: 300 × 0.15 = 45 → below Track(60) → Ambient.
        let f = finding(Severity::High, Category::Vulnerability);
        let p = score_finding(&f, Activity::Abandoned, false);
        assert_eq!(p.action, Action::Ambient);
    }

    #[test]
    fn kev_ambient_short_circuits_to_act() {
        let mut f = finding(Severity::Low, Category::Vulnerability);
        f.exploit = Some(crate::model::ExploitInfo {
            kev: true,
            epss: None,
        });
        let p = score_finding(&f, Activity::Abandoned, false);
        assert_eq!(p.action, Action::Act);
    }

    #[test]
    fn category_risk_class_holds() {
        assert_eq!(Category::Secret.risk_class(), RiskClass::Exposure);
        assert_eq!(Category::Vulnerability.risk_class(), RiskClass::Ambient);
        assert_eq!(Category::InstallHardening.risk_class(), RiskClass::Exposure);
    }

    fn vuln_at(root: &str, manifest: &str, name: &str, advisory: &str) -> Finding {
        let mut f = finding(Severity::High, Category::Vulnerability);
        f.id = advisory.to_string();
        f.title = format!("{advisory} affects {name}");
        f.project_id = Some(crate::model::ProjectId::from_root(std::path::Path::new(
            root,
        )));
        f.package = Some(crate::model::PackageRef {
            ecosystem: "pypi".to_string(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            manifest_path: std::path::PathBuf::from(manifest),
            line: None,
        });
        f
    }

    fn scored(root: &str, findings: Vec<Finding>) -> ScanReport {
        let mut report = ScanReport::empty(vec![std::path::PathBuf::from(root)]);
        report.projects = vec![crate::model::Project {
            id: crate::model::ProjectId::from_root(std::path::Path::new(root)),
            root: std::path::PathBuf::from(root),
            name: "p".to_string(),
            kind: ProjectKind::GitRepo,
            submodule_of: None,
            git: None,
            last_modified: None,
            activity: Activity::Active,
            ecosystems: Vec::new(),
            package_count: 0,
            rollup: Default::default(),
            posture: None,
        }];
        report.findings = findings;
        score_report(&mut report);
        report
    }

    #[test]
    fn a_categorys_subjects_count_things_not_advisories() {
        // "14 vulnerable dependencies" has to mean dependencies. Six advisories
        // against two coordinates are two subjects and six findings, and both
        // numbers travel so no surface has to guess which one its label means.
        let report = scored(
            "/p",
            vec![
                vuln_at("/p", "/p/api/uv.lock", "urllib3", "CVE-1"),
                vuln_at("/p", "/p/api/uv.lock", "urllib3", "CVE-2"),
                vuln_at("/p", "/p/api/uv.lock", "urllib3", "CVE-3"),
                vuln_at("/p", "/p/api/uv.lock", "requests", "CVE-4"),
                vuln_at("/p", "/p/api/uv.lock", "requests", "CVE-5"),
                vuln_at("/p", "/p/api/uv.lock", "requests", "CVE-6"),
            ],
        );
        let rollup = &report.summary.by_category[0];
        assert_eq!(rollup.category, Category::Vulnerability);
        assert_eq!(rollup.count, 6);
        assert_eq!(rollup.subjects, 2);
    }

    #[test]
    fn one_package_in_two_subfolders_is_two_subjects() {
        // Two lockfiles are two edits, so the reader gets two rows and the
        // headline has to agree with the list it heads.
        let report = scored(
            "/p",
            vec![
                vuln_at("/p", "/p/web/package-lock.json", "minimist", "CVE-1"),
                vuln_at("/p", "/p/cli/package-lock.json", "minimist", "CVE-1"),
            ],
        );
        assert_eq!(report.summary.by_category[0].subjects, 2);
    }

    #[test]
    fn the_aggregate_unions_projects_rather_than_summing_them() {
        let report = scored(
            "/p",
            vec![
                vuln_at("/p", "/p/uv.lock", "urllib3", "CVE-1"),
                vuln_at("/p", "/p/uv.lock", "urllib3", "CVE-2"),
            ],
        );
        assert_eq!(
            report.summary.by_category[0].subjects,
            report.projects[0].rollup.by_category[0].subjects
        );
    }
}
