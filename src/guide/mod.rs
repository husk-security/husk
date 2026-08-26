//! Scan-backed security guidance compiled from `guides/*.md`.

pub mod control;

use crate::guide::control::{ControlAssessment, ControlStatus, Evidence};
use crate::model::{Finding, ScanReport, Severity};
use crate::remediation::ExecutionClass;
use anyhow::Context;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Step {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Opt {
    pub name: String,
    pub recommended: bool,
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Source {
    pub title: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Solution {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub husk: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuideKind {
    Baseline,
    Recommendation,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verification {
    /// A registered control observes this guide against the scan.
    #[default]
    Automatic,
    /// Husk cannot observe this at all: the evidence lives in an online account
    /// or a vendor console. There is no control and no control status; the user
    /// completes or dismisses it themselves.
    Manual,
}

/// How many tasks one authored item becomes.
///
/// Upgrading Python dependencies in one repository and Go dependencies in
/// another are separate jobs, done at different times and carrying different
/// risk. One checkbox over both can never honestly be ticked, so an item
/// declares the unit of work it actually is and `assess` expands it into one
/// task per subject the scan found something in.
///
/// A split runs along keys the finding itself carries, so only an item whose
/// control attaches findings can be split, and only where the split names real
/// separate work: "encrypt your disk" is one job however many projects are on
/// the disk.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// One task, for the machine.
    #[default]
    Machine,
    /// One task per project the control found something in.
    Project,
    /// One task per (project, ecosystem) pair the control found something in.
    ProjectEcosystem,
}

/// Build-generated representation of one Markdown guide.
#[derive(Clone, Deserialize)]
pub struct GuideDefinition {
    pub id: String,
    pub category: String,
    pub kind: GuideKind,
    pub severity: Severity,
    #[serde(default)]
    pub verification: Verification,
    #[serde(default)]
    pub scope: Scope,
    /// `None` exactly when `verification` is `Manual`; `build.rs` enforces it.
    #[serde(default)]
    pub control: Option<String>,
    #[serde(default)]
    pub related_rules: Vec<String>,
    pub title: String,
    pub why: String,
    pub problem: String,
    #[serde(default)]
    pub estimate: String,
    pub steps: Vec<Step>,
    #[serde(default)]
    pub options: Vec<Opt>,
    #[serde(default)]
    pub sources: Vec<Source>,
    pub solution: Solution,
}

const CATALOG_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/guide_catalog.json"));

pub fn catalog() -> &'static [GuideDefinition] {
    static CATALOG: OnceLock<Vec<GuideDefinition>> = OnceLock::new();
    CATALOG.get_or_init(|| serde_json::from_str(CATALOG_JSON).expect("compiled guide catalog"))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Completed,
    Dismissed,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TaskState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UserState {
    #[serde(default)]
    pub tasks: BTreeMap<String, TaskState>,
}

/// Where review state lives: `~/.husk/guide.json`, resolved through
/// [`crate::paths::husk_home`] so `HUSK_HOME` redirects it like every other
/// durable local file. Tests and agent runs that set `HUSK_HOME` must never
/// touch the developer's real checklist.
pub fn data_file() -> anyhow::Result<PathBuf> {
    Ok(crate::paths::husk_home()?.join("guide.json"))
}

pub fn load_state() -> UserState {
    data_file()
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn save_state(state: &UserState) -> anyhow::Result<()> {
    let path = data_file()?;
    let dir = path.parent().context("guide state has no parent")?;
    crate::paths::ensure_dir_private(dir)?;
    crate::paths::write_atomic(&path, &serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuideAction {
    Read,
    Complete,
    Dismiss,
    Clear,
}

impl std::str::FromStr for GuideAction {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value {
            "read" => Ok(Self::Read),
            "complete" => Ok(Self::Complete),
            "dismiss" => Ok(Self::Dismiss),
            "clear" => Ok(Self::Clear),
            _ => anyhow::bail!("unknown guide action `{value}`"),
        }
    }
}

/// Whether `id` names a task the catalog can produce: an item id, or one of a
/// scoped item's instance ids (see [`instance_id`]).
///
/// The subject half is not checked against the current scan. A decision is
/// allowed to arrive for an instance this machine cannot see right now, and an
/// id no instance carries simply never matches a row.
pub fn is_known_task(id: &str) -> bool {
    let (base, qualified) = match id.split_once(['@', '#']) {
        Some((base, _)) => (base, true),
        None => (id, false),
    };
    catalog()
        .iter()
        .any(|task| task.id == base && (!qualified || task.scope != Scope::Machine))
}

/// The id of one instance of a scoped item: the item, the project the findings
/// belong to, and the ecosystem they came from.
///
/// Stable across rescans of an unchanged tree because every part is: the item
/// id is authored, [`crate::model::ProjectId`] is a hash of the project's
/// canonical root, and the ecosystem is the scanner's own id. Moving or
/// renaming a project changes its root and therefore its instance ids, and an
/// ecosystem that disappears takes its instance with it. Both strand whatever
/// the user decided under the old id, which is the intended failure: the old
/// id names a subject that no longer exists, and no other instance can claim
/// it, because `@` and `#` appear in none of the three parts.
fn instance_id(item: &str, project: &str, ecosystem: &str) -> String {
    let mut id = item.to_string();
    if !project.is_empty() {
        id.push('@');
        id.push_str(project);
    }
    if !ecosystem.is_empty() {
        id.push('#');
        id.push_str(ecosystem);
    }
    id
}

/// What makes two evidence rows the same row.
fn evidence_key(row: &Evidence) -> (String, Option<PathBuf>, Option<usize>) {
    (row.summary.clone(), row.path.clone(), row.line)
}

/// One task in the assessed guide: a whole item, or one slice of a scoped one.
struct Row {
    id: String,
    title: String,
    evidence: Vec<Evidence>,
    finding_ids: Vec<String>,
    /// `Some` once the item was split: the worst severity among this slice's
    /// own findings, and the signal that remediation belongs to it alone.
    slice_severity: Option<Severity>,
}

/// The subject one slice of a scoped item covers, ordered so a rescan of an
/// unchanged tree lists the slices identically: the project's own place in the
/// report (worst first), then its id, then the ecosystem. A finding whose
/// project is not in the report sorts last under an empty id.
type SliceKey = (usize, String, String);

/// Expand one authored item into the tasks it is.
///
/// The whole item is one task unless it declares a subject scope *and* its
/// control attached findings to split along. A scoped item with nothing found
/// stays a single row: there is no per-project work to list, and one row saying
/// so keeps the item countable.
fn rows(
    definition: &GuideDefinition,
    control: Option<&ControlAssessment>,
    report: &ScanReport,
) -> Vec<Row> {
    let whole = || {
        vec![Row {
            id: definition.id.clone(),
            title: definition.title.clone(),
            evidence: control.map(|c| c.evidence.clone()).unwrap_or_default(),
            finding_ids: control.map(|c| c.finding_ids.clone()).unwrap_or_default(),
            slice_severity: None,
        }]
    };
    if definition.scope == Scope::Machine {
        return whole();
    }
    let Some(control) = control else {
        return whole();
    };

    let ranks = report
        .projects
        .iter()
        .enumerate()
        .map(|(rank, project)| (project.id.0.as_str(), rank))
        .collect::<HashMap<_, _>>();
    let owned = control
        .finding_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    // Walked in report order, which scoring already sorted worst-first, so the
    // findings inside a slice keep that order without re-sorting them here.
    let mut slices: BTreeMap<SliceKey, Vec<&Finding>> = BTreeMap::new();
    for finding in report
        .findings
        .iter()
        .filter(|f| owned.contains(f.id.as_str()))
    {
        let project = finding
            .project_id
            .as_ref()
            .map_or("", |id| id.0.as_str())
            .to_string();
        let ecosystem = match definition.scope {
            Scope::ProjectEcosystem => finding
                .package
                .as_ref()
                .map_or(String::new(), |package| package.ecosystem.clone()),
            _ => String::new(),
        };
        let rank = ranks.get(project.as_str()).copied().unwrap_or(usize::MAX);
        slices
            .entry((rank, project, ecosystem))
            .or_default()
            .push(finding);
    }
    if slices.is_empty() {
        return whole();
    }

    // The project only earns room in the title when it tells two rows apart.
    // On the common one-project scan it is the same word on every row, which
    // is exactly the noise that pushes the ecosystem out of a narrow column.
    let projects = slices
        .keys()
        .map(|(_, project, _)| project.as_str())
        .collect::<BTreeSet<_>>();
    let labels = if projects.len() > 1 {
        project_labels(report, &projects)
    } else {
        BTreeMap::new()
    };

    // Evidence the control did not derive from one of its findings describes
    // the scan as a whole (an advisory source that did not answer, say), so it
    // belongs to every slice. Dropping it would let a slice read as a complete
    // account of its ecosystem when the scan knows it is not.
    let from_finding = slices
        .values()
        .flatten()
        .map(|finding| evidence_key(&control::finding_evidence(finding)))
        .collect::<HashSet<_>>();
    let context = control
        .evidence
        .iter()
        .filter(|row| !from_finding.contains(&evidence_key(row)))
        .cloned()
        .collect::<Vec<_>>();

    slices
        .into_iter()
        .map(|((_, project, ecosystem), findings)| {
            let mut evidence = context.clone();
            evidence.extend(
                findings
                    .iter()
                    .map(|finding| control::finding_evidence(finding)),
            );
            control::dedup_evidence(&mut evidence);
            Row {
                id: instance_id(&definition.id, &project, &ecosystem),
                title: instance_title(
                    &definition.title,
                    labels.get(project.as_str()).map(String::as_str),
                    &ecosystem,
                ),
                evidence,
                slice_severity: findings.iter().map(|finding| finding.severity).max(),
                finding_ids: {
                    let mut ids = Vec::new();
                    let mut seen = HashSet::new();
                    for finding in &findings {
                        if seen.insert(finding.id.as_str()) {
                            ids.push(finding.id.clone());
                        }
                    }
                    ids
                },
            }
        })
        .collect()
}

/// The title one instance carries.
///
/// The part that tells the rows apart leads, because the list column truncates
/// from the right and is as narrow as 32 columns in the terminal: four rows
/// that first differ past that are the same unreadable row four times.
fn instance_title(item: &str, project: Option<&str>, ecosystem: &str) -> String {
    match (project, ecosystem) {
        (None, "") => item.to_string(),
        (None, ecosystem) => format!("{ecosystem}: {item}"),
        (Some(project), "") => format!("{project}: {item}"),
        (Some(project), ecosystem) => format!("{ecosystem} in {project}: {item}"),
    }
}

/// Display labels for the projects a split item landed in, distinct from each
/// other: two projects can carry one name, and two rows that read the same is
/// the failure the split exists to remove, so a repeated name grows its parent
/// directory.
fn project_labels(report: &ScanReport, wanted: &BTreeSet<&str>) -> BTreeMap<String, String> {
    let projects = report
        .projects
        .iter()
        .filter(|project| wanted.contains(project.id.0.as_str()))
        .collect::<Vec<_>>();
    let mut repeats: BTreeMap<&str, usize> = BTreeMap::new();
    for project in &projects {
        *repeats.entry(project.name.as_str()).or_default() += 1;
    }
    projects
        .iter()
        .map(|project| {
            let label = match repeats.get(project.name.as_str()) {
                Some(1) => project.name.clone(),
                _ => project
                    .root
                    .parent()
                    .and_then(|parent| parent.file_name())
                    .map_or_else(
                        || project.name.clone(),
                        |parent| format!("{}/{}", parent.to_string_lossy(), project.name),
                    ),
            };
            (project.id.0.clone(), label)
        })
        .collect()
}

pub fn apply(id: &str, action: GuideAction, reason: Option<String>) -> anyhow::Result<UserState> {
    let mut state = load_state();
    let now = Utc::now().to_rfc3339();
    match action {
        GuideAction::Read => {
            state.tasks.entry(id.to_string()).or_default().read_at = Some(now);
        }
        GuideAction::Complete | GuideAction::Dismiss => {
            let task = state.tasks.entry(id.to_string()).or_default();
            task.read_at.get_or_insert_with(|| now.clone());
            task.decision = Some(if action == GuideAction::Complete {
                Decision::Completed
            } else {
                Decision::Dismissed
            });
            task.reason = reason;
            task.decided_at = Some(now);
        }
        GuideAction::Clear => {
            state.tasks.remove(id);
        }
    }
    save_state(&state)?;
    Ok(state)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuideStatus {
    ActionNeeded,
    Recommended,
    Verified,
    Completed,
    Dismissed,
    Unknown,
}

/// Which list slice a task belongs to. The three variants partition the
/// catalog exactly once, so every tab count, category count, and progress
/// number on every surface is derived from the same split and they can never
/// disagree. A task husk verified is `Done` immediately: there is nothing for
/// the user to do, and a count that depends on whether they scrolled past the
/// row measures the reader instead of the machine.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Bucket {
    Todo,
    Done,
    Ignored,
}

/// Where a task sits in the priority view.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// Something husk observed is wrong or half-configured.
    Next,
    /// Advice with no failing evidence behind it.
    Later,
    Done,
    Ignored,
}

/// The priority view's sections, in display order, with the heading every
/// surface prints. The web Guide mirrors these strings in `TIER_META`
/// (`web/src/features/guide/Guide.tsx`); change both together.
pub const TIERS: &[(Tier, &str)] = &[
    (Tier::Next, "Do next: highest impact"),
    (Tier::Later, "When you get to it"),
    // "Handled", not "Done": most of these are things husk verified, which the
    // user never did anything about.
    (Tier::Done, "Handled"),
    (Tier::Ignored, "Ignored"),
];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssessedTask {
    pub id: String,
    pub category: String,
    pub kind: GuideKind,
    pub verification: Verification,
    /// Which report verifies this task: the machine posture or a project scan.
    pub scope: Scope,
    pub severity: Severity,
    pub title: String,
    pub why: String,
    pub problem: String,
    pub estimate: String,
    pub steps: Vec<Step>,
    pub options: Vec<Opt>,
    pub sources: Vec<Source>,
    pub solution: Solution,
    pub status: GuideStatus,
    /// `None` for `verification = "manual"` guides: husk performed no check, so
    /// it reports no verification rather than an invented one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_status: Option<ControlStatus>,
    pub read: bool,
    pub handled: bool,
    pub priority: i64,
    pub bucket: Bucket,
    pub tier: Tier,
    pub effort: String,
    pub evidence: Vec<Evidence>,
    pub finding_ids: Vec<String>,
    pub remediation_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GuideCategory {
    pub id: String,
    pub title: String,
    pub items: Vec<AssessedTask>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GuideReport {
    pub generated_at: String,
    pub categories: Vec<GuideCategory>,
    pub total: usize,
    /// The three buckets partition `total`; every surface counts from these.
    pub todo: usize,
    pub done: usize,
    pub ignored: usize,
    /// Read and then resolved, `done + ignored`. This is review progress, not
    /// a security score: a task counts once the user has looked at it and it
    /// is either verified, marked done, or ignored.
    pub handled: usize,
    /// `handled` as a percentage of `total`, floored. The one place any
    /// surface may take this number from, so no two of them round differently.
    pub percent: u8,
    /// Tasks a control observed as passing, whether or not the user read them.
    pub verified: usize,
    pub completed: usize,
}

/// `machine` is the newest machine-posture report, when one exists: machine-
/// scoped items verify against it, project-scoped items against `report`.
/// Without one, machine-scoped items read `report` — whatever that scan knew.
pub fn assess(report: &ScanReport, machine: Option<&ScanReport>, state: &UserState) -> GuideReport {
    let mut categories: BTreeMap<String, Vec<AssessedTask>> = BTreeMap::new();
    for definition in catalog() {
        let scoped: &ScanReport = if definition.scope == Scope::Machine {
            machine.unwrap_or(report)
        } else {
            report
        };
        // A manual guide has no control, so it gets no control status: husk
        // must not display a verification it never performed.
        let control = definition.control.as_ref().map(|id| {
            scoped
                .controls
                .iter()
                .find(|assessment| assessment.control_id == *id)
                .cloned()
                .unwrap_or_else(|| ControlAssessment {
                    control_id: id.clone(),
                    status: ControlStatus::Unknown,
                    evidence: Vec::new(),
                    finding_ids: Vec::new(),
                })
        });
        let control_status = control.as_ref().map(|control| control.status);
        for row in rows(definition, control.as_ref(), scoped) {
            let user = state.tasks.get(&row.id);
            let read = user.and_then(|task| task.read_at.as_ref()).is_some();
            let decision = user.and_then(|task| task.decision);
            // Two things resolve a task, and neither is "the row was on
            // screen": husk verified it, or the user decided about it. A read
            // must never count: the web marks a row read when it renders, so
            // any read-based rule measures scrolling.
            let handled = control_status == Some(ControlStatus::Passed)
                || matches!(decision, Some(Decision::Completed | Decision::Dismissed));
            let status = match decision {
                Some(Decision::Dismissed) => GuideStatus::Dismissed,
                Some(Decision::Completed) => GuideStatus::Completed,
                None if control_status == Some(ControlStatus::Passed) => GuideStatus::Verified,
                None if matches!(
                    control_status,
                    Some(ControlStatus::Failed | ControlStatus::Partial)
                ) =>
                {
                    GuideStatus::ActionNeeded
                }
                // Manual guides are always advice awaiting the user's own decision.
                None if definition.verification == Verification::Manual => GuideStatus::Recommended,
                None if definition.kind == GuideKind::Recommendation => GuideStatus::Recommended,
                None => GuideStatus::Unknown,
            };
            // A slice is ranked by what it holds, not by the worst thing the
            // whole item found: that is the point of splitting it.
            let severity = definition.severity.max(match row.slice_severity {
                Some(severity) => severity,
                None => related_severity(definition, scoped),
            });
            let remediation = definition
                .control
                .as_deref()
                .map(|control| {
                    related_remediations(
                        control,
                        scoped,
                        row.slice_severity.map(|_| row.finding_ids.as_slice()),
                    )
                })
                .unwrap_or_default();
            let priority = priority(
                status,
                control_status,
                severity,
                definition.kind,
                remediation.fixable,
            );
            // One split, three outcomes, no overlap: ignoring is the user's own
            // act and wins, then review progress, then everything still to look at.
            let bucket = if decision == Some(Decision::Dismissed) {
                Bucket::Ignored
            } else if handled {
                Bucket::Done
            } else {
                Bucket::Todo
            };
            let tier = match bucket {
                Bucket::Ignored => Tier::Ignored,
                Bucket::Done => Tier::Done,
                Bucket::Todo
                    if matches!(
                        control_status,
                        Some(ControlStatus::Failed | ControlStatus::Partial)
                    ) =>
                {
                    Tier::Next
                }
                Bucket::Todo => Tier::Later,
            };
            let task = AssessedTask {
                id: row.id,
                category: definition.category.clone(),
                kind: definition.kind,
                verification: definition.verification,
                scope: definition.scope,
                severity,
                title: row.title,
                why: definition.why.clone(),
                problem: definition.problem.clone(),
                estimate: definition.estimate.clone(),
                steps: definition.steps.clone(),
                options: definition.options.clone(),
                sources: definition.sources.clone(),
                solution: definition.solution.clone(),
                status,
                control_status,
                read,
                handled,
                priority,
                bucket,
                tier,
                effort: effort_bucket(&definition.estimate).to_string(),
                evidence: row.evidence,
                finding_ids: row.finding_ids,
                remediation_ids: remediation.ids,
                decision,
                reason: user.and_then(|task| task.reason.clone()),
            };
            categories
                .entry(definition.category.clone())
                .or_default()
                .push(task);
        }
    }

    let mut categories = categories
        .into_iter()
        .map(|(title, mut items)| {
            items.sort_by_key(|item| std::cmp::Reverse(item.priority));
            GuideCategory {
                id: slug(&title),
                title,
                items,
            }
        })
        .collect::<Vec<_>>();
    categories.sort_by_key(|category| category_rank(&category.title));

    let all = categories
        .iter()
        .flat_map(|category| &category.items)
        .collect::<Vec<_>>();
    let count = |bucket: Bucket| all.iter().filter(|task| task.bucket == bucket).count();
    let total = all.len();
    let (todo, done, ignored) = (
        count(Bucket::Todo),
        count(Bucket::Done),
        count(Bucket::Ignored),
    );
    let handled = done + ignored;
    let status_count = |want: GuideStatus| all.iter().filter(|task| task.status == want).count();
    let (verified, completed) = (
        status_count(GuideStatus::Verified),
        status_count(GuideStatus::Completed),
    );
    GuideReport {
        generated_at: report.generated_at.to_rfc3339(),
        categories,
        total,
        todo,
        done,
        ignored,
        handled,
        percent: (handled * 100).checked_div(total).unwrap_or(100) as u8,
        verified,
        completed,
    }
}

fn related_severity(definition: &GuideDefinition, report: &ScanReport) -> Severity {
    let rules = definition
        .related_rules
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    report
        .findings
        .iter()
        .filter(|finding| {
            finding
                .rule_id
                .as_ref()
                .is_some_and(|id| rules.contains(id.as_str()))
        })
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::Info)
}

/// The remediation husk planned for one control: the proposal ids to render,
/// and whether any of them is something husk will actually run.
#[derive(Default)]
struct Remediation {
    ids: Vec<String>,
    /// True when at least one proposal is `AutoSafe` or `Confirm`. A `Manual`
    /// proposal is a checklist husk prints, not a fix it applies, so it must
    /// not earn the fixability bonus in [`priority`].
    fixable: bool,
}

/// The control's proposals, narrowed to `findings` when the caller is one slice
/// of a split item: a slice that offered another slice's upgrade would run a
/// fix in a project its own row does not name.
fn related_remediations(
    control: &str,
    report: &ScanReport,
    findings: Option<&[String]>,
) -> Remediation {
    let owned = findings.map(|ids| ids.iter().map(String::as_str).collect::<HashSet<_>>());
    let proposals = report
        .remediations
        .iter()
        .filter(|proposal| proposal.control_id == control)
        .filter(|proposal| {
            owned.as_ref().is_none_or(|owned| {
                proposal
                    .finding_ids
                    .iter()
                    .any(|id| owned.contains(id.as_str()))
            })
        })
        .collect::<Vec<_>>();
    Remediation {
        fixable: proposals.iter().any(|proposal| {
            matches!(
                proposal.class,
                ExecutionClass::AutoSafe | ExecutionClass::Confirm
            )
        }),
        ids: proposals
            .iter()
            .map(|proposal| proposal.id.clone())
            .collect(),
    }
}

/// Where a task sits in the to-do order, as one number so every surface sorts
/// identically.
///
/// The terms are deliberately separated by an order of magnitude each, so a
/// weaker term can only ever break a tie inside the band above it. Evidence
/// that husk actually observed a problem dominates; severity orders within
/// that; kind and fixability settle the rest. A one-click fix therefore rises
/// to the top of its band, which is the point of showing fixes inside the
/// to-do list rather than in a view of their own, but a critical finding
/// nobody can auto-fix still outranks a trivial one husk can.
fn priority(
    status: GuideStatus,
    control: Option<ControlStatus>,
    severity: Severity,
    kind: GuideKind,
    fixable: bool,
) -> i64 {
    if matches!(status, GuideStatus::Completed | GuideStatus::Dismissed) {
        return 0;
    }
    let severity = match severity {
        Severity::Critical => 500,
        Severity::High => 400,
        Severity::Medium => 300,
        Severity::Low => 200,
        Severity::Info => 100,
    };
    let evidence = match control {
        Some(ControlStatus::Failed) => 30_000,
        Some(ControlStatus::Partial) => 20_000,
        Some(ControlStatus::Unknown) => 10_000,
        // Manual guides carry no evidence either way; rank them like an
        // unresolved check so they stay visible without outranking one.
        None => 10_000,
        Some(ControlStatus::Passed) => 1_000,
        Some(ControlStatus::NotApplicable) => 0,
    };
    evidence
        + severity
        + if kind == GuideKind::Baseline { 50 } else { 0 }
        + if fixable { 25 } else { 0 }
}

fn effort_bucket(estimate: &str) -> &'static str {
    let number = estimate
        .split(|ch: char| !ch.is_ascii_digit())
        .find_map(|part| part.parse::<u32>().ok())
        .unwrap_or(30);
    if estimate.contains("hour") || number > 60 {
        "project"
    } else if number <= 15 {
        "quick"
    } else {
        "medium"
    }
}

/// Category display order, highest-impact first. The order is the incident
/// evidence: dependency resolution and credentials at rest appear in more real
/// developer-machine compromises than anything below them, and account posture
/// husk cannot even observe sits last.
/// `every_category_has_an_explicit_rank` keeps this in sync with `guides/*.md`
/// so a new category can never silently sort last.
const CATEGORY_ORDER: &[&str] = &[
    "Dependencies",
    "Secrets & credentials",
    "AI agents & MCP",
    "Editor & IDE",
    "CI/CD & release",
    "Source control",
    "Local environment",
    "Machine & identity",
    "Using Husk",
];

fn category_rank(category: &str) -> usize {
    CATEGORY_ORDER
        .iter()
        .position(|candidate| *candidate == category)
        .unwrap_or(usize::MAX)
}

fn slug(title: &str) -> String {
    title
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PackageRef, Project, ProjectId, ProjectKind};

    /// The item every split test uses: a real scoped catalog entry, so the
    /// tests exercise shipped frontmatter rather than a fixture scope no
    /// guide declares.
    const SPLIT_ITEM: &str = "dependency-security";

    fn fixture_project(root: &str, name: &str) -> Project {
        let root = PathBuf::from(root);
        Project {
            id: ProjectId::from_root(&root),
            root,
            name: name.to_string(),
            kind: ProjectKind::GitRepo,
            submodule_of: None,
            git: None,
            last_modified: None,
            activity: crate::model::Activity::Active,
            ecosystems: Vec::new(),
            package_count: 0,
            rollup: crate::model::ProjectRollup::default(),
            posture: None,
        }
    }

    fn vulnerability(
        project: &Project,
        ecosystem: &str,
        name: &str,
        severity: Severity,
    ) -> Finding {
        let manifest = project.root.join("manifest");
        let mut finding = Finding::new(
            format!("osv:{name}:{ecosystem}"),
            format!("{name} is vulnerable"),
            severity,
            crate::rule::Category::Vulnerability,
            "OSV.dev",
            Some(manifest.clone()),
            None,
            "",
            None,
            "",
        );
        finding.package = Some(PackageRef {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            manifest_path: manifest,
            line: None,
        });
        finding.project_id = Some(project.id.clone());
        finding
    }

    /// Two projects, four (project, ecosystem) pairs, with the control that
    /// owns them stated directly so the fixture never depends on what the host
    /// machine happens to have installed.
    fn split_report() -> ScanReport {
        let api = fixture_project("/work/api", "api");
        let web = fixture_project("/work/web", "web");
        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        report.findings = vec![
            vulnerability(&api, "npm", "left-pad", Severity::High),
            vulnerability(&api, "npm", "minimist", Severity::Medium),
            vulnerability(&api, "pypi", "requests", Severity::Critical),
            vulnerability(&web, "npm", "lodash", Severity::Low),
            vulnerability(&web, "cargo", "openssl", Severity::High),
        ];
        report.controls = vec![ControlAssessment {
            control_id: SPLIT_ITEM.to_string(),
            status: ControlStatus::Failed,
            evidence: report
                .findings
                .iter()
                .map(control::finding_evidence)
                .collect(),
            finding_ids: report.findings.iter().map(|f| f.id.clone()).collect(),
        }];
        report.projects = vec![api, web];
        report
    }

    fn tasks(guidance: &GuideReport) -> Vec<&AssessedTask> {
        guidance
            .categories
            .iter()
            .flat_map(|category| &category.items)
            .collect()
    }

    fn instances_of<'a>(guidance: &'a GuideReport, item: &str) -> Vec<&'a AssessedTask> {
        tasks(guidance)
            .into_iter()
            .filter(|task| task.id == item || task.id.starts_with(&format!("{item}@")))
            .collect()
    }

    /// A scoped item becomes one task per (project, ecosystem) pair, and each
    /// one owns only what its own subject produced. A row showing another
    /// row's advisories is the failure the split exists to remove.
    #[test]
    fn a_scoped_item_splits_and_no_instance_carries_another_instances_findings() {
        let report = split_report();
        let guidance = assess(&report, None, &UserState::default());
        let instances = instances_of(&guidance, SPLIT_ITEM);
        assert_eq!(instances.len(), 4, "two projects, four ecosystem pairs");

        for instance in &instances {
            let ecosystem = instance.id.rsplit('#').next().expect("an ecosystem");
            let project = instance
                .id
                .trim_start_matches(SPLIT_ITEM)
                .trim_start_matches('@')
                .split('#')
                .next()
                .expect("a project")
                .to_string();
            let own = report
                .findings
                .iter()
                .filter(|finding| {
                    finding
                        .project_id
                        .as_ref()
                        .is_some_and(|id| id.0 == project)
                        && finding
                            .package
                            .as_ref()
                            .is_some_and(|p| p.ecosystem == ecosystem)
                })
                .map(|finding| finding.id.clone())
                .collect::<Vec<_>>();
            assert!(!own.is_empty(), "{} matched no finding", instance.id);
            assert_eq!(
                instance.finding_ids, own,
                "{} owns other findings",
                instance.id
            );
            assert_eq!(
                instance.evidence.len(),
                own.len(),
                "{} shows evidence for findings it does not own",
                instance.id
            );
        }

        // Severity is the slice's own worst, not the whole item's: the point of
        // splitting is that the npm row is not ranked by the pypi row.
        let severity = |suffix: &str| {
            instances
                .iter()
                .find(|task| task.id.ends_with(suffix))
                .map(|task| task.severity)
                .unwrap_or_else(|| panic!("no instance ending {suffix}"))
        };
        assert_eq!(
            severity("#cargo"),
            Severity::Critical,
            "floored at the item's own severity"
        );
    }

    /// Ids are the join between a row and the user's decision about it, so two
    /// assessments of one unchanged report must produce the same ids in the
    /// same order. A rescan that reshuffles them lands done/ignored state on
    /// the wrong row.
    #[test]
    fn instance_ids_and_their_order_survive_a_rescan_of_an_unchanged_tree() {
        let report = split_report();
        let ids = |guidance: &GuideReport| {
            tasks(guidance)
                .into_iter()
                .map(|task| task.id.clone())
                .collect::<Vec<_>>()
        };
        let first = ids(&assess(&report, None, &UserState::default()));
        let second = ids(&assess(&split_report(), None, &UserState::default()));
        assert_eq!(first, second, "assessment order is not deterministic");

        let mut unique = first.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), first.len(), "two tasks share an id");
    }

    /// Each instance holds its own review state. Marking the npm work done
    /// must not tick off the Python work.
    #[test]
    fn each_instance_holds_its_own_decision() {
        let report = split_report();
        let ids = instances_of(&assess(&report, None, &UserState::default()), SPLIT_ITEM)
            .into_iter()
            .map(|task| task.id.clone())
            .collect::<Vec<_>>();

        let mut state = UserState::default();
        state.tasks.insert(
            ids[0].clone(),
            TaskState {
                read_at: Some("now".to_string()),
                decision: Some(Decision::Completed),
                ..TaskState::default()
            },
        );
        let guidance = assess(&report, None, &state);
        for instance in instances_of(&guidance, SPLIT_ITEM) {
            let expected = if instance.id == ids[0] {
                Bucket::Done
            } else {
                Bucket::Todo
            };
            assert_eq!(
                instance.bucket, expected,
                "{} moved with its sibling",
                instance.id
            );
        }
    }

    /// State written under the pre-split id names the whole item, which no
    /// longer exists once the item splits. It must not be inherited by one of
    /// the instances, which would silently mark one project's work done.
    #[test]
    fn state_under_the_unsplit_id_never_attaches_to_an_instance() {
        let report = split_report();
        let mut state = UserState::default();
        state.tasks.insert(
            SPLIT_ITEM.to_string(),
            TaskState {
                read_at: Some("now".to_string()),
                decision: Some(Decision::Completed),
                ..TaskState::default()
            },
        );
        let guidance = assess(&report, None, &state);
        for instance in instances_of(&guidance, SPLIT_ITEM) {
            assert_eq!(
                instance.bucket,
                Bucket::Todo,
                "{} inherited the pre-split decision",
                instance.id
            );
        }
    }

    /// The instances are told apart inside the narrowest column that shows
    /// them: 32 characters in the terminal.
    #[test]
    fn instance_titles_differ_inside_the_narrowest_list_column() {
        const NARROWEST: usize = 32;
        let guidance = assess(&split_report(), None, &UserState::default());
        let heads = instances_of(&guidance, SPLIT_ITEM)
            .into_iter()
            .map(|task| crate::term::truncate_end(&task.title, NARROWEST))
            .collect::<Vec<_>>();
        let mut unique = heads.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            heads.len(),
            "instances read the same once truncated: {heads:?}"
        );
    }

    /// An item with a subject scope but nothing found stays one row, so the
    /// catalog keeps its shape on a clean machine instead of vanishing.
    #[test]
    fn a_scoped_item_with_no_findings_stays_a_single_task() {
        let report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let guidance = assess(&report, None, &UserState::default());
        assert_eq!(guidance.total, catalog().len());
        let instances = instances_of(&guidance, SPLIT_ITEM);
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].id, SPLIT_ITEM);
    }

    /// The catalog declares a scope deliberately; splitting everything would
    /// bury the list in the noise the split exists to remove.
    #[test]
    fn scoping_stays_a_small_deliberate_exception() {
        let scoped = catalog()
            .iter()
            .filter(|guide| guide.scope != Scope::Machine)
            .count();
        assert!(
            scoped <= 5,
            "{scoped} scoped items. An item is only worth splitting when the \
             pieces are work a reader would do at separate times; everything \
             else multiplies the list into noise."
        );
        for guide in catalog() {
            assert!(
                guide.scope == Scope::Machine || guide.verification == Verification::Automatic,
                "guide `{}` is scoped but manual, so it has no findings to split along",
                guide.id
            );
        }
    }

    #[test]
    fn instance_ids_are_accepted_only_for_items_that_can_split() {
        assert!(is_known_task(SPLIT_ITEM));
        assert!(is_known_task(&format!(
            "{SPLIT_ITEM}@proj_0123456789abcdef#npm"
        )));
        assert!(is_known_task(&format!(
            "{SPLIT_ITEM}@proj_0123456789abcdef"
        )));
        assert!(!is_known_task("full-disk-encryption@proj_0123456789abcdef"));
        assert!(!is_known_task("not-a-guide"));
        assert!(!is_known_task("not-a-guide@proj_0123456789abcdef#npm"));
    }

    /// Splitting changes every number on the page, so the partition has to
    /// still hold over the split list rather than over the catalog.
    #[test]
    fn buckets_partition_the_split_list() {
        let report = split_report();
        let guidance = assess(&report, None, &UserState::default());
        assert!(guidance.total > catalog().len(), "the item did not split");
        assert_eq!(
            guidance.todo + guidance.done + guidance.ignored,
            guidance.total
        );
        assert_eq!(
            guidance
                .categories
                .iter()
                .map(|category| category.items.len())
                .sum::<usize>(),
            guidance.total
        );
    }

    #[test]
    fn markdown_catalog_and_control_registry_match() {
        let controls = control::registry()
            .iter()
            .map(|control| control.id)
            .collect::<HashSet<_>>();
        assert_eq!(controls.len(), control::registry().len());
        let automatic = catalog()
            .iter()
            .filter(|guide| guide.verification == Verification::Automatic)
            .count();
        assert_eq!(
            automatic,
            controls.len(),
            "every control-backed guide needs exactly one registered control"
        );
        for guide in catalog() {
            assert!(!guide.steps.is_empty(), "{} has no steps", guide.id);
            match (guide.verification, guide.control.as_deref()) {
                (Verification::Automatic, Some(control)) => assert!(
                    controls.contains(control),
                    "guide `{}` names unregistered control `{control}`",
                    guide.id
                ),
                (Verification::Manual, None) => {}
                (Verification::Automatic, None) => {
                    panic!("guide `{}` is automatic but has no control", guide.id)
                }
                (Verification::Manual, Some(control)) => panic!(
                    "guide `{}` is manual but still names control `{control}`; \
                     husk cannot check it, so it must not claim a control",
                    guide.id
                ),
            }
        }
    }

    #[test]
    fn manual_guides_report_no_verification_and_resolve_only_by_decision() {
        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        report.controls = control::run(&report).0;

        let manual = catalog()
            .iter()
            .filter(|guide| guide.verification == Verification::Manual)
            .map(|guide| guide.id.clone())
            .collect::<Vec<_>>();
        assert!(!manual.is_empty(), "the catalog should keep manual guides");

        let guidance = assess(&report, None, &UserState::default());
        let tasks = guidance
            .categories
            .iter()
            .flat_map(|category| &category.items)
            .collect::<Vec<_>>();

        for id in &manual {
            let task = tasks
                .iter()
                .find(|task| task.id == *id)
                .unwrap_or_else(|| panic!("assessed {id}"));
            assert_eq!(
                task.control_status, None,
                "{id} is manual, so husk must report no verification"
            );
            assert_eq!(
                task.status,
                GuideStatus::Recommended,
                "{id} is manual, so it is advice until the user decides"
            );
            assert!(task.evidence.is_empty(), "{id} has no control evidence");
        }

        // The only way a manual guide resolves is the user's own decision.
        let id = &manual[0];
        let mut state = UserState::default();
        state.tasks.insert(
            id.clone(),
            TaskState {
                read_at: Some("now".to_string()),
                decision: Some(Decision::Completed),
                ..TaskState::default()
            },
        );
        let after = assess(&report, None, &state);
        let task = after
            .categories
            .iter()
            .flat_map(|category| &category.items)
            .find(|task| task.id == *id)
            .expect("assessed manual task");
        assert_eq!(task.status, GuideStatus::Completed);
        assert!(task.handled);
    }

    /// Controls whose verdict depends on machine state no fixture can stage:
    /// the root filesystem's encryption, the system sshd config, the ambient
    /// `PATH`, and the installed git. Each may legitimately answer `Unknown` on
    /// a host that cannot be asked. Everything else must decide.
    const SYSTEM_SCOPED_CONTROLS: &[&str] = &[
        "full-disk-encryption",
        "sshd-exposure",
        "path-hygiene",
        "git-client-version",
    ];

    /// Controls the file fixtures cannot reach, because their surface is a scan
    /// result rather than a file: they roll up findings, or they read
    /// `report.packages`, and both are produced by a real walk. Their own
    /// modules test them against synthetic findings.
    ///
    /// Kept as an exact list, asserted in both directions, rather than a skip.
    /// A control added without a fixture lands here and fails the test, and a
    /// name that starts being exercised has to be removed. Either way the
    /// author has to look.
    const FINDING_SCOPED_CONTROLS: &[&str] = &[
        "container-image-pinning",
        "dependency-security",
        "docker-socket-exposure",
        "dockerignore-coverage",
        "lifecycle-scripts",
        "malicious-packages",
        "mcp-safety",
        "release-provenance",
    ];

    /// A control that cannot reach a verdict is not a control: run every
    /// control against a home holding the surfaces it probes, and require a
    /// decision.
    #[test]
    fn controls_decide_rather_than_answering_unknown_when_their_surface_exists() {
        let home = tempfile::tempdir().expect("fixture home");
        let project = tempfile::tempdir().expect("fixture project");
        stage_probe_surfaces(home.path());
        stage_project_surfaces(project.path());
        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        report.context.home_dir = Some(home.path().to_path_buf());
        report.roots = vec![project.path().to_path_buf()];

        let mut untouched = Vec::new();
        for assessment in control::run(&report).0 {
            if SYSTEM_SCOPED_CONTROLS.contains(&assessment.control_id.as_str()) {
                continue;
            }
            assert_ne!(
                assessment.status,
                ControlStatus::Unknown,
                "control `{}` answered Unknown against a home holding the files it \
                 reads. `Unknown` means husk could not read the artifact, never that \
                 the probe is unwritten: implement the verdict, or report \
                 NotApplicable when the surface is genuinely absent.",
                assessment.control_id
            );
            if assessment.status == ControlStatus::NotApplicable {
                untouched.push(assessment.control_id);
            }
        }

        // A control the fixture never reaches is a control this test does not
        // check, so the fixture has to be kept honest from both directions: no
        // new control may sit outside it silently, and no name may linger here
        // after its artifact starts being staged.
        untouched.sort();
        let expected = FINDING_SCOPED_CONTROLS
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            untouched, expected,
            "the set of controls the fixture home does not exercise changed. Stage \
             the artifact in `stage_probe_surfaces` so the control is actually \
             tested, or add it to FINDING_SCOPED_CONTROLS with the reason it cannot \
             be staged from files alone."
        );
    }

    /// A project root holding one instance of every repository artifact the
    /// repo-scoped controls read. Content is deliberately minimal and mostly
    /// inert: the point is that each control finds its surface and commits to a
    /// verdict, not which verdict it reaches.
    fn stage_project_surfaces(root: &std::path::Path) {
        for (relative, contents) in [
            ("package.json", "{\"scripts\":{\"ci\":\"npm ci\"}}\n"),
            ("package-lock.json", "{}\n"),
            (".npmrc", "ignore-scripts=true\n"),
            (".git/config", "[core]\n\tbare = false\n"),
            (
                ".github/workflows/ci.yml",
                "on: push\npermissions:\n  contents: read\njobs: {}\n",
            ),
            (".github/dependabot.yml", "version: 2\n"),
            (".husk/policy.toml", "[ci]\n"),
            (".pre-commit-config.yaml", "repos: []\n"),
            ("Dockerfile", "FROM debian@sha256:0\nUSER app\n"),
            (".dockerignore", ".env*\n.git\n*.pem\n*.key\n"),
            ("docker-compose.yml", "services: {}\n"),
            (
                ".vscode/tasks.json",
                "{\"version\":\"2.0.0\",\"tasks\":[]}\n",
            ),
            (
                ".devcontainer/devcontainer.json",
                "{\"name\":\"fixture\"}\n",
            ),
            (".envrc", "export FIXTURE=1\n"),
        ] {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("fixture dir");
            std::fs::write(&path, contents).expect("fixture file");
        }
    }

    /// A home directory containing a well-formed instance of every artifact the
    /// home-scoped controls read, so "the surface exists" is true for all of
    /// them at once.
    fn stage_probe_surfaces(home: &std::path::Path) {
        // A key file has to be a real key, not an empty placeholder: husk
        // cannot classify a file it cannot decode, and answering Unknown there
        // is correct. Only the header matters to the passphrase probe, so this
        // is the armor plus the magic and an unencrypted `ciphername`.
        let key_dir = home.join(".ssh");
        std::fs::create_dir_all(&key_dir).expect("fixture dir");
        std::fs::write(
            key_dir.join("id_ed25519"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\n\
             b3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n\
             -----END OPENSSH PRIVATE KEY-----\n",
        )
        .expect("fixture key");
        std::fs::write(
            key_dir.join("id_ed25519.pub"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture user@host\n",
        )
        .expect("fixture public key");

        for relative in [
            ".ssh/config",
            ".npmrc",
            ".netrc",
            ".pypirc",
            ".gitconfig",
            ".git-credentials",
            ".aws/credentials",
            ".aws/config",
            ".kube/config",
            ".docker/config.json",
            ".cargo/credentials.toml",
            ".gem/credentials",
            ".claude/settings.json",
            ".claude/.credentials.json",
            ".claude/skills/demo/SKILL.md",
            ".codex/config.toml",
            ".config/gh/hosts.yml",
            ".config/pip/pip.conf",
            ".config/go/env",
            ".config/Code/User/settings.json",
            ".bashrc",
            ".zshrc",
        ] {
            let path = home.join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("fixture dir");
            // `{}` parses as both empty JSON and an empty TOML table, and reads
            // as an inert single line to every line-oriented probe.
            std::fs::write(&path, "{}\n").expect("fixture file");
        }
    }

    #[test]
    fn every_category_has_an_explicit_rank() {
        for guide in catalog() {
            assert!(
                CATEGORY_ORDER.contains(&guide.category.as_str()),
                "guide `{}` uses category `{}`, which is missing from CATEGORY_ORDER. \
                 Unranked categories sort last, which silently buries them in the \
                 TUI and web Guide. Add it in the right place.",
                guide.id,
                guide.category
            );
        }
        for category in CATEGORY_ORDER {
            assert!(
                catalog().iter().any(|guide| guide.category == *category),
                "CATEGORY_ORDER lists `{category}`, which no guide uses"
            );
        }
    }

    #[test]
    fn account_and_device_baselines_sort_above_the_rest() {
        let report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let titles = assess(&report, None, &UserState::default())
            .categories
            .into_iter()
            .map(|category| category.title)
            .collect::<Vec<_>>();
        assert_eq!(titles, CATEGORY_ORDER);
    }

    /// Every guide item is either something husk observes locally or something
    /// that remediates what husk found. Manual items are the deliberate
    /// exception and must stay countable on one hand.
    #[test]
    fn manual_guides_stay_a_small_deliberate_exception() {
        let manual = catalog()
            .iter()
            .filter(|guide| guide.verification == Verification::Manual)
            .count();
        assert!(
            manual <= 3,
            "{manual} manual guides. An item husk cannot observe is advice, not \
             a control; keep only the ones whose absence causes the incidents \
             the rest of the catalog mitigates."
        );
    }

    /// A fix husk can apply is the cheapest thing in the list, so it rises to
    /// the top of its band. It must not climb out of that band: fixability is
    /// how a tie is broken, not a reason to show a trivial problem before a
    /// serious one.
    #[test]
    fn a_ready_fix_outranks_an_equal_task_without_one_but_never_beats_severity() {
        let ranked = |severity, fixable| {
            priority(
                GuideStatus::ActionNeeded,
                Some(ControlStatus::Failed),
                severity,
                GuideKind::Baseline,
                fixable,
            )
        };

        assert!(
            ranked(Severity::Medium, true) > ranked(Severity::Medium, false),
            "equal on every other axis, the fixable task sorts first"
        );
        assert!(
            ranked(Severity::Critical, false) > ranked(Severity::Medium, true),
            "a critical task nobody can auto-fix still outranks a fixable medium one"
        );
        assert!(
            priority(
                GuideStatus::ActionNeeded,
                Some(ControlStatus::Failed),
                Severity::Info,
                GuideKind::Recommendation,
                true,
            ) < ranked(Severity::Info, false),
            "evidence and kind outrank fixability too"
        );
    }

    /// The bonus is only worth anything if `assess` actually passes it through,
    /// so prove it end to end on the real catalog rather than on `priority`
    /// alone.
    #[test]
    fn assess_lifts_the_task_whose_control_has_a_fix_ready() {
        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let pair = catalog()
            .iter()
            .filter(|guide| guide.control.is_some())
            .find_map(|first| {
                catalog()
                    .iter()
                    .find(|second| {
                        second.control.is_some()
                            && second.id != first.id
                            && second.severity == first.severity
                            && second.kind == first.kind
                            && second.category == first.category
                    })
                    .map(|second| (first, second))
            })
            .expect("two catalog guides alike on severity, kind, and category");

        report.controls = catalog()
            .iter()
            .filter_map(|guide| guide.control.clone())
            .map(|control_id| ControlAssessment {
                control_id,
                status: ControlStatus::Failed,
                evidence: Vec::new(),
                finding_ids: Vec::new(),
            })
            .collect();
        report.remediations = vec![crate::remediation::RemediationProposal {
            id: "fix:test".to_string(),
            control_id: pair.0.control.clone().expect("control"),
            finding_ids: Vec::new(),
            title: "Test fix".to_string(),
            severity: pair.0.severity,
            class: ExecutionClass::AutoSafe,
            reason: "test".to_string(),
            action: crate::remediation::RemediationOperation::GitignoreAppend {
                secret_path: PathBuf::from(".env"),
            },
            // A one-click fix: a real recipe, nothing blocking it, so ranking
            // sees the case it is meant to lift.
            recipe: crate::remediation::op::Recipe::manual(
                PathBuf::from("."),
                crate::remediation::op::Explain::new("Test fix"),
                Vec::new(),
            ),
            preview: None,
            blockers: Vec::new(),
            overrides: Vec::new(),
            ready: true,
        }];

        let guidance = assess(&report, None, &UserState::default());
        let rank = |id: &str| {
            guidance
                .categories
                .iter()
                .flat_map(|category| &category.items)
                .find(|task| task.id == id)
                .map(|task| task.priority)
                .unwrap_or_else(|| panic!("assessed {id}"))
        };
        assert!(
            rank(&pair.0.id) > rank(&pair.1.id),
            "the task with a ready fix must sort above its otherwise identical twin"
        );
    }

    /// The counts every surface shows must come out of one partition, or a tab
    /// bar adds up to less than its own total and tasks hide in no slice at all.
    #[test]
    fn buckets_partition_the_catalog_across_report_and_categories() {
        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        report.controls = control::run(&report).0;
        // A verified task the user has not read, one completed, one dismissed:
        // the three ways a task leaves (or fails to leave) the to-do slice.
        let automatic = catalog()
            .iter()
            .filter(|guide| guide.verification == Verification::Automatic)
            .map(|guide| guide.id.clone())
            .collect::<Vec<_>>();
        for assessment in &mut report.controls {
            assessment.status = ControlStatus::Passed;
        }
        let mut state = UserState::default();
        state.tasks.insert(
            automatic[1].clone(),
            TaskState {
                read_at: Some("now".to_string()),
                decision: Some(Decision::Completed),
                ..TaskState::default()
            },
        );
        state.tasks.insert(
            automatic[2].clone(),
            TaskState {
                read_at: Some("now".to_string()),
                decision: Some(Decision::Dismissed),
                ..TaskState::default()
            },
        );

        let guidance = assess(&report, None, &state);
        assert_eq!(
            guidance.todo + guidance.done + guidance.ignored,
            guidance.total,
            "tab counts must sum to the total"
        );
        assert_eq!(guidance.handled, guidance.done + guidance.ignored);
        assert_eq!(guidance.ignored, 1);
        assert!(guidance.todo > 0, "unread verified tasks stay to-do");

        let items = |bucket: Bucket| {
            guidance
                .categories
                .iter()
                .map(|category| {
                    category
                        .items
                        .iter()
                        .filter(|task| task.bucket == bucket)
                        .count()
                })
                .sum::<usize>()
        };
        assert_eq!(
            guidance
                .categories
                .iter()
                .map(|category| category.items.len())
                .sum::<usize>(),
            guidance.total,
            "category counts must sum to the total"
        );
        assert_eq!(items(Bucket::Todo), guidance.todo);
        assert_eq!(items(Bucket::Done), guidance.done);
        assert_eq!(items(Bucket::Ignored), guidance.ignored);
    }

    /// A passing control resolves its task on its own, and reading one resolves
    /// nothing: the web records a read when it paints a row, so a read-based
    /// rule would make progress a function of scrolling.
    #[test]
    fn verification_resolves_a_task_and_reading_one_never_does() {
        // A control-backed guide: manual ones can never reach Verified by scan.
        let definition = catalog()
            .iter()
            .find(|guide| guide.verification == Verification::Automatic)
            .expect("a control-backed guide");
        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        report.controls = catalog()
            .iter()
            .filter_map(|guide| guide.control.clone())
            .map(|control_id| ControlAssessment {
                control_id,
                status: ControlStatus::Passed,
                evidence: Vec::new(),
                finding_ids: Vec::new(),
            })
            .collect();

        let unread = assess(&report, None, &UserState::default());
        assert!(
            unread.handled > 0,
            "a verified task is handled without the user touching it"
        );

        let mut state = UserState::default();
        state.tasks.insert(
            definition.id.clone(),
            TaskState {
                read_at: Some("now".to_string()),
                ..TaskState::default()
            },
        );
        assert_eq!(
            assess(&report, None, &state).handled,
            unread.handled,
            "reading a task must not move it, or the count measures scrolling"
        );

        // An unverifiable task still needs the user's own act.
        report.controls[0].status = ControlStatus::Unknown;
        let before = assess(&report, None, &state).handled;
        state.tasks.get_mut(&definition.id).unwrap().decision = Some(Decision::Dismissed);
        assert_eq!(
            assess(&report, None, &state).handled,
            before + 1,
            "dismissal handles an unverifiable task"
        );
    }

    /// The whole point of the split between "husk checked it" and "husk could
    /// not check": only the first may resolve a task on its own.
    #[test]
    fn an_unchecked_control_never_resolves_its_task() {
        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        report.controls = vec![ControlAssessment {
            control_id: SPLIT_ITEM.to_string(),
            status: ControlStatus::Unknown,
            evidence: Vec::new(),
            finding_ids: Vec::new(),
        }];
        let guidance = assess(&report, None, &UserState::default());
        let task = tasks(&guidance)
            .into_iter()
            .find(|task| task.id == SPLIT_ITEM)
            .expect("assessed the item");
        assert_eq!(task.bucket, Bucket::Todo);
        assert_eq!(task.status, GuideStatus::Unknown);
    }

    /// Evidence about the scan as a whole, such as an advisory source that did
    /// not answer, has to reach every slice. A slice that dropped it would read
    /// as a complete account of its ecosystem when husk knows it is not.
    #[test]
    fn scan_wide_evidence_reaches_every_slice_of_a_split_item() {
        let mut report = split_report();
        let caveat = "This list may be incomplete: GitHub Advisory Database did not answer";
        report.controls[0]
            .evidence
            .insert(0, crate::guide::control::evidence(caveat, None));

        let guidance = assess(&report, None, &UserState::default());
        let instances = instances_of(&guidance, SPLIT_ITEM);
        assert_eq!(instances.len(), 4);
        for instance in instances {
            assert_eq!(
                instance.evidence.first().map(|row| row.summary.as_str()),
                Some(caveat),
                "{} lost the scan-wide caveat",
                instance.id
            );
        }
    }
}
