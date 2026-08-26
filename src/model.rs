//! The shared report vocabulary: the contract every husk surface renders from.
//!
//! A scan produces a [`ScanReport`] (findings, discovered packages, provider
//! statuses, project posture, benchmarks); while it runs, progress streams
//! through the mutex-shared [`LiveScan`] that the TUI and the localhost web API
//! both read. The CLI renderers, cache, `husk status`/`ci`, the TUI, the web
//! UI, and the MCP tools all consume these same types: when scanner code adds
//! data that users or agents need, it goes here first, then each surface
//! renders it.
//!
//! Most types serialize with serde: the JSON shapes are the `husk ci` output,
//! the cached report on disk, and the `/api/*` payloads, so field changes are
//! wire-format changes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// husk is deliberately conservative: critical/high are reserved for genuinely
/// dangerous findings so users keep trusting the alerts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Numeric weight for ordering: `Critical` = 5 down to `Info` = 1.
    /// `Ord`/`PartialOrd` delegate here, so `Critical > Info`. Prefer direct
    /// comparisons (`a > b`, `sort`, `max`); reach for `rank()` only when an
    /// actual number is needed (score weights).
    pub fn rank(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Info => 1,
        }
    }

    /// The lowercase wire/display name (matches the serde rename).
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    /// Parses an external advisory's severity string (case-insensitive;
    /// accepts GitHub's `moderate` for `medium`). Unknown values degrade to
    /// `Info`, never to a scarier level.
    pub fn from_external(value: &str) -> Self {
        Self::parse_strict(value).unwrap_or(Self::Info)
    }

    /// Strict counterpart of [`Self::from_external`] for user-supplied
    /// filters: `None` on unknown values instead of silently widening to
    /// `Info`.
    pub fn parse_strict(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "moderate" | "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            "info" => Some(Self::Info),
            _ => None,
        }
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One discovered package coordinate plus where it was found.
///
/// Emitted by the `ScanTarget` registry (`scan::targets`). `ecosystem` is the
/// target's stable lowercase id (`"npm"`, `"cargo"`, release-qualified distro
/// ids like `"debian:12"`); `name`/`version` preserve each registry's canonical
/// casing: advisory matching can be case-sensitive (e.g. NuGet in OSV), so
/// targets never normalize case here.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PackageRef {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// The manifest/lockfile (or database) the coordinate was read from.
    pub manifest_path: PathBuf,
    /// Approximate line of the name in `manifest_path`, when locatable.
    pub line: Option<usize>,
}

impl PackageRef {
    /// The dedup/display key: `ecosystem:name@version`.
    pub fn key(&self) -> String {
        format!("{}:{}@{}", self.ecosystem, self.name, self.version)
    }

    /// Maps a Husk ecosystem id to its OSV.dev ecosystem string. `None` means
    /// OSV does not cover this coordinate, so it is inventory-only.
    ///
    /// Distro coordinates are **release-qualified**: OSV's Linux-distro
    /// ecosystems require the release (`Debian:12`, `Ubuntu:22.04`,
    /// `Alpine:v3.19`), never a bare distro name. The distro `ScanTarget`s
    /// encode the release after a colon in the ecosystem id (e.g. `debian:12`
    /// read from `/etc/os-release`); a bare distro id without a detected
    /// release stays inventory-only because a release-less OSV query matches
    /// nothing.
    pub fn osv_ecosystem(&self) -> Option<String> {
        if let Some((base, release)) = self.ecosystem.split_once(':') {
            if release.is_empty() {
                return None;
            }
            let osv_base = match base {
                "debian" => "Debian",
                "ubuntu" => "Ubuntu",
                "alpine" => "Alpine",
                _ => return None,
            };
            return Some(format!("{osv_base}:{release}"));
        }
        let fixed = match self.ecosystem.as_str() {
            "npm" => "npm",
            "pypi" => "PyPI",
            "cargo" => "crates.io",
            "go" => "Go",
            "nuget" => "NuGet",
            "maven" => "Maven",
            "rubygems" => "RubyGems",
            "packagist" => "Packagist",
            "hex" => "Hex",
            "pub" => "Pub",
            "swift" => "SwiftURL",
            "conan" => "ConanCenter",
            "cran" => "CRAN",
            "julia" => "Julia",
            "hackage" => "Hackage",
            "opam" => "opam",
            "github-actions" => "GitHub Actions",
            "clojure" => "Maven",
            // Editor extensions, `publisher.name` case-sensitive. OSV carries
            // both marketplace and Open VSX malware entries under this one
            // ecosystem, so a single mapping covers both registries.
            "vscode-extension" => "VSCode",
            // RPM families inferred from the dist tag. OSV `Red Hat` is a bare
            // ecosystem (the RHEL release lives in the `.elN` of the version);
            // SUSE/openSUSE share the `openSUSE` feed. Fedora has no OSV
            // ecosystem and stays inventory-only via the `rpm`/`fedora` ids.
            "redhat" => "Red Hat",
            "suse" => "openSUSE",
            _ => return None,
        };
        Some(fixed.to_string())
    }

    /// Maps a husk ecosystem id to the GitHub Advisory Database ecosystem
    /// name. `None` means GitHub advisories do not cover this coordinate.
    pub fn github_ecosystem(&self) -> Option<&'static str> {
        match self.ecosystem.as_str() {
            "npm" => Some("npm"),
            "pypi" => Some("pip"),
            "cargo" => Some("rust"),
            "go" => Some("go"),
            "nuget" => Some("nuget"),
            "maven" => Some("maven"),
            "rubygems" => Some("rubygems"),
            "packagist" => Some("composer"),
            "hex" => Some("erlang"),
            "swift" => Some("swift"),
            "clojure" => Some("maven"),
            "pub" => Some("pub"),
            "github-actions" => Some("actions"),
            _ => None,
        }
    }
}

/// One security finding: the unit every surface lists, sorts, and triages.
///
/// `id` is stable across scans (policy suppression and daemon new-vs-seen
/// diffing key on it) and must be unique per rule + subject (path/package),
/// so suppressing one finding never silences another file's.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    /// The finding's rule family. Owned by the rule for catalog detectors;
    /// deserialization is lenient (legacy pre-v3 strings map via
    /// [`crate::rule::Category::parse_lenient`]) so cached reports keep loading.
    #[serde(deserialize_with = "crate::rule::deserialize_category_lenient")]
    pub category: crate::rule::Category,
    /// Which detector/provider produced this (e.g. `"OSV.dev"`,
    /// `"Husk secret scanner"`).
    pub source: String,
    pub path: Option<PathBuf>,
    pub line: Option<usize>,
    pub summary: String,
    /// A short, already-redacted excerpt (never raw secret material).
    pub evidence: Option<String>,
    pub recommendation: String,
    pub references: Vec<String>,
    /// The package coordinate, for advisory/package findings.
    pub package: Option<PackageRef>,
    /// The project this finding belongs to (joins to `ScanReport.projects`;
    /// assigned during finalize by `crate::project::build_projects`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<ProjectId>,
    /// What this finding is *about*: the vulnerable coordinate in one place, or
    /// the rule in one place. Findings sharing a subject are one row on every
    /// surface and one entry in [`CategoryRollup::subjects`], so no surface has
    /// to invent its own grouping rule and disagree about the total. Assigned
    /// by `crate::score::score_report`, which is the only place it is derived.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subject: String,
    /// The rule that defines this finding (the join point to the guide + fix).
    /// Catalog ids for static detectors; namespaced advisory ids
    /// (`osv:…`, `github:…`) for provider findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<crate::rule::RuleId>,
    /// Detector confidence, wired into scoring.
    #[serde(default)]
    pub confidence: crate::rule::Confidence,
    /// Project-aware scoring output (`None` until `score.rs` runs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    /// Exploit-in-the-wild intel for this finding's CVEs (CISA KEV / EPSS),
    /// when known. Drives "fix these first" prioritization. `None` when the
    /// finding has no CVE or no exploit intel was fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit: Option<ExploitInfo>,
    /// The safe version to move `package` to, when the advisory names one
    /// (an upgrade for a vuln, possibly a downgrade for a compromised newer
    /// release). Drives the one-click dependency fix in the web UI / TUI /
    /// `husk fix --deps`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
    /// CVE ids this finding references (normalized upper-case, deduped),
    /// populated at creation from the provider's structured fields. KEV/EPSS
    /// prioritization keys on this (never on prose), with
    /// `crate::prioritize::extract_cves` kept only as a fallback for sources
    /// that carry CVEs in free text.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_cves"
    )]
    pub cves: Vec<String>,
}

/// Exploitation signal for a finding: whether any of its CVEs is on the CISA
/// Known-Exploited-Vulnerabilities list (actively exploited), and the highest
/// EPSS exploit-probability across its CVEs (0.0 to 1.0).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct ExploitInfo {
    pub kev: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        severity: Severity,
        category: crate::rule::Category,
        source: impl Into<String>,
        path: Option<PathBuf>,
        line: Option<usize>,
        summary: impl Into<String>,
        evidence: Option<String>,
        recommendation: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            severity,
            category,
            source: source.into(),
            path,
            line,
            summary: summary.into(),
            evidence,
            recommendation: recommendation.into(),
            references: Vec::new(),
            package: None,
            project_id: None,
            subject: String::new(),
            rule_id: None,
            confidence: crate::rule::Confidence::default(),
            priority: None,
            exploit: None,
            fixed_version: None,
            cves: Vec::new(),
        }
    }

    /// Append the location to the id, turning a detector's rule-and-subject key
    /// into the identifier a user triages.
    ///
    /// A `[[suppress]]` entry in a committed `.husk/policy.toml` matches an id
    /// by exact string, so two findings sharing an id cannot be triaged apart:
    /// suppressing the one you reviewed silences the other for the whole team,
    /// with no warning. Path and line are what separate two matches of the same
    /// rule, so they belong in the id. Applied once, centrally, over the whole
    /// finding set, so no detector can forget it and no detector has to guess
    /// whether its own subject key happens to be unique.
    pub fn locate_id(&mut self) {
        if let Some(path) = &self.path {
            self.id = format!("{}@{}", self.id, path.display());
        }
        if let Some(line) = self.line {
            self.id = format!("{}#{line}", self.id);
        }
    }

    /// Construct a finding from a registered rule: pre-fills the title,
    /// severity, category, and `rule_id` from the catalog. Detector-specific
    /// `summary`/`evidence`/`path`/`line` are set with the chained setters
    /// below, and every caller sets an `.id(…)` naming the rule and the subject
    /// it matched (never the path or line, which [`Finding::locate_id`] adds).
    pub fn from_rule(rule_id: &str) -> Self {
        let id = crate::rule::RuleId::owned(rule_id.to_string());
        let rule = crate::rule::lookup_static(&id);
        let (title, severity, category) = match rule {
            Some(r) => (r.title.to_string(), r.default_severity, r.category),
            None => (
                rule_id.to_string(),
                Severity::Info,
                crate::rule::Category::Other,
            ),
        };
        let mut f = Finding::new(
            rule_id, title, severity, category, rule_id, None, None, "", None, "",
        );
        f.rule_id = Some(id);
        f
    }

    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }
    pub fn at(mut self, path: PathBuf, line: Option<usize>) -> Self {
        self.path = Some(path);
        self.line = line;
        self
    }
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }
    pub fn evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
    pub fn recommend(mut self, rec: impl Into<String>) -> Self {
        self.recommendation = rec.into();
        self
    }
    pub fn confidence(mut self, c: crate::rule::Confidence) -> Self {
        self.confidence = c;
        self
    }

    /// Attach the rule that defines this finding (the join point to the guide +
    /// fix + scoring). Detectors keep their curated `title`/`severity`/`summary`
    /// and additionally tag the rule so scoring stays rule-driven.
    pub fn rule(mut self, id: crate::rule::RuleId) -> Self {
        self.rule_id = Some(id);
        self
    }

    pub fn with_package(mut self, package: PackageRef) -> Self {
        self.package = Some(package);
        self
    }

    pub fn with_references(mut self, references: Vec<String>) -> Self {
        self.references = references;
        self
    }

    pub fn with_fixed_version(mut self, fixed_version: Option<String>) -> Self {
        self.fixed_version = fixed_version;
        self
    }

    /// Attach the structured CVE ids (normalized upper-case, deduped, order
    /// preserved). Providers call this with their structured identifier fields
    /// so prioritization never has to scrape prose.
    pub fn with_cves(mut self, cves: impl IntoIterator<Item = String>) -> Self {
        self.cves = normalize_cves(cves);
        self
    }
}

/// Upper-case, `CVE-`-prefixed, deduped, order preserved: the invariant
/// KEV/EPSS matching relies on.
fn normalize_cves(cves: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    cves.into_iter()
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.starts_with("CVE-") && seen.insert(c.clone()))
        .collect()
}

/// Applies [`normalize_cves`] on deserialization too, so a cached or imported
/// report (`"cve-2021-44228"`) matches KEV/EPSS exactly like a fresh one.
fn deserialize_cves<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer).map(normalize_cves)
}

/// Local report identity for a project: a hash of its canonical absolute root.
/// NOT a cloud-correlation key (that's `GitInfo::owner_repo`) and not stable
/// across `git mv`/re-clone; it only keys local view-state and finding rollup.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ProjectId(pub String);

impl ProjectId {
    /// `proj_<sha256(canonical_root)[..16 hex]>`.
    pub fn from_root(canonical_root: &std::path::Path) -> Self {
        let digest = crate::hash::sha256(canonical_root.to_string_lossy().as_bytes());
        ProjectId(format!("proj_{}", hex::encode(&digest[..8])))
    }
}

/// What a project *is*. Identification happens in this priority order:
/// git repos first, then submodules / plain nested clones, then meaningful
/// directories, then the single synthetic config/host location.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectKind {
    GitRepo,
    /// A git repo nested inside another (a submodule or a plain nested clone).
    Submodule,
    Directory,
    /// The synthetic "System & user config" project (npmrc, ssh, host config…).
    ConfigLocation,
}

/// How recently the project saw activity; drives ambient-risk demotion later
/// (P5). Computed at discovery from git commit date and/or filesystem mtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Activity {
    Active,
    Recent,
    Dormant,
    Abandoned,
}

impl Activity {
    /// The user-facing name; matches the serde `kebab-case` form the web UI
    /// receives, so both surfaces show the same words.
    pub fn label(self) -> &'static str {
        match self {
            Activity::Active => "active",
            Activity::Recent => "recent",
            Activity::Dormant => "dormant",
            Activity::Abandoned => "abandoned",
        }
    }
}

/// Git metadata read cheaply and locally (never networked on the hot path).
/// Every field is optional so a partial/shallow/broken repo is representable
/// rather than a lie.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct GitInfo {
    pub branch: Option<String>,
    pub head_sha: Option<String>,
    /// Committer date of HEAD.
    pub head_date: Option<DateTime<Utc>>,
    pub shallow: bool,
    /// Normalized `owner/repo` from the remote: the cloud correlation key.
    /// GitHub only, so a GitLab or self-hosted project has `remote_url` and a
    /// host but no correlation key.
    pub owner_repo: Option<String>,
    pub remote_host: Option<String>,
    /// The `origin` url exactly as the repo's config spells it.
    pub remote_url: Option<String>,
}

/// Pure per-project finding counts, produced during finalize.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProjectRollup {
    /// Per-severity finding counts (reuses [`ScanStats`]; its `packages` field
    /// is unused here; package counts live on [`Project::package_count`]).
    pub by_severity: ScanStats,
    /// Per-category counts, sorted worst-first: the "3 secrets · 112 deps" line.
    #[serde(default)]
    pub by_category: Vec<CategoryRollup>,
    pub worst_severity: Option<Severity>,
}

/// A category's contribution to a project's rollup.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CategoryRollup {
    pub category: crate::rule::Category,
    /// Raw findings, which is not what "N vulnerable dependencies" means: one
    /// package can carry a dozen advisories. Surfaces that name the *thing*
    /// render [`Self::subjects`]; this is for per-finding arithmetic.
    pub count: usize,
    /// Distinct [`Finding::subject`]s, and therefore rows a reader will find
    /// when they open the category.
    #[serde(default)]
    pub subjects: usize,
    pub worst_severity: Severity,
    /// How many landed in the `Act` action band (drives the headline).
    pub act_count: usize,
}

/// Scoring action band: what to do, worst-first. `Act` is the highest priority.
/// Declaration order is the `Ord` (worst-first), used for sorting + `min`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Act,
    Attend,
    Track,
    Ambient,
}

/// Why a finding was demoted below its raw severity; surfaced to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DemotionReason {
    DormantProject,
    SubmoduleNotOwned,
    LowConfidence,
}

/// Project-aware scoring output for one finding (produced by `score.rs`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Priority {
    pub action: Action,
    pub score: i64,
    pub risk_class: crate::rule::RiskClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demoted_by: Option<DemotionReason>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectBucket {
    NeedsAttention,
    Dormant,
}

/// Scoring output for a project (produced by `score.rs`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProjectPosture {
    pub bucket: ProjectBucket,
    pub rank_score: i64,
    pub worst_action: Action,
    pub act: usize,
    pub attend: usize,
    pub track: usize,
    pub ambient: usize,
}

/// The reframed headline: what the Scan tab leads with instead of a raw count.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PostureSummary {
    pub projects_total: usize,
    pub projects_needing_attention: usize,
    pub by_category: Vec<CategoryRollup>,
    pub act: usize,
    pub attend: usize,
    pub track: usize,
    pub ambient: usize,
}

/// The unit of attention: every finding belongs to exactly one project
/// (attachment in `crate::project`, scoring in `crate::score`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Project {
    pub id: ProjectId,
    /// Canonical absolute root.
    pub root: PathBuf,
    pub name: String,
    pub kind: ProjectKind,
    /// Set when this project is a submodule / nested clone of another.
    pub submodule_of: Option<ProjectId>,
    pub git: Option<GitInfo>,
    /// Max filesystem mtime under the project, captured during the scan walk.
    pub last_modified: Option<DateTime<Utc>>,
    pub activity: Activity,
    pub ecosystems: Vec<String>,
    pub package_count: usize,
    pub rollup: ProjectRollup,
    /// Scoring output; `None` until `score.rs` runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<ProjectPosture>,
}

/// How one advisory source (`IntelSource`) fared during the scan, surfaced in
/// the report's providers block so users can see which sources actually
/// answered. A failing source degrades to `ok: false` + a message; it never
/// aborts the scan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderStatus {
    pub name: String,
    pub ok: bool,
    pub checked_packages: usize,
    pub findings: usize,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ScanStats {
    pub packages: usize,
    pub findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanStats {
    /// Count one finding of the given severity (bumps `findings` too).
    pub fn add(&mut self, severity: Severity) {
        self.findings += 1;
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    pub fn from_findings(packages: usize, findings: &[Finding]) -> Self {
        let mut stats = Self {
            packages,
            ..Self::default()
        };
        for finding in findings {
            stats.add(finding.severity);
        }
        stats
    }
}

/// What changed relative to the previous cached scan of the same roots: the
/// "3 resolved · 1 new" line and the Resolved section every surface renders.
/// Absent on a first scan, a roots change, or a cache-version mismatch.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanDelta {
    pub previous_at: DateTime<Utc>,
    /// Posture score (0-100) of the previous scan.
    pub previous_score: u32,
    /// Posture score of this scan, stored so clients never re-derive
    /// the grading math (the CLI, TUI, and web must all grade identically).
    pub score: u32,
    /// Finding ids present now but not in the previous scan.
    pub new_count: usize,
    /// Finding ids present in both scans.
    pub unchanged_count: usize,
    /// Finding ids gone since the previous scan (>= `resolved.len()`, which is capped).
    pub resolved_count: usize,
    /// The resolved findings themselves, worst-first, capped at [`RESOLVED_CAP`].
    pub resolved: Vec<Finding>,
    /// The new findings themselves, worst-first, capped at [`RESOLVED_CAP`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new: Vec<Finding>,
}

/// Cap on the resolved (and new) findings embedded in a delta, so a rule change
/// that clears or adds hundreds of findings can't bloat the cached report.
pub const RESOLVED_CAP: usize = 50;

impl ScanDelta {
    /// Diff `current` against `previous` (same id-set logic as the daemon's
    /// alert reconcile: `Finding.id` is the stable cross-scan identity).
    pub fn between(previous: &ScanReport, current: &ScanReport) -> Self {
        let prev_ids: std::collections::BTreeSet<&str> =
            previous.findings.iter().map(|f| f.id.as_str()).collect();
        let cur_ids: std::collections::BTreeSet<&str> =
            current.findings.iter().map(|f| f.id.as_str()).collect();
        let mut resolved: Vec<Finding> = previous
            .findings
            .iter()
            .filter(|f| !cur_ids.contains(f.id.as_str()))
            .cloned()
            .collect();
        resolved.sort_by_key(|f| std::cmp::Reverse(f.severity));
        resolved.dedup_by(|a, b| a.id == b.id);
        let resolved_count = resolved.len();
        resolved.truncate(RESOLVED_CAP);
        let mut new: Vec<Finding> = current
            .findings
            .iter()
            .filter(|f| !prev_ids.contains(f.id.as_str()))
            .cloned()
            .collect();
        new.sort_by_key(|f| std::cmp::Reverse(f.severity));
        new.dedup_by(|a, b| a.id == b.id);
        let new_count = new.len();
        new.truncate(RESOLVED_CAP);
        Self {
            previous_at: previous.generated_at,
            previous_score: crate::score::posture_score(&previous.stats),
            score: crate::score::posture_score(&current.stats),
            new_count,
            unchanged_count: cur_ids.intersection(&prev_ids).count(),
            resolved_count,
            resolved,
            new,
        }
    }
}

/// What a scan is *of*: the whole machine's standing posture, or one project
/// folder. Same report shape either way; the kind is routing, deciding which
/// stages run (home inventory is machine-only), which cache slot the report
/// lands in, and which live slot serves it. Logic below those seams never
/// branches on it.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanKind {
    Machine,
    #[default]
    Project,
}

/// The complete result of one scan: what the cache stores, `husk ci` emits as
/// JSON, and every UI renders.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanReport {
    /// Client shape-detection: bumped when the report shape changes.
    #[serde(default = "default_api_version")]
    pub api_version: u32,
    /// Machine posture or project scan; `default` so stored pre-kind reports
    /// still parse (they are all project-shaped scans).
    #[serde(default)]
    pub kind: ScanKind,
    pub generated_at: DateTime<Utc>,
    pub roots: Vec<PathBuf>,
    pub context: SystemContext,
    pub packages: Vec<PackageRef>,
    /// Discovered projects (the unit of attention). The findings list stays flat
    /// and joins to projects via `Finding.project_id`.
    #[serde(default)]
    pub projects: Vec<Project>,
    #[serde(default)]
    pub summary: PostureSummary,
    pub findings: Vec<Finding>,
    /// Findings the user has chosen to silence (project-policy `suppress`/`allow`
    /// or a personal ledger decision). Display-only: kept out of `findings` so
    /// scoring, posture, projects, and stats stay about open issues.
    #[serde(default)]
    pub ignored: Vec<Finding>,
    /// Read-only machine/project control observations produced during scanning.
    pub controls: Vec<crate::guide::control::ControlAssessment>,
    /// Typed, dynamically planned remediation for this exact report.
    pub remediations: Vec<crate::remediation::RemediationProposal>,
    /// Markdown catalog assessed against controls, findings, remediations, and
    /// the user's explicit read/completed/dismissed decisions.
    pub guidance: crate::guide::GuideReport,
    pub providers: Vec<ProviderStatus>,
    pub benchmarks: Vec<StageBenchmark>,
    pub stats: ScanStats,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<ScanDelta>,
}

/// Report shape version. Bump it whenever a field a surface renders is added or
/// changes meaning: the cache refuses anything older, so a report saved by the
/// previous build can never be rendered against the current expectations.
pub const REPORT_API_VERSION: u32 = 5;

fn default_api_version() -> u32 {
    REPORT_API_VERSION
}

impl ScanReport {
    pub fn empty(roots: Vec<PathBuf>) -> Self {
        Self {
            api_version: default_api_version(),
            kind: ScanKind::default(),
            generated_at: Utc::now(),
            roots,
            context: SystemContext::default(),
            packages: Vec::new(),
            projects: Vec::new(),
            summary: PostureSummary::default(),
            findings: Vec::new(),
            ignored: Vec::new(),
            controls: Vec::new(),
            remediations: Vec::new(),
            guidance: crate::guide::GuideReport::default(),
            providers: Vec::new(),
            benchmarks: Vec::new(),
            stats: ScanStats::default(),
            delta: None,
        }
    }

    pub fn new(
        roots: Vec<PathBuf>,
        packages: Vec<PackageRef>,
        findings: Vec<Finding>,
        providers: Vec<ProviderStatus>,
    ) -> Self {
        let stats = ScanStats::from_findings(packages.len(), &findings);
        Self {
            api_version: default_api_version(),
            kind: ScanKind::default(),
            generated_at: Utc::now(),
            roots,
            context: SystemContext::default(),
            packages,
            projects: Vec::new(),
            summary: PostureSummary::default(),
            findings,
            ignored: Vec::new(),
            controls: Vec::new(),
            remediations: Vec::new(),
            guidance: crate::guide::GuideReport::default(),
            providers,
            benchmarks: Vec::new(),
            stats,
            delta: None,
        }
    }

    /// The project a finding was attached to during finalization. The
    /// `Finding::project_id` -> [`Self::projects`] join every surface needs;
    /// linear because a machine holds tens of projects, not thousands.
    pub fn project_of(&self, finding: &Finding) -> Option<&Project> {
        let id = finding.project_id.as_ref()?;
        self.projects.iter().find(|project| &project.id == id)
    }

    /// One project's slice of this report, in the report's own display order.
    pub fn project_findings<'a>(
        &'a self,
        id: &'a ProjectId,
    ) -> impl Iterator<Item = &'a Finding> + 'a {
        self.findings
            .iter()
            .filter(move |f| f.project_id.as_ref() == Some(id))
    }

    pub fn refresh_stats(&mut self) {
        self.generated_at = Utc::now();
        self.stats = ScanStats::from_findings(self.packages.len(), &self.findings);
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StageBenchmark {
    pub stage: String,
    pub elapsed_ms: u128,
    pub files_checked: usize,
    pub bytes_scanned: u64,
    pub packages_checked: usize,
    pub findings: usize,
    pub workers: usize,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SystemContext {
    pub user: Option<String>,
    pub home_dir: Option<PathBuf>,
    pub current_dir: Option<PathBuf>,
    pub os: String,
    pub arch: String,
    pub distro: Option<String>,
    pub kernel: Option<String>,
    pub git_name: Option<String>,
    pub git_email: Option<String>,
    /// Dev/security tools detected on `PATH` (package managers plus tooling
    /// like gitleaks/gpg/gh). Legacy wire name kept for client compatibility.
    pub package_managers: Vec<String>,
    pub dev_configs: Vec<DevConfigSummary>,
    pub scan_roots: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DevConfigSummary {
    pub label: String,
    pub path: PathBuf,
    pub present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProgressState {
    Pending,
    Running,
    Done,
    Warning,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProgressStep {
    pub label: String,
    pub state: ProgressState,
    pub message: String,
    pub elapsed_ms: Option<u128>,
    /// Within-step completion estimate (0..1) while `Running`; UIs interpolate
    /// the progress bar with it instead of holding at the step boundary.
    #[serde(default)]
    pub fraction: Option<f32>,
    /// When the step first entered `Running`; lets UIs ease the bar forward
    /// during steps with no countable work (network waits).
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
}

impl ProgressStep {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            state: ProgressState::Pending,
            message: String::new(),
            elapsed_ms: None,
            fraction: None,
            started_at: None,
        }
    }
}

/// The in-progress scan state the TUI and the web `/api/live` endpoint poll.
/// The pipeline updates it (behind [`SharedLiveScan`]) as stages complete and
/// `steps` narrates progress; `running` + `finished_at` distinguish running /
/// finished / idle (see [`LiveScan::idle`]).
///
/// `report` is always a whole report, never a half-built one. A rescan that has
/// a finished report to keep on screen builds the replacement off to the side
/// and swaps it in once ([`LiveScan::publish`]), so `running == true` together
/// with `finished_at.is_some()` means "these results are the previous scan's,
/// and a new scan is running".
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveScan {
    pub report: ScanReport,
    pub running: bool,
    pub current_task: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub steps: Vec<ProgressStep>,
    pub error: Option<String>,
    /// Where a rescan accumulates its report while `report` still serves the
    /// previous one. Process-local: [`LiveScanLock::snapshot`] drops it, so no
    /// reader and nothing on the wire can observe a partial scan.
    #[serde(skip)]
    pending: Option<ScanReport>,
}

impl LiveScan {
    fn default_steps() -> Vec<ProgressStep> {
        vec![
            ProgressStep::new("discover packages"),
            ProgressStep::new("scan local files"),
            ProgressStep::new("scan home inventory"),
            ProgressStep::new("query online providers"),
            ProgressStep::new("finalize report"),
        ]
    }

    /// A pending live scan over `roots`. Pure data: the fresh
    /// [`SystemContext`] is collected by the scan itself
    /// (`scan::run_scan_live`), not here.
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            report: ScanReport::empty(roots),
            running: true,
            current_task: "starting scan".to_string(),
            started_at: Utc::now(),
            finished_at: None,
            steps: Self::default_steps(),
            error: None,
            pending: None,
        }
    }

    /// An idle live scan: the server is up but no scan has been started;
    /// `husk web` waits for the user to pick a directory in the UI. Detected
    /// by clients as `!running && finished_at.is_none()`.
    pub fn idle(roots: Vec<PathBuf>) -> Self {
        Self {
            report: ScanReport::empty(roots),
            running: false,
            current_task: "waiting for a scan target".to_string(),
            started_at: Utc::now(),
            finished_at: None,
            steps: Self::default_steps(),
            error: None,
            pending: None,
        }
    }

    /// Wrap an already-complete report (the cached-report path). Reuses the
    /// report's own context; collects nothing and spawns no subprocesses.
    pub fn finished(report: ScanReport) -> Self {
        let mut steps = Self::default_steps();
        for step in &mut steps {
            step.state = ProgressState::Done;
        }
        Self {
            report,
            running: false,
            current_task: "scan complete".to_string(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            steps,
            error: None,
            pending: None,
        }
    }

    /// Begin a scan over `roots` in place. A finished report over the same
    /// roots stays on display until the replacement lands, so a rescan never
    /// blanks the UI for its duration; a first scan, a re-targeted scan, or a
    /// never-completed one has nothing worth keeping and starts empty, which is
    /// where results stream in as they arrive.
    pub fn restart(&mut self, roots: Vec<PathBuf>) {
        if self.finished_at.is_none() || self.report.roots != roots {
            *self = Self::new(roots);
            return;
        }
        self.pending = Some(ScanReport::empty(roots));
        self.running = true;
        self.current_task = "starting scan".to_string();
        self.started_at = Utc::now();
        self.steps = Self::default_steps();
        self.error = None;
    }

    /// The report this scan writes into: the retained case fills the off-screen
    /// one, every other case fills `report` directly.
    pub fn working(&mut self) -> &mut ScanReport {
        self.pending.as_mut().unwrap_or(&mut self.report)
    }

    /// Read side of [`LiveScan::working`], for the stages that need back what
    /// an earlier stage recorded.
    pub fn working_ref(&self) -> &ScanReport {
        self.pending.as_ref().unwrap_or(&self.report)
    }

    /// Swap in the finished report and mark the scan complete. `report` is
    /// built whole before it gets here, so under the caller's write lock the
    /// visible transition is one assignment: a reader sees either the previous
    /// report while running or the new one when done, never a mixture.
    pub fn publish(&mut self, report: ScanReport) {
        self.report = report;
        self.pending = None;
        self.running = false;
        self.current_task = "scan complete".to_string();
        self.finished_at = Some(Utc::now());
    }

    /// Stop a failed scan and discard its half-built report, leaving whatever
    /// was already on display in place.
    pub fn fail(&mut self, error: String) {
        self.pending = None;
        self.running = false;
        self.current_task = format!("scan failed: {error}");
        self.error = Some(error);
        self.finished_at = Some(Utc::now());
    }

    /// A copy safe to hand to any reader: the in-flight report is left behind
    /// (not just cleared afterwards, so a poll never pays to clone it), making
    /// this exactly what the UIs render and serialize.
    pub fn visible(&self) -> Self {
        Self {
            report: self.report.clone(),
            running: self.running,
            current_task: self.current_task.clone(),
            started_at: self.started_at,
            finished_at: self.finished_at,
            steps: self.steps.clone(),
            error: self.error.clone(),
            pending: None,
        }
    }
}

pub type SharedLiveScan = Arc<RwLock<LiveScan>>;

/// Convenience accessors for the shared live-scan lock. They recover from a
/// poisoned lock (a panicked scan thread) instead of propagating the panic,
/// and give every reader one idiom instead of scattered `.read().expect(…)`.
pub trait LiveScanLock {
    fn with_read<T>(&self, f: impl FnOnce(&LiveScan) -> T) -> T;
    fn with_write<T>(&self, f: impl FnOnce(&mut LiveScan) -> T) -> T;
    fn snapshot(&self) -> LiveScan {
        self.with_read(LiveScan::visible)
    }
}

impl LiveScanLock for SharedLiveScan {
    fn with_read<T>(&self, f: impl FnOnce(&LiveScan) -> T) -> T {
        f(&self.read().unwrap_or_else(|poison| poison.into_inner()))
    }

    fn with_write<T>(&self, f: impl FnOnce(&mut LiveScan) -> T) -> T {
        f(&mut self.write().unwrap_or_else(|poison| poison.into_inner()))
    }
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub kind: ScanKind,
    pub roots: Vec<PathBuf>,
    pub online: bool,
    pub include_home_inventory: bool,
    pub max_file_bytes: u64,
    /// Append a `~/.husk/history.jsonl` row when the scan finishes. Off for
    /// ephemeral scans (an agent hook scanning one edited file, or a prompt in
    /// a temp dir): each has its own roots and would land as a separate,
    /// permanent "scan target" in the history surfaces.
    pub record_history: bool,
}

impl ScanOptions {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            kind: ScanKind::Project,
            roots,
            online: true,
            // Home inventory is the machine-only stage; a project scan is the
            // folder and nothing else.
            include_home_inventory: false,
            max_file_bytes: 1_000_000,
            record_history: true,
        }
    }

    /// A machine-posture scan: the home directory plus the machine-only
    /// stages (home inventory of editor/AI config locations).
    pub fn machine(home: PathBuf) -> Self {
        let mut options = Self::new(vec![home]);
        options.kind = ScanKind::Machine;
        options.include_home_inventory = true;
        options
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn pkg(ecosystem: &str) -> PackageRef {
        PackageRef {
            ecosystem: ecosystem.to_string(),
            name: "x".to_string(),
            version: "1".to_string(),
            manifest_path: PathBuf::from("x"),
            line: None,
        }
    }

    fn report_with_findings(specs: &[(&str, Severity)]) -> ScanReport {
        let mut report = ScanReport::empty(vec![]);
        report.findings = specs
            .iter()
            .map(|(id, sev)| {
                Finding::new(
                    *id,
                    *id,
                    *sev,
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
        report.refresh_stats();
        report
    }

    fn scan_over(roots: &[&str], findings: &[&str]) -> ScanReport {
        let specs: Vec<_> = findings.iter().map(|id| (*id, Severity::High)).collect();
        let mut report = report_with_findings(&specs);
        report.roots = roots.iter().map(PathBuf::from).collect();
        report
    }

    fn finding_ids(report: &ScanReport) -> Vec<&str> {
        report.findings.iter().map(|f| f.id.as_str()).collect()
    }

    /// A rescan over the same target keeps the previous results on screen for
    /// its whole duration: every mid-scan write lands off screen, and the
    /// visible report changes exactly once, when the new one is published.
    #[test]
    fn a_rescan_shows_the_previous_report_until_the_new_one_lands() {
        let roots = ["/proj"];
        let mut live = LiveScan::finished(scan_over(&roots, &["previous"]));
        let mut seen = vec![finding_ids(&live.report).join(",")];

        live.restart(vec![PathBuf::from("/proj")]);
        assert!(live.running, "the rescan is running");
        assert!(
            live.finished_at.is_some(),
            "and the visible report is still the one that finished earlier"
        );
        seen.push(finding_ids(&live.visible().report).join(","));

        // Stand in for the pipeline stages, each of which writes through
        // `working`: context, packages, then incremental finding publishes.
        live.working().context.os = "test".to_string();
        for _ in 0..3 {
            live.working().findings = scan_over(&roots, &["mid-scan"]).findings;
            live.working().refresh_stats();
            seen.push(finding_ids(&live.visible().report).join(","));
        }

        live.publish(scan_over(&roots, &["fresh"]));
        seen.push(finding_ids(&live.visible().report).join(","));
        assert!(!live.running, "publishing ends the scan");

        seen.dedup();
        assert_eq!(
            seen,
            vec!["previous".to_string(), "fresh".to_string()],
            "one swap, at publish"
        );
    }

    /// The half-built report is process-local: what a reader takes is the
    /// visible one, with nothing behind it to leak on a later read.
    #[test]
    fn a_snapshot_carries_no_half_built_report() {
        let live: SharedLiveScan = Arc::new(RwLock::new(LiveScan::finished(scan_over(
            &["/proj"],
            &["previous"],
        ))));
        live.with_write(|state| {
            state.restart(vec![PathBuf::from("/proj")]);
            state.working().findings = scan_over(&["/proj"], &["mid-scan"]).findings;
        });

        let mut snapshot = live.snapshot();
        assert_eq!(finding_ids(&snapshot.report), ["previous"]);
        assert_eq!(finding_ids(snapshot.working()), ["previous"]);
    }

    /// Nothing to retain degrades to the empty start, which is what lets a
    /// first scan's results appear as they arrive.
    #[test]
    fn a_first_scan_starts_empty_and_streams_into_view() {
        let mut live = LiveScan::idle(vec![PathBuf::from("/proj")]);

        live.restart(vec![PathBuf::from("/proj")]);
        assert!(live.running);
        assert!(live.finished_at.is_none());
        assert!(live.report.findings.is_empty());

        live.working().findings = scan_over(&["/proj"], &["streamed"]).findings;
        assert_eq!(finding_ids(&live.visible().report), ["streamed"]);
    }

    #[test]
    fn re_targeting_the_scan_drops_the_previous_report() {
        let mut live = LiveScan::finished(scan_over(&["/proj"], &["previous"]));

        live.restart(vec![PathBuf::from("/other")]);
        assert!(
            live.report.findings.is_empty(),
            "one directory's results are not another's"
        );
        assert_eq!(live.report.roots, vec![PathBuf::from("/other")]);
    }

    /// A failed scan has no report to show, so the one already on screen stays,
    /// and the next rescan can still retain it.
    #[test]
    fn a_failed_rescan_leaves_the_previous_report_on_screen() {
        let mut live = LiveScan::finished(scan_over(&["/proj"], &["previous"]));
        live.restart(vec![PathBuf::from("/proj")]);
        live.working().findings = scan_over(&["/proj"], &["mid-scan"]).findings;

        live.fail("no route to host".to_string());
        assert!(!live.running);
        assert_eq!(live.error.as_deref(), Some("no route to host"));
        assert_eq!(finding_ids(&live.report), ["previous"]);

        live.restart(vec![PathBuf::from("/proj")]);
        assert_eq!(finding_ids(&live.report), ["previous"]);
        assert!(
            live.error.is_none(),
            "the new run starts without the old error"
        );
    }

    #[test]
    fn delta_counts_resolved_new_and_unchanged() {
        let previous = report_with_findings(&[
            ("gone-high", Severity::High),
            ("gone-low", Severity::Low),
            ("kept", Severity::Medium),
        ]);
        let current =
            report_with_findings(&[("kept", Severity::Medium), ("fresh", Severity::Critical)]);
        let delta = ScanDelta::between(&previous, &current);
        assert_eq!(delta.resolved_count, 2);
        assert_eq!(delta.new_count, 1);
        assert_eq!(delta.unchanged_count, 1);
        // Resolved list is worst-first.
        let ids: Vec<&str> = delta.resolved.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["gone-high", "gone-low"]);
        // Posture penalties: previous = high 10 + medium 3 + low 1 → 86;
        // current = critical 25 + medium 3 → 72.
        assert_eq!(delta.previous_score, 86);
        assert_eq!(delta.score, 72);
    }

    #[test]
    fn delta_caps_the_embedded_resolved_findings() {
        let many: Vec<(String, Severity)> = (0..RESOLVED_CAP + 20)
            .map(|i| (format!("f{i}"), Severity::Low))
            .collect();
        let specs: Vec<(&str, Severity)> =
            many.iter().map(|(id, sev)| (id.as_str(), *sev)).collect();
        let previous = report_with_findings(&specs);
        let current = report_with_findings(&[]);
        let delta = ScanDelta::between(&previous, &current);
        assert_eq!(delta.resolved_count, RESOLVED_CAP + 20);
        assert_eq!(delta.resolved.len(), RESOLVED_CAP);
    }

    #[test]
    fn severity_orders_worst_first() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn maps_fixed_osv_ecosystems() {
        assert_eq!(pkg("npm").osv_ecosystem().as_deref(), Some("npm"));
        assert_eq!(pkg("cargo").osv_ecosystem().as_deref(), Some("crates.io"));
        assert_eq!(pkg("clojure").osv_ecosystem().as_deref(), Some("Maven"));
        assert_eq!(pkg("opam").osv_ecosystem().as_deref(), Some("opam"));
        // No OSV coverage -> inventory only.
        assert_eq!(pkg("cocoapods").osv_ecosystem(), None);
        assert_eq!(pkg("ollama").osv_ecosystem(), None);
    }

    #[test]
    fn release_qualified_distros_map_to_osv() {
        assert_eq!(
            pkg("debian:12").osv_ecosystem().as_deref(),
            Some("Debian:12")
        );
        assert_eq!(
            pkg("ubuntu:22.04").osv_ecosystem().as_deref(),
            Some("Ubuntu:22.04")
        );
        assert_eq!(
            pkg("alpine:v3.19").osv_ecosystem().as_deref(),
            Some("Alpine:v3.19")
        );
        // A bare distro id (no release detected) cannot match OSV.
        assert_eq!(pkg("debian").osv_ecosystem(), None);
        assert_eq!(pkg("alpine").osv_ecosystem(), None);
        // An empty release segment is not a valid query.
        assert_eq!(pkg("debian:").osv_ecosystem(), None);
    }

    #[test]
    fn github_ecosystem_uses_rest_api_tokens() {
        // GitHub's REST advisories API uses lowercase ecosystem tokens; `pub`
        // (Dart) and `actions` are valid and covered (verified against
        // api.github.com), broadening the GitHub malware provider.
        assert_eq!(pkg("pub").github_ecosystem(), Some("pub"));
        assert_eq!(pkg("github-actions").github_ecosystem(), Some("actions"));
        assert_eq!(pkg("pypi").github_ecosystem(), Some("pip"));
        // Inventory-only ecosystems have no GitHub advisory namespace.
        assert_eq!(pkg("ollama").github_ecosystem(), None);
    }

    #[test]
    fn rpm_families_map_to_osv() {
        assert_eq!(pkg("redhat").osv_ecosystem().as_deref(), Some("Red Hat"));
        assert_eq!(pkg("suse").osv_ecosystem().as_deref(), Some("openSUSE"));
        // Fedora and unknown rpm stay inventory-only (no OSV ecosystem).
        assert_eq!(pkg("fedora").osv_ecosystem(), None);
        assert_eq!(pkg("rpm").osv_ecosystem(), None);
    }

    #[test]
    fn cves_are_normalized_on_deserialize_like_with_cves() {
        // A cached/imported report bypasses `with_cves`; deserialization must
        // apply the same invariant or lowercase ids miss KEV/EPSS matching.
        let json = serde_json::json!({
            "id": "f",
            "title": "t",
            "severity": "high",
            "category": "vulnerability",
            "source": "s",
            "path": null,
            "line": null,
            "summary": "",
            "evidence": null,
            "recommendation": "",
            "references": [],
            "package": null,
            "cves": ["cve-2021-44228", " CVE-2021-44228 ", "GHSA-xxxx", "cve-2021-45046"],
        });
        let finding: Finding = serde_json::from_value(json).expect("finding deserializes");
        assert_eq!(finding.cves, vec!["CVE-2021-44228", "CVE-2021-45046"]);
    }
}
