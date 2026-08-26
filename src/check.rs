//! `husk check`: a pre-install verdict for a single package, answered by
//! **OSV.dev**, the same public advisory source `husk scan` queries. There is
//! no husk-curated feed and no husk-controlled trust root in the path: the
//! verdict comes straight from a source anyone can audit, over TLS.
//!
//! Lookups are cached for an hour in the local [`crate::cache::KvCache`].
//! When the network is down (or the ecosystem has no OSV coverage) the verdict
//! is an honest `unknown`, never a guess and never a hard error.
//!
//! # Verdict rules
//!
//! 1. With a **version**, every advisory OSV matches to that exact version
//!    counts: malicious-package records (OSV `MAL-` ids) and vulnerabilities
//!    alike.
//! 2. Without a version, only **malicious-package advisories** count. Nearly
//!    every popular package has some historical CVE in old releases; blocking
//!    `npm install lodash` over one would be noise. A malware advisory is
//!    different: any version of a malicious name is a no.
//! 3. An advisory *published within the cooldown window* (default 24h) is
//!    marked so the result can call out that it is brand new.

use crate::model::Severity;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration as StdDuration;

/// Default cooldown: advisories published within this many hours are treated
/// as extra-risky. Configurable per check.
pub const DEFAULT_COOLDOWN_HOURS: i64 = 24;

pub const SOURCE: &str = "OSV.dev";

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

/// How long a cached OSV answer stays fresh.
const CACHE_TTL: StdDuration = StdDuration::from_secs(60 * 60);

/// Per-lookup HTTP timeout so an interactive check fails open quickly when the
/// network is unavailable.
const CHECK_TIMEOUT: StdDuration = StdDuration::from_secs(6);

/// The package the verdict is about, after ecosystem inference/normalization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CheckTarget {
    pub ecosystem: String,
    pub name: String,
    /// `None` means "any version"; only malicious-package advisories apply.
    pub version: Option<String>,
}

impl CheckTarget {
    /// Build a target from CLI input. A bare `name` (no explicit ecosystem)
    /// infers `npm`, matching what the install wrappers pass for `npm`/`npx`.
    pub fn new(ecosystem: Option<&str>, name: &str, version: Option<&str>) -> Self {
        let ecosystem = ecosystem
            .map(normalize_ecosystem)
            .unwrap_or_else(|| "npm".to_string());
        Self {
            ecosystem,
            name: name.trim().to_string(),
            version: version
                .map(|value| value.trim().to_string())
                .filter(|v| !v.is_empty()),
        }
    }
}

/// Map common package-manager / CLI spellings onto husk's lowercase ecosystem
/// ids. Unknown values pass through lowercased.
pub fn normalize_ecosystem(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "npm" | "node" | "nodejs" | "pnpm" | "yarn" | "npx" | "pnpx" => "npm".to_string(),
        "pypi" | "pip" | "pip3" | "python" | "uv" | "poetry" | "pipx" => "pypi".to_string(),
        "cargo" | "crates" | "crates.io" | "rust" => "cargo".to_string(),
        "go" | "golang" => "go".to_string(),
        other => other.to_string(),
    }
}

/// The kind of problem an advisory describes, derived from its OSV id: the
/// `MAL-` namespace is OSV's malicious-package database (malware, compromised
/// releases, typosquats); everything else is a vulnerability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictKind {
    Malicious,
    Vulnerable,
}

impl VerdictKind {
    fn of(advisory_id: &str) -> Self {
        if advisory_id.to_ascii_uppercase().starts_with("MAL-") {
            Self::Malicious
        } else {
            Self::Vulnerable
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Vulnerable => "vulnerable",
        }
    }

    /// True for verdicts that mean "do not run this package's code at all",
    /// as opposed to a merely-vulnerable dependency.
    pub fn is_malicious(self) -> bool {
        matches!(self, Self::Malicious)
    }

    /// The recommendation text shown by `husk check`.
    pub fn recommendation(self) -> &'static str {
        match self {
            Self::Malicious => {
                "Do not install. Remove it anywhere it is already present and rotate any \
                 credentials that were exposed on those machines."
            }
            Self::Vulnerable => {
                "Install a fixed version instead, or avoid the dependency until one is available."
            }
        }
    }
}

/// One advisory that flags the target, derived from a single OSV record.
#[derive(Clone, Debug, Serialize)]
pub struct FlagReason {
    pub kind: VerdictKind,
    /// The OSV advisory id (`MAL-…`, `GHSA-…`, `CVE-…`).
    pub advisory: String,
    pub severity: Severity,
    pub summary: String,
    pub references: Vec<String>,
    pub published_at: Option<DateTime<Utc>>,
    /// True when `published_at` is within the cooldown window relative to the
    /// check's clock.
    pub within_cooldown: bool,
    pub recommendation: String,
}

/// The outcome of a check. `Clean` means OSV answered and matched nothing;
/// `Unknown` means no answer (offline, or an ecosystem OSV does not cover);
/// honest, and never a block.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum CheckOutcome {
    Clean,
    Flagged { reasons: Vec<FlagReason> },
    Unknown { reason: String },
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckResult {
    pub target: CheckTarget,
    pub outcome: CheckOutcome,
    /// The advisory source consulted ([`SOURCE`]); stamped into the JSON
    /// output so scripts see where the verdict came from.
    pub source: &'static str,
    pub cooldown_hours: i64,
}

impl CheckResult {
    pub fn is_flagged(&self) -> bool {
        matches!(self.outcome, CheckOutcome::Flagged { .. })
    }

    /// Process exit code: non-zero when flagged so scripts can branch on it.
    /// Clean and unknown both exit 0.
    pub fn exit_code(&self) -> i32 {
        if self.is_flagged() { 1 } else { 0 }
    }
}

/// Check one package against OSV.dev: cache → network → verdict. Never an
/// error: a failed lookup is an `Unknown` outcome.
pub async fn check(target: CheckTarget, cooldown_hours: i64) -> CheckResult {
    let outcome = match osv_ecosystem(&target.ecosystem) {
        None => CheckOutcome::Unknown {
            reason: format!(
                "no live advisory source covers ecosystem {:?}",
                target.ecosystem
            ),
        },
        Some(ecosystem) => match fetch_vulns(&target, &ecosystem).await {
            Ok(vulns) => outcome_from_vulns(&target, &vulns, Utc::now(), cooldown_hours),
            Err(reason) => CheckOutcome::Unknown {
                reason: format!("{SOURCE} lookup failed: {reason}"),
            },
        },
    };
    CheckResult {
        target,
        outcome,
        source: SOURCE,
        cooldown_hours,
    }
}

/// OSV's name for a local ecosystem id (`cargo` → `crates.io`, `pypi` →
/// `PyPI`), via the same mapping table the scan providers use, so check and
/// scan verdicts can never diverge on ecosystem naming.
fn osv_ecosystem(local_ecosystem: &str) -> Option<String> {
    crate::model::PackageRef {
        ecosystem: local_ecosystem.to_string(),
        name: String::new(),
        version: String::new(),
        manifest_path: std::path::PathBuf::new(),
        line: None,
    }
    .osv_ecosystem()
}

/// Fetch the matching advisories for `target` from OSV, going through the
/// KvCache first. Errors are short status strings for the `unknown` outcome.
async fn fetch_vulns(target: &CheckTarget, ecosystem: &str) -> Result<Vec<CheckVuln>, String> {
    let cache = crate::cache::KvCache::open().ok();
    let key = format!(
        "check:{ecosystem}:{}:{}",
        target.name,
        target.version.as_deref().unwrap_or("*")
    );
    if let Some(body) = cache.as_ref().and_then(|c| c.get_fresh(&key, CACHE_TTL))
        && let Ok(parsed) = serde_json::from_slice::<OsvQueryResponse>(&body)
    {
        return Ok(parsed.vulns);
    }

    let client = reqwest::Client::builder()
        .timeout(CHECK_TIMEOUT)
        .user_agent(concat!("husk/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|err| err.to_string())?;
    let mut query = serde_json::json!({
        "package": { "name": target.name, "ecosystem": ecosystem }
    });
    if let Some(version) = &target.version {
        query["version"] = serde_json::json!(version);
    }
    let body = crate::providers::fetch_body(client.post(OSV_QUERY_URL).json(&query))
        .await
        .map_err(|err| err.to_string())?;
    let parsed = serde_json::from_slice::<OsvQueryResponse>(&body)
        .map_err(|err| format!("invalid response: {err}"))?;
    if let Some(cache) = &cache {
        let _ = cache.put(&key, &body);
    }
    Ok(parsed.vulns)
}

/// Pure verdict logic over an explicit advisory set, clock, and cooldown.
pub(crate) fn outcome_from_vulns(
    target: &CheckTarget,
    vulns: &[CheckVuln],
    now: DateTime<Utc>,
    cooldown_hours: i64,
) -> CheckOutcome {
    let cooldown = Duration::hours(cooldown_hours.max(0));
    let mut reasons: Vec<FlagReason> = vulns
        .iter()
        // Rule 2: without a version, only malicious-package advisories count.
        .filter(|vuln| target.version.is_some() || VerdictKind::of(&vuln.id).is_malicious())
        .map(|vuln| flag_reason(vuln, now, cooldown))
        .collect();

    // Strongest first: malicious before vulnerable, then by severity rank,
    // then newest advisory first. Deterministic so output and tests are stable.
    reasons.sort_by(|a, b| {
        b.kind
            .is_malicious()
            .cmp(&a.kind.is_malicious())
            .then(b.severity.cmp(&a.severity))
            .then(b.published_at.cmp(&a.published_at))
    });

    if reasons.is_empty() {
        CheckOutcome::Clean
    } else {
        CheckOutcome::Flagged { reasons }
    }
}

fn flag_reason(vuln: &CheckVuln, now: DateTime<Utc>, cooldown: Duration) -> FlagReason {
    let kind = VerdictKind::of(&vuln.id);
    let within_cooldown = cooldown > Duration::zero()
        && vuln
            .published
            .is_some_and(|published| now - published < cooldown);
    let summary = vuln
        .summary
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| vuln.details.clone().filter(|s| !s.trim().is_empty()))
        .map(|s| crate::providers::first_sentence(&s))
        .unwrap_or_else(|| format!("{} matched this package at {SOURCE}.", vuln.id));
    let mut references: Vec<String> = vuln
        .references
        .iter()
        .map(|reference| reference.url.clone())
        .filter(|url| !url.is_empty())
        .collect();
    references.push(format!("https://osv.dev/vulnerability/{}", vuln.id));
    FlagReason {
        kind,
        advisory: vuln.id.clone(),
        severity: vuln_severity(vuln, &summary),
        summary,
        references,
        published_at: vuln.published,
        within_cooldown,
        recommendation: kind.recommendation().to_string(),
    }
}

/// Same ladder as the scan provider's OSV severity mapping: malicious →
/// Critical, else the `database_specific.severity` label, else a CVSS string
/// containing "critical", else High.
fn vuln_severity(vuln: &CheckVuln, summary: &str) -> Severity {
    if VerdictKind::of(&vuln.id).is_malicious()
        || summary.to_ascii_lowercase().contains("malicious")
    {
        return Severity::Critical;
    }
    if let Some(value) = vuln
        .database_specific
        .get("severity")
        .and_then(|value| value.as_str())
    {
        return Severity::from_external(value);
    }
    if vuln
        .severity
        .iter()
        .any(|severity| severity.score.to_ascii_lowercase().contains("critical"))
    {
        return Severity::Critical;
    }
    Severity::High
}

/// The subset of an OSV record `husk check` acts on; unknown fields ignored.
#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct CheckVuln {
    pub(crate) id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverityScore>,
    #[serde(default)]
    database_specific: serde_json::Value,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    pub(crate) published: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvSeverityScore {
    score: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvReference {
    #[serde(default)]
    url: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<CheckVuln>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(id: &str, summary: &str, published: Option<DateTime<Utc>>) -> CheckVuln {
        CheckVuln {
            id: id.to_string(),
            summary: Some(summary.to_string()).filter(|s| !s.is_empty()),
            published,
            ..CheckVuln::default()
        }
    }

    fn target(version: Option<&str>) -> CheckTarget {
        CheckTarget::new(Some("npm"), "leftpad-pro", version)
    }

    fn result(outcome: CheckOutcome) -> CheckResult {
        CheckResult {
            target: target(Some("1.0.0")),
            outcome,
            source: SOURCE,
            cooldown_hours: DEFAULT_COOLDOWN_HOURS,
        }
    }

    #[test]
    fn bare_name_infers_npm() {
        let target = CheckTarget::new(None, "left-pad", None);
        assert_eq!(target.ecosystem, "npm");
        assert_eq!(target.version, None);
    }

    #[test]
    fn ecosystem_aliases_normalize() {
        assert_eq!(normalize_ecosystem("pip"), "pypi");
        assert_eq!(normalize_ecosystem("YARN"), "npm");
        assert_eq!(normalize_ecosystem("crates.io"), "cargo");
        assert_eq!(normalize_ecosystem("golang"), "go");
    }

    #[test]
    fn local_ids_map_to_osv_ecosystems() {
        // The same mapping table the scan providers use: `husk check cargo:…`
        // must query OSV's `crates.io`, `pip` its `PyPI`.
        assert_eq!(osv_ecosystem("cargo").as_deref(), Some("crates.io"));
        assert_eq!(osv_ecosystem("pypi").as_deref(), Some("PyPI"));
        assert_eq!(osv_ecosystem("npm").as_deref(), Some("npm"));
        // Editor extensions are covered: OSV files marketplace and Open VSX
        // malware under one `VSCode` ecosystem, so `husk check
        // vscode-extension:Foo.Bar` is a real lookup rather than an `unknown`.
        assert_eq!(osv_ecosystem("vscode-extension").as_deref(), Some("VSCode"));
        // Still no OSV coverage → None → the check reports an honest `unknown`.
        assert_eq!(osv_ecosystem("chrome-extension"), None);
    }

    #[test]
    fn no_advisories_is_clean_with_zero_exit() {
        let outcome = outcome_from_vulns(
            &target(Some("1.0.0")),
            &[],
            Utc::now(),
            DEFAULT_COOLDOWN_HOURS,
        );
        let result = result(outcome);
        assert!(!result.is_flagged());
        assert_eq!(result.exit_code(), 0);
    }

    #[test]
    fn malware_advisory_flags_with_nonzero_exit() {
        let now = Utc::now();
        let vulns = vec![vuln(
            "MAL-2026-0001",
            "Malicious code in leftpad-pro",
            Some(now - Duration::days(10)),
        )];
        let outcome =
            outcome_from_vulns(&target(Some("1.0.0")), &vulns, now, DEFAULT_COOLDOWN_HOURS);
        let result = result(outcome);
        assert!(result.is_flagged());
        assert_eq!(result.exit_code(), 1);
        let CheckOutcome::Flagged { reasons } = &result.outcome else {
            panic!("expected a flagged result");
        };
        let reason = reasons.first().expect("a reason");
        assert_eq!(reason.kind, VerdictKind::Malicious);
        assert!(reason.kind.is_malicious());
        assert_eq!(reason.severity, Severity::Critical);
        assert!(
            !reason.within_cooldown,
            "10-day-old advisory is past cooldown"
        );
        assert!(
            reason
                .references
                .iter()
                .any(|r| r.contains("osv.dev/vulnerability/MAL-2026-0001"))
        );
    }

    #[test]
    fn versionless_check_counts_only_malicious_advisories() {
        // `npm install lodash` (no pin) must not be blocked by an old patched
        // CVE; without a version only MAL- records count.
        let now = Utc::now();
        let vulns = vec![
            vuln("GHSA-aaaa-bbbb-cccc", "Old prototype pollution", Some(now)),
            vuln("CVE-2021-0001", "Historical CVE", Some(now)),
        ];
        let outcome = outcome_from_vulns(&target(None), &vulns, now, DEFAULT_COOLDOWN_HOURS);
        assert!(matches!(outcome, CheckOutcome::Clean));

        // But a MAL- record flags the bare name.
        let vulns = vec![vuln("MAL-2026-0002", "", Some(now - Duration::days(2)))];
        let outcome = outcome_from_vulns(&target(None), &vulns, now, DEFAULT_COOLDOWN_HOURS);
        assert!(matches!(outcome, CheckOutcome::Flagged { .. }));
    }

    #[test]
    fn versioned_check_counts_vulnerabilities_too() {
        let now = Utc::now();
        let vulns = vec![vuln("GHSA-aaaa-bbbb-cccc", "RCE in 1.0.0", Some(now))];
        let outcome =
            outcome_from_vulns(&target(Some("1.0.0")), &vulns, now, DEFAULT_COOLDOWN_HOURS);
        let CheckOutcome::Flagged { reasons } = outcome else {
            panic!("expected flagged");
        };
        assert_eq!(reasons[0].kind, VerdictKind::Vulnerable);
        assert_eq!(reasons[0].severity, Severity::High);
    }

    #[test]
    fn cooldown_marks_freshly_published_advisories() {
        let now = Utc::now();
        let vulns = vec![vuln(
            "MAL-2026-0003",
            "typosquat",
            Some(now - Duration::hours(3)),
        )];
        let outcome =
            outcome_from_vulns(&target(Some("9.9.9")), &vulns, now, DEFAULT_COOLDOWN_HOURS);
        let CheckOutcome::Flagged { reasons } = outcome else {
            panic!("expected flagged");
        };
        assert!(
            reasons[0].within_cooldown,
            "3h-old advisory is inside 24h cooldown"
        );

        // Zero cooldown never marks; an unknown publish date never marks.
        let outcome = outcome_from_vulns(&target(Some("9.9.9")), &vulns, now, 0);
        let CheckOutcome::Flagged { reasons } = outcome else {
            panic!("expected flagged");
        };
        assert!(!reasons[0].within_cooldown);

        let undated = vec![vuln("MAL-2026-0004", "", None)];
        let outcome = outcome_from_vulns(
            &target(Some("9.9.9")),
            &undated,
            now,
            DEFAULT_COOLDOWN_HOURS,
        );
        let CheckOutcome::Flagged { reasons } = outcome else {
            panic!("expected flagged");
        };
        assert!(!reasons[0].within_cooldown);
    }

    #[test]
    fn malicious_outranks_vulnerable_in_ordering() {
        let now = Utc::now();
        let vulns = vec![
            vuln("GHSA-xxxx-yyyy-zzzz", "vuln", Some(now - Duration::days(1))),
            vuln("MAL-2026-0005", "malware", Some(now - Duration::days(5))),
        ];
        let outcome =
            outcome_from_vulns(&target(Some("1.0.0")), &vulns, now, DEFAULT_COOLDOWN_HOURS);
        let CheckOutcome::Flagged { reasons } = outcome else {
            panic!("expected flagged");
        };
        assert_eq!(
            reasons[0].kind,
            VerdictKind::Malicious,
            "malicious must sort ahead of a newer vulnerable advisory"
        );
    }

    #[test]
    fn unknown_ecosystem_and_unknown_outcome_never_flag() {
        let result = result(CheckOutcome::Unknown {
            reason: "offline".to_string(),
        });
        assert!(!result.is_flagged());
        assert_eq!(result.exit_code(), 0, "unknown fails open");
    }
}
