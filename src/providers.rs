//! The online advisory fan-out: the pluggable [`IntelSource`] registry.
//!
//! Each advisory/malware backend (OSV.dev, npm audit, PyPI, GitHub advisories,
//! the Arch security tracker) is one [`IntelSource`] registered in
//! [`INTEL_SOURCES`]; adding a feed is one struct + one line. Every source is
//! an original public database; there is no husk-curated feed in the path.
//! Sources are queried concurrently under a shared wall-clock budget, and each
//! degrades to a [`ProviderStatus`](crate::model::ProviderStatus) row on
//! failure; one slow or broken source never stalls or aborts the scan.
//! Queries send package coordinates (ecosystem/name/version) only, never
//! file contents or paths.
//!
//! Per-URL responses are served from the TTL'd [`KvCache`] (the same store the
//! KEV/EPSS feeds use), so a rescan minutes after a dependency fix pays
//! network only for the coordinates the fix changed. The batch queries (OSV
//! querybatch, npm audit bulk) are always fetched fresh: they are one request
//! each, and they are where new-advisory matching must not lag.

use crate::cache::KvCache;
use crate::model::{Finding, PackageRef, ProviderStatus, Severity};
use crate::rule::{Category, RuleId};
use futures::future::{BoxFuture, join_all};
use futures::{StreamExt, stream};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

/// One advisory / malware backend. The symmetric counterpart to a
/// [`crate::scan::targets::ScanTarget`]: a `ScanTarget` turns files into
/// package coordinates, an `IntelSource` turns coordinates into findings.
///
/// Adding a new intel source (a non-OSV distro tracker, a malware feed, an
/// internal advisory DB) is a local change: write the query function and add
/// one entry to [`INTEL_SOURCES`]. The fan-out in [`query_all`] picks it up
/// automatically; no other edits.
pub struct IntelSource {
    /// The source's one canonical display name. [`query_all`] stamps it onto
    /// the provider-status row, so per-source query functions never repeat it.
    pub name: &'static str,
    /// Query the subset of `packages` this source covers. Must be non-fatal:
    /// network/parse errors degrade to a status row, never a panic, so one
    /// source failing never aborts the others. The cache accelerates per-URL
    /// fetches; `None` (unopenable store) just means every fetch is fresh.
    query: SourceQuery,
}

type SourceQuery = for<'a> fn(
    &'a Client,
    &'a [PackageRef],
    Option<&'a Arc<KvCache>>,
) -> BoxFuture<'a, SingleProviderResult>;

/// The default advisory/malware fan-out, wired in one declarative table.
/// Order is cosmetic (results are aggregated); concurrency is handled by
/// [`query_all`].
pub const INTEL_SOURCES: &[IntelSource] = &[
    IntelSource {
        name: "OSV.dev",
        query: |client, packages, cache| Box::pin(query_osv(client, packages, cache)),
    },
    IntelSource {
        name: "npm audit",
        query: |client, packages, _| Box::pin(query_npm_audit(client, packages)),
    },
    IntelSource {
        name: "PyPI JSON",
        query: |client, packages, cache| Box::pin(query_pypi(client, packages, cache)),
    },
    IntelSource {
        name: "GitHub Advisory Database",
        query: |client, packages, cache| Box::pin(query_github_advisories(client, packages, cache)),
    },
    IntelSource {
        name: ARCH_SECURITY_NAME,
        query: |client, packages, cache| Box::pin(query_arch_security(client, packages, cache)),
    },
];

/// Canonical display name of the Arch Linux security tracker source, used for
/// both its status row and its finding `source` attribution.
const ARCH_SECURITY_NAME: &str = "Arch Security";

/// Shared wall-clock budget: the per-request timeout of the provider HTTP
/// client, so one slow source never stalls the scan indefinitely.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(12);

/// How long a cached per-URL provider response is served before a re-fetch.
/// Short enough that new advisory data lands within the hour; long enough
/// that the rescan right after a one-package fix re-pays network only for
/// the coordinate the fix changed.
const INTEL_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// Cap on unique coordinates queried against GitHub's unauthenticated
/// advisories API (one request per coordinate; the unauthenticated rate limit
/// is 60 requests/hour, so going higher trips 403s mid-scan).
const GITHUB_UNAUTH_PACKAGE_CAP: usize = 30;

/// Cap on unique coordinates queried against PyPI's per-release JSON API
/// (one request per coordinate; the cap bounds scan time on machines with
/// hundreds of virtualenv packages).
const PYPI_PACKAGE_CAP: usize = 80;

pub struct ProviderResult {
    pub findings: Vec<Finding>,
    pub statuses: Vec<ProviderStatus>,
}

pub async fn query_all(packages: &[PackageRef]) -> ProviderResult {
    let client = match Client::builder()
        .timeout(PROVIDER_TIMEOUT)
        .user_agent(format!("husk/{}", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return ProviderResult {
                findings: Vec::new(),
                statuses: vec![ProviderStatus {
                    name: "provider client".to_string(),
                    ok: false,
                    checked_packages: packages.len(),
                    findings: 0,
                    message: err.to_string(),
                }],
            };
        }
    };

    // Same posture as the KEV/EPSS cache: opening is SQLite I/O (blocking
    // pool), and an unopenable cache is no acceleration, never a scan failure.
    let cache = tokio::task::spawn_blocking(|| KvCache::open().ok().map(Arc::new))
        .await
        .ok()
        .flatten();

    let results = join_all(
        INTEL_SOURCES
            .iter()
            .map(|source| (source.query)(&client, packages, cache.as_ref())),
    )
    .await;

    let mut all_findings = Vec::new();
    let mut statuses = Vec::new();
    for (source, result) in INTEL_SOURCES.iter().zip(results) {
        let finding_count = result.findings.len();
        all_findings.extend(result.findings);
        statuses.push(ProviderStatus {
            name: source.name.to_string(),
            ok: result.ok,
            checked_packages: result.checked,
            findings: finding_count,
            message: result.message,
        });
    }

    ProviderResult {
        findings: all_findings,
        statuses,
    }
}

/// The result of querying a single [`IntelSource`]: the findings it produced
/// plus what the status row should say. The row's `name` is owned by the
/// source's [`IntelSource::name`], stamped on by [`query_all`].
pub struct SingleProviderResult {
    pub findings: Vec<Finding>,
    pub ok: bool,
    pub checked: usize,
    pub message: String,
}

fn provider_ok(
    checked: usize,
    findings: Vec<Finding>,
    message: impl Into<String>,
) -> SingleProviderResult {
    SingleProviderResult {
        findings,
        ok: true,
        checked,
        message: message.into(),
    }
}

fn provider_err(
    checked: usize,
    findings: Vec<Finding>,
    message: impl Into<String>,
) -> SingleProviderResult {
    SingleProviderResult {
        findings,
        ok: false,
        checked,
        message: message.into(),
    }
}

/// The four ways a provider HTTP call fails. Its `Display` is the status-row
/// phrasing every intel source shares, so the wording lives in exactly one
/// place.
#[derive(Debug)]
pub(crate) enum FetchError {
    Request(reqwest::Error),
    Http(reqwest::StatusCode),
    Parse(serde_json::Error),
    BodyTooLarge,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Request(err) => write!(f, "request failed: {err}"),
            FetchError::Http(status) => write!(f, "HTTP {status}"),
            FetchError::Parse(err) => write!(f, "invalid response: {err}"),
            FetchError::BodyTooLarge => {
                write!(f, "response body exceeded {MAX_PROVIDER_JSON_BYTES} bytes")
            }
        }
    }
}

/// Hard cap on a single provider JSON response body. Generous for the
/// largest known payload (Arch's `all.json` is a few MB) while still bounding
/// memory against a misbehaving or malicious server: `reqwest::Response::json`
/// has no built-in limit and will buffer an arbitrarily large body.
const MAX_PROVIDER_JSON_BYTES: usize = 64 * 1024 * 1024;

/// Send `request` and return its raw body: the one send → status-check →
/// bounded-read ladder every reqwest consumer in the crate shares (the intel
/// sources here, the KEV/EPSS fetches in [`crate::prioritize`]). The chunked
/// read caps the body at [`MAX_PROVIDER_JSON_BYTES`]; `reqwest`'s own
/// `bytes()`/`json()` buffer an arbitrarily large response.
pub(crate) async fn fetch_body(request: reqwest::RequestBuilder) -> Result<Vec<u8>, FetchError> {
    fetch_body_capped(request, MAX_PROVIDER_JSON_BYTES).await
}

/// Cap-parameterized body of [`fetch_body`]: the seam that lets a unit test
/// exercise the size-cap rejection with a tiny cap instead of a 64 MiB body.
async fn fetch_body_capped(
    request: reqwest::RequestBuilder,
    cap: usize,
) -> Result<Vec<u8>, FetchError> {
    let mut response = request.send().await.map_err(FetchError::Request)?;
    let status = response.status();
    if !status.is_success() {
        return Err(FetchError::Http(status));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(FetchError::Request)? {
        if body.len() + chunk.len() > cap {
            return Err(FetchError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// [`fetch_body`] + JSON parse. Per-provider headers, query params, and bodies
/// stay with the caller on the `RequestBuilder`; per-provider status handling
/// (e.g. GitHub's 403/429 rate-limit case) matches on [`FetchError::Http`].
pub(crate) async fn fetch_json<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
) -> Result<T, FetchError> {
    let body = fetch_body(request).await?;
    serde_json::from_slice(&body).map_err(FetchError::Parse)
}

/// Run one [`KvCache`] operation on the blocking pool: its SQLite I/O must
/// never stall the async executor. A failed join is just a cache miss.
pub(crate) async fn cache_blocking<T: Send + 'static>(
    cache: &Arc<KvCache>,
    op: impl FnOnce(&KvCache) -> T + Send + 'static,
) -> Option<T> {
    let cache = Arc::clone(cache);
    tokio::task::spawn_blocking(move || op(&cache)).await.ok()
}

/// [`fetch_json`] with the TTL'd [`KvCache`] in front, keyed by `key` (the
/// request URL). Only a body that parsed as `T` is stored, so a transient
/// garbage response can never stick for the TTL; every cache failure (open,
/// read, stale, unparseable stored body) is a plain miss.
async fn fetch_json_cached<T: serde::de::DeserializeOwned>(
    cache: Option<&Arc<KvCache>>,
    key: &str,
    request: reqwest::RequestBuilder,
) -> Result<T, FetchError> {
    if let Some(cache) = cache {
        let stored = {
            let key = key.to_string();
            cache_blocking(cache, move |c| c.get_fresh(&key, INTEL_CACHE_TTL)).await
        }
        .flatten();
        if let Some(parsed) = stored.and_then(|body| serde_json::from_slice(&body).ok()) {
            return Ok(parsed);
        }
    }
    let body = fetch_body(request).await?;
    let parsed = serde_json::from_slice(&body).map_err(FetchError::Parse)?;
    if let Some(cache) = cache {
        let key = key.to_string();
        let _ = cache_blocking(cache, move |c| c.put(&key, &body)).await;
    }
    Ok(parsed)
}

async fn query_osv(
    client: &Client,
    packages: &[PackageRef],
    cache: Option<&Arc<KvCache>>,
) -> SingleProviderResult {
    // Carry each package's OSV ecosystem through the filter so the query body
    // can never fall back to a silent empty-string ecosystem.
    let eligible = packages
        .iter()
        .filter_map(|package| {
            package
                .osv_ecosystem()
                .map(|ecosystem| (package.clone(), ecosystem))
        })
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return provider_ok(0, Vec::new(), "no supported packages discovered");
    }

    let mut findings = Vec::new();
    let mut matches: Vec<(PackageRef, String)> = Vec::new();
    let mut checked = 0;

    for chunk in eligible.chunks(1000) {
        checked += chunk.len();
        let queries = chunk
            .iter()
            .map(|(package, ecosystem)| {
                let mut query = json!({
                    "package": {
                        "name": package.name,
                        "ecosystem": ecosystem,
                    }
                });
                // A version-less coordinate queries by name alone (an explicit
                // any-version query, not a bogus exact-"" one); the response is
                // then filtered by `osv_match_applies`.
                if !package.version.is_empty() {
                    query["version"] = json!(package.version);
                }
                query
            })
            .collect::<Vec<_>>();

        let parsed = match fetch_json::<OsvBatchResponse>(
            client
                .post("https://api.osv.dev/v1/querybatch")
                .json(&json!({ "queries": queries })),
        )
        .await
        {
            Ok(parsed) => parsed,
            Err(err) => {
                return provider_err(checked, osv_minimal_findings(matches), err.to_string());
            }
        };

        for (idx, result) in parsed.results.into_iter().enumerate() {
            let Some((package, _)) = chunk.get(idx) else {
                continue;
            };
            for vuln in result.vulns {
                if osv_match_applies(package, &vuln.id) {
                    matches.push((package.clone(), vuln.id));
                }
            }
        }
    }

    // querybatch is deliberately minimal (`{id, modified}` per vuln), so fetch
    // each matched advisory's details once; that's where the summary,
    // severity, references, and the `affected` fixed versions (the one-click
    // upgrade/downgrade target) live. A failed detail fetch degrades to the
    // minimal finding, never an error.
    let mut ids = matches.iter().map(|(_, id)| id.clone()).collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    let details: HashMap<String, OsvVuln> = stream::iter(ids)
        .map(|id| async move {
            let url = format!("https://api.osv.dev/v1/vulns/{id}");
            let vuln = fetch_json_cached::<OsvVuln>(cache, &url, client.get(&url))
                .await
                .ok()?;
            Some((id, vuln))
        })
        .buffer_unordered(8)
        .filter_map(|entry| async move { entry })
        .collect()
        .await;

    for (package, id) in matches {
        let vuln = details
            .get(&id)
            .cloned()
            .unwrap_or_else(|| OsvVuln::minimal(id));
        findings.push(osv_finding(&package, vuln));
    }

    // Advisory data can lag a registry-side "bad release" deprecation: OSV
    // said a version was fixed, but the registry has since flagged that exact
    // version bad (e.g. superseded within a day by a real fix). Never point
    // the one-click dependency fix at a release npm itself calls out as bad.
    patch_npm_deprecated_targets(client, cache, &mut findings).await;

    provider_ok(
        checked,
        findings,
        "queried /v1/querybatch + /v1/vulns for exact package versions",
    )
}

/// Whether an OSV advisory match may become a finding for this package.
///
/// A version-less coordinate (an unpinned `npx` MCP server, a notebook import,
/// a `latest` winget entry) queried by name returns OSV's ENTIRE advisory
/// history for the package; rendering those as exact-version findings is a
/// false-positive storm. So without a version, only malicious-package records
/// (OSV `MAL-` ids) apply: any version of a malicious name is a no. This is
/// the same rule `husk check` uses for a version-less target.
fn osv_match_applies(package: &PackageRef, advisory_id: &str) -> bool {
    !package.version.is_empty() || advisory_id.to_ascii_uppercase().starts_with("MAL-")
}

#[derive(Debug, Deserialize)]
struct NpmAbbreviatedDoc {
    #[serde(default)]
    versions: BTreeMap<String, NpmAbbreviatedVersion>,
}

#[derive(Debug, Deserialize)]
struct NpmAbbreviatedVersion {
    #[serde(default)]
    deprecated: Option<String>,
}

/// Fetch npm's lightweight "abbreviated" packument (the same shape npm/yarn/
/// pnpm themselves use for resolution), small enough to fetch per package
/// without materially slowing a scan, and it carries each version's
/// `deprecated` message when the registry has flagged that release bad.
async fn fetch_npm_abbreviated(
    client: &Client,
    cache: Option<&Arc<KvCache>>,
    name: &str,
) -> Option<NpmAbbreviatedDoc> {
    // Scoped packages (`@scope/pkg`) need the `/` percent-encoded in the
    // registry path; otherwise it reads as two path segments.
    let path = name.replacen('/', "%2f", 1);
    let url = format!("https://registry.npmjs.org/{path}");
    fetch_json_cached::<NpmAbbreviatedDoc>(
        cache,
        &url,
        client
            .get(&url)
            .header("Accept", "application/vnd.npm.install-v1+json"),
    )
    .await
    .ok()
}

/// If `target` is deprecated per `doc`, walk forward to the nearest *higher*
/// published version that isn't; never sideways/down, so this only ever
/// swaps one safe recommendation for a newer one. Falls back to `target`
/// unchanged if every later version is also flagged (or none exist).
fn resolve_safe_npm_target(target: &str, doc: &NpmAbbreviatedDoc) -> String {
    let is_deprecated = |v: &str| doc.versions.get(v).is_some_and(|e| e.deprecated.is_some());
    if !is_deprecated(target) {
        return target.to_string();
    }
    doc.versions
        .keys()
        .filter(|v| crate::version::naive_vercmp(v, target) == std::cmp::Ordering::Greater)
        .filter(|v| !is_deprecated(v))
        .min_by(|a, b| crate::version::naive_vercmp(a, b))
        .cloned()
        .unwrap_or_else(|| target.to_string())
}

/// Re-check every npm finding's `fixed_version` against the registry's
/// deprecation flag, fetching each distinct package's abbreviated packument
/// at most once. Best-effort: a failed fetch leaves that package's findings
/// untouched rather than erroring the whole provider.
async fn patch_npm_deprecated_targets(
    client: &Client,
    cache: Option<&Arc<KvCache>>,
    findings: &mut [Finding],
) {
    let mut names: Vec<String> = findings
        .iter()
        .filter(|f| f.fixed_version.is_some())
        .filter_map(|f| {
            f.package
                .as_ref()
                .filter(|p| p.ecosystem == "npm")
                .map(|p| p.name.clone())
        })
        .collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        return;
    }

    let docs: HashMap<String, NpmAbbreviatedDoc> = stream::iter(names)
        .map(|name| async move {
            let doc = fetch_npm_abbreviated(client, cache, &name).await?;
            Some((name, doc))
        })
        .buffer_unordered(8)
        .filter_map(|entry| async move { entry })
        .collect()
        .await;

    for finding in findings.iter_mut() {
        let Some(package) = &finding.package else {
            continue;
        };
        if package.ecosystem != "npm" {
            continue;
        }
        let Some(target) = &finding.fixed_version else {
            continue;
        };
        let Some(doc) = docs.get(&package.name) else {
            continue;
        };
        let resolved = resolve_safe_npm_target(target, doc);
        if &resolved != target {
            finding.fixed_version = Some(resolved);
        }
    }
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvQueryResult>,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    database_specific: serde_json::Value,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvAffected {
    package: Option<OsvAffectedPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvAffectedPackage {
    name: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}

/// The safe version the one-click dependency fix moves to, picked from the
/// advisory's `fixed` events for this package (nearest upgrade, else nearest
/// downgrade; see [`crate::version::pick_fix_version`]). `None` when the advisory
/// names no fixed release (e.g. unremediated malware: remove instead).
fn osv_fixed_version(package: &PackageRef, affected: &[OsvAffected]) -> Option<String> {
    crate::version::pick_fix_version(
        &package.version,
        affected
            .iter()
            .filter(|a| {
                a.package
                    .as_ref()
                    .map(|p| p.name.eq_ignore_ascii_case(&package.name))
                    .unwrap_or(true)
            })
            .flat_map(|a| a.ranges.iter())
            .flat_map(|r| r.events.iter())
            .filter_map(|e| e.fixed.as_deref()),
    )
}

#[derive(Clone, Debug, Deserialize)]
struct OsvReference {
    url: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvSeverity {
    score: String,
}

impl OsvVuln {
    /// The shape querybatch returns (id only), used when the detail fetch for
    /// an advisory failed, so the finding still exists with generic text.
    fn minimal(id: String) -> Self {
        Self {
            id,
            summary: None,
            details: None,
            aliases: Vec::new(),
            references: Vec::new(),
            database_specific: serde_json::Value::Null,
            severity: Vec::new(),
            affected: Vec::new(),
        }
    }
}

/// Degrade matched advisories to minimal findings when a querybatch chunk
/// errors out mid-run (matches from earlier chunks are still reported).
fn osv_minimal_findings(matches: Vec<(PackageRef, String)>) -> Vec<Finding> {
    matches
        .into_iter()
        .map(|(package, id)| osv_finding(&package, OsvVuln::minimal(id)))
        .collect()
}

/// Build a finding from a raw OSV record (JSON text), the seam the local
/// advisory mirror uses so mirror-served findings are byte-identical in shape
/// to live-query findings: same severity mapping, malware classification,
/// fixed-version extraction, and id scheme.
pub(crate) fn finding_from_osv_record(package: &PackageRef, record: &str) -> Option<Finding> {
    let vuln: OsvVuln = serde_json::from_str(record).ok()?;
    Some(osv_finding(package, vuln))
}

/// Whether an OSV advisory id may become a finding for this coordinate; the
/// versionless rule shared by the live query path, `husk check`, and the
/// local mirror.
pub(crate) fn osv_advisory_applies(package: &PackageRef, advisory_id: &str) -> bool {
    osv_match_applies(package, advisory_id)
}

fn osv_finding(package: &PackageRef, vuln: OsvVuln) -> Finding {
    let summary = vuln
        .summary
        .clone()
        .or_else(|| vuln.details.clone().map(|details| first_sentence(&details)))
        .unwrap_or_else(|| "Vulnerability matched this exact package version.".to_string());
    let severity = osv_severity(&vuln, &summary);
    // OSV's MAL- namespace is its malicious-package feed: an honest malware
    // category, not a vulnerability.
    let category = if vuln.id.to_ascii_uppercase().starts_with("MAL-") {
        Category::Malware
    } else {
        Category::Vulnerability
    };
    let mut references = vuln
        .references
        .into_iter()
        .map(|reference| reference.url)
        .collect::<Vec<_>>();
    references.push(format!("https://osv.dev/vulnerability/{}", vuln.id));

    let aliases = if vuln.aliases.is_empty() {
        String::new()
    } else {
        format!(" ({})", vuln.aliases.join(", "))
    };
    // Structured CVE identity: the advisory's own id (when it IS a CVE) plus
    // its aliases. `with_cves` keeps only CVE-shaped ids, normalized.
    let cves = std::iter::once(vuln.id.clone()).chain(vuln.aliases.iter().cloned());

    Finding::new(
        format!("osv:{}:{}", vuln.id, package.key()),
        format!("{} affects {}{}", vuln.id, package.name, aliases),
        severity,
        category,
        "OSV.dev",
        Some(package.manifest_path.clone()),
        package.line,
        summary,
        Some(format!("{} {}@{}", package.ecosystem, package.name, package.version)),
        "Upgrade to a fixed version, remove the package, or confirm the advisory does not apply to this local use.",
    )
    .rule(RuleId::owned(format!("osv:{}", vuln.id)))
    .with_package(package.clone())
    .with_references(references)
    .with_fixed_version(osv_fixed_version(package, &vuln.affected))
    .with_cves(cves)
}

fn osv_severity(vuln: &OsvVuln, summary: &str) -> Severity {
    let summary_lower = summary.to_ascii_lowercase();
    if vuln.id.to_ascii_uppercase().starts_with("MAL-") || summary_lower.contains("malicious") {
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

async fn query_npm_audit(client: &Client, packages: &[PackageRef]) -> SingleProviderResult {
    let mut package_by_name: BTreeMap<String, Vec<PackageRef>> = BTreeMap::new();
    // Version-less coordinates are skipped: this source is vulnerability-only
    // and its advisories are version ranges; with no version to compare there
    // is nothing honest to report (malware verdicts come from the malware
    // sources, which match version-independently).
    for package in packages
        .iter()
        .filter(|package| package.ecosystem == "npm" && !package.version.is_empty())
    {
        package_by_name
            .entry(package.name.clone())
            .or_default()
            .push(package.clone());
    }

    if package_by_name.is_empty() {
        return provider_ok(0, Vec::new(), "no npm packages discovered");
    }

    // The bulk endpoint takes `{name: [versions...]}`; derive the sorted,
    // deduped version lists from the package map at request-build time.
    let request_body: BTreeMap<&str, Vec<&str>> = package_by_name
        .iter()
        .map(|(name, packages)| {
            let mut versions = packages
                .iter()
                .map(|package| package.version.as_str())
                .collect::<Vec<_>>();
            versions.sort_unstable();
            versions.dedup();
            (name.as_str(), versions)
        })
        .collect();
    let checked = package_by_name.len();

    let parsed = match fetch_json::<HashMap<String, Vec<NpmAdvisory>>>(
        client
            .post("https://registry.npmjs.org/-/npm/v1/security/advisories/bulk")
            .json(&request_body),
    )
    .await
    {
        Ok(parsed) => parsed,
        Err(err) => return provider_err(checked, Vec::new(), err.to_string()),
    };

    let mut findings = Vec::new();
    for (name, advisories) in parsed {
        let Some(local_packages) = package_by_name.get(&name) else {
            continue;
        };
        for advisory in advisories {
            // The bulk response is keyed by NAME only; an advisory must not
            // attach to a local copy whose version is outside the advisory's
            // vulnerable range (a patched lodash@4.17.21 next to a vulnerable
            // 3.x must not get flagged).
            for package in local_packages {
                if npm_range_matches(&package.version, &advisory.vulnerable_versions) {
                    findings.push(npm_finding(package, &advisory));
                }
            }
        }
    }

    provider_ok(
        checked,
        findings,
        "queried public npm registry advisory bulk endpoint",
    )
}

/// True when `version` falls inside an npm-audit `vulnerable_versions` range,
/// a node-semver range set: `||`-separated alternatives of space-separated
/// comparators (`<1.2.3`, `>=2.0.0 <2.1.5`, `*`), including hyphen ranges
/// (`1.2.3 - 2.3.4`) and operators spaced from their version (`< 1.2.3`).
/// Shapes this parser can't read (wildcard segments, tags, dangling
/// operators/hyphens) fail OPEN: an unknown range can only over-report,
/// never silently hide a real advisory.
fn npm_range_matches(version: &str, range: &str) -> bool {
    let range = range.trim();
    if range.is_empty() || range == "*" {
        return true;
    }
    range.split("||").any(|alternative| {
        let Some(comparators) = npm_comparator_set(alternative) else {
            return true; // unreadable alternative: fail open
        };
        !comparators.is_empty()
            && comparators
                .iter()
                .all(|comparator| npm_comparator_matches(version, comparator))
    })
}

/// Desugar one `||` alternative into its AND-combined comparator list: joins a bare
/// operator token to the version that follows it (`< 1.2.3` → `<1.2.3`) and
/// expands a hyphen range into its inclusive bounds (`1.2.3 - 2.3.4` →
/// `>=1.2.3 <=2.3.4`). `None` = a malformed shape (dangling operator or
/// hyphen) the caller fails open on.
fn npm_comparator_set(alternative: &str) -> Option<Vec<String>> {
    let tokens = alternative.split_whitespace().collect::<Vec<_>>();
    let mut comparators: Vec<String> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "-" => {
                let low = comparators.pop()?;
                if low.starts_with(['<', '>', '=']) || i + 1 >= tokens.len() {
                    return None;
                }
                comparators.push(format!(">={low}"));
                comparators.push(format!("<={}", tokens[i + 1]));
                i += 2;
            }
            op @ ("<" | "<=" | ">" | ">=" | "=") => {
                comparators.push(format!("{op}{}", tokens.get(i + 1)?));
                i += 2;
            }
            token => {
                comparators.push(token.to_string());
                i += 1;
            }
        }
    }
    Some(comparators)
}

fn npm_comparator_matches(version: &str, comparator: &str) -> bool {
    use std::cmp::Ordering;
    let (op, target) = ["<=", ">=", "<", ">", "="]
        .iter()
        .find_map(|op| comparator.strip_prefix(op).map(|rest| (*op, rest)))
        .unwrap_or(("=", comparator));
    // Wildcard / non-numeric targets (`*`, `1.x`, a dist-tag): fail open.
    let target = target.trim();
    let bare = target.strip_prefix(['v', 'V']).unwrap_or(target);
    if !bare.starts_with(|c: char| c.is_ascii_digit())
        || bare
            .split(['.', '-'])
            .any(|segment| matches!(segment, "x" | "X" | "*"))
    {
        return true;
    }
    let ordering = crate::version::naive_vercmp(version, target);
    match op {
        "<" => ordering == Ordering::Less,
        "<=" => ordering != Ordering::Greater,
        ">" => ordering == Ordering::Greater,
        ">=" => ordering != Ordering::Less,
        _ => ordering == Ordering::Equal,
    }
}

#[derive(Debug, Deserialize)]
struct NpmAdvisory {
    id: serde_json::Value,
    title: String,
    severity: String,
    url: Option<String>,
    #[serde(default)]
    vulnerable_versions: String,
}

fn npm_finding(package: &PackageRef, advisory: &NpmAdvisory) -> Finding {
    let id = advisory
        .id
        .as_i64()
        .map(|id| id.to_string())
        .or_else(|| advisory.id.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());
    let references = advisory.url.clone().into_iter().collect::<Vec<_>>();
    Finding::new(
        format!("npm-audit:{id}:{}", package.key()),
        advisory.title.clone(),
        Severity::from_external(&advisory.severity),
        Category::Vulnerability,
        "npm audit",
        Some(package.manifest_path.clone()),
        package.line,
        format!(
            "{}@{} matches npm advisory {}. Vulnerable range: {}",
            package.name, package.version, id, advisory.vulnerable_versions
        ),
        Some(format!("npm {}@{}", package.name, package.version)),
        "Upgrade to a non-vulnerable version or remove the dependency.",
    )
    .rule(RuleId::owned(format!("npm-audit:{id}")))
    .with_package(package.clone())
    .with_references(references)
}

/// Group packages by unique `(name, version)` coordinate so a per-coordinate
/// cap covers as many real coordinates as possible: the same package pinned in
/// ten manifests costs one request, and its findings fan back out to every
/// local occurrence.
fn unique_coordinates(packages: Vec<PackageRef>) -> Vec<(PackageRef, Vec<PackageRef>)> {
    let mut grouped: BTreeMap<(String, String, String), Vec<PackageRef>> = BTreeMap::new();
    for package in packages {
        grouped
            .entry((
                package.ecosystem.clone(),
                package.name.clone(),
                package.version.clone(),
            ))
            .or_default()
            .push(package);
    }
    grouped
        .into_values()
        .map(|occurrences| (occurrences[0].clone(), occurrences))
        .collect()
}

/// The honest status message for a capped per-coordinate provider: says how
/// much of the eligible set was actually checked when the cap truncated it.
fn capped_message(default: &str, checked: usize, total: usize, why: &str) -> String {
    if checked < total {
        format!("checked first {checked} of {total} unique coordinates ({why})")
    } else {
        default.to_string()
    }
}

async fn query_pypi(
    client: &Client,
    packages: &[PackageRef],
    cache: Option<&Arc<KvCache>>,
) -> SingleProviderResult {
    // Per-RELEASE lookups: a version-less coordinate has no release to query
    // (`/pypi/<name>//json` is a guaranteed 404), so it is skipped.
    let eligible = packages
        .iter()
        .filter(|package| package.ecosystem == "pypi" && !package.version.is_empty())
        .cloned()
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return provider_ok(0, Vec::new(), "no PyPI packages discovered");
    }

    let coordinates = unique_coordinates(eligible);
    let total = coordinates.len();
    let queried = coordinates
        .into_iter()
        .take(PYPI_PACKAGE_CAP)
        .collect::<Vec<_>>();
    let checked = queried.len();

    let results =
        stream::iter(queried)
            .map(|(representative, occurrences)| {
                let client = client.clone();
                let cache = cache.map(Arc::clone);
                async move {
                    query_one_pypi(&client, cache.as_ref(), representative, &occurrences).await
                }
            })
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;

    let mut findings = Vec::new();
    let mut failures = 0;
    let mut first_error = None;
    for result in results {
        match result {
            Ok(mut lookup_findings) => findings.append(&mut lookup_findings),
            Err(err) => {
                failures += 1;
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }

    pypi_status(checked, total, failures, first_error, findings)
}

/// The honest status row for the PyPI fan-out. Every lookup failing means the
/// provider itself failed (machine offline, PyPI down) and must show red like
/// the other sources do; a partial failure stays green but says how many
/// lookups were lost; zero failures reports normally (with the cap note).
fn pypi_status(
    checked: usize,
    total: usize,
    failures: usize,
    first_error: Option<String>,
    findings: Vec<Finding>,
) -> SingleProviderResult {
    let error = first_error.unwrap_or_default();
    if failures > 0 && failures == checked {
        return provider_err(checked, findings, error);
    }
    if failures > 0 {
        return provider_ok(
            checked,
            findings,
            format!("{failures} of {checked} lookups failed ({error})"),
        );
    }
    provider_ok(
        checked,
        findings,
        capped_message(
            "queried per-release PyPI JSON vulnerability metadata",
            checked,
            total,
            "per-package request cost cap",
        ),
    )
}

async fn query_one_pypi(
    client: &Client,
    cache: Option<&Arc<KvCache>>,
    representative: PackageRef,
    occurrences: &[PackageRef],
) -> Result<Vec<Finding>, String> {
    let url = format!(
        "https://pypi.org/pypi/{}/{}/json",
        urlencoding::encode(&representative.name),
        urlencoding::encode(&representative.version)
    );
    let parsed = match fetch_json_cached::<PypiRelease>(cache, &url, client.get(&url)).await {
        Ok(parsed) => parsed,
        // Not every local Python package lives on PyPI (private indexes,
        // internal wheels, yanked releases): a 404 is "nothing to say about
        // this coordinate", not a provider failure.
        Err(FetchError::Http(status)) if status == reqwest::StatusCode::NOT_FOUND => {
            return Ok(Vec::new());
        }
        Err(err) => return Err(err.to_string()),
    };
    Ok(parsed
        .vulnerabilities
        .into_iter()
        .flat_map(|vuln| {
            occurrences
                .iter()
                .map(|package| pypi_finding(package, &vuln))
                .collect::<Vec<_>>()
        })
        .collect())
}

#[derive(Debug, Deserialize)]
struct PypiRelease {
    #[serde(default)]
    vulnerabilities: Vec<PypiVulnerability>,
}

#[derive(Debug, Deserialize)]
struct PypiVulnerability {
    id: String,
    details: Option<String>,
    summary: Option<String>,
    link: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    fixed_in: Vec<String>,
}

fn pypi_finding(package: &PackageRef, vuln: &PypiVulnerability) -> Finding {
    let references = vuln.link.clone().into_iter().collect::<Vec<_>>();
    let fixed = if vuln.fixed_in.is_empty() {
        "No fixed version listed by PyPI.".to_string()
    } else {
        format!("Fixed in: {}.", vuln.fixed_in.join(", "))
    };
    let alias = if vuln.aliases.is_empty() {
        String::new()
    } else {
        format!(" ({})", vuln.aliases.join(", "))
    };
    Finding::new(
        format!("pypi:{}:{}", vuln.id, package.key()),
        format!("{} affects {}{}", vuln.id, package.name, alias),
        Severity::High,
        Category::Vulnerability,
        "PyPI JSON",
        Some(package.manifest_path.clone()),
        package.line,
        vuln.summary
            .clone()
            .or_else(|| vuln.details.clone())
            .unwrap_or_else(|| format!("{} {}", package.name, fixed)),
        Some(format!("pypi {}@{}", package.name, package.version)),
        "Upgrade to a fixed release or remove the dependency.",
    )
    .rule(RuleId::owned(format!("pypi:{}", vuln.id)))
    .with_package(package.clone())
    .with_references(references)
    .with_fixed_version(crate::version::pick_fix_version(
        &package.version,
        vuln.fixed_in.iter().map(String::as_str),
    ))
    .with_cves(std::iter::once(vuln.id.clone()).chain(vuln.aliases.iter().cloned()))
}

/// Unauthenticated callers get 60 requests/hour, which the package cap alone
/// burns through in two scans. A token raises the ceiling to 5000/hour, enough
/// to drop the cap entirely.
fn github_package_cap(token: Option<&str>, total: usize) -> usize {
    if token.is_some() {
        total
    } else {
        GITHUB_UNAUTH_PACKAGE_CAP.min(total)
    }
}

async fn query_github_advisories(
    client: &Client,
    packages: &[PackageRef],
    cache: Option<&Arc<KvCache>>,
) -> SingleProviderResult {
    let eligible = packages
        .iter()
        .filter(|package| package.github_ecosystem().is_some())
        .cloned()
        .collect::<Vec<_>>();
    if eligible.is_empty() {
        return provider_ok(0, Vec::new(), "no supported packages discovered");
    }

    let coordinates = unique_coordinates(eligible);
    let total = coordinates.len();

    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|token| !token.trim().is_empty());
    let cap = github_package_cap(token.as_deref(), total);

    let mut findings = Vec::new();
    let mut checked = 0;
    for (representative, occurrences) in coordinates.iter().take(cap) {
        checked += 1;
        // Malware-only source: a version-less coordinate queries by bare name
        // (any version of a malicious name is a hit); `name@` would be a
        // malformed spec.
        let affects = if representative.version.is_empty() {
            representative.name.clone()
        } else {
            format!("{}@{}", representative.name, representative.version)
        };
        let url = format!(
            "https://api.github.com/advisories?type=malware&ecosystem={}&affects={}&per_page=100",
            representative.github_ecosystem().unwrap_or(""),
            urlencoding::encode(&affects)
        );
        let mut request = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(token) = &token {
            request = request.bearer_auth(token);
        }
        let parsed = match fetch_json_cached::<Vec<GithubAdvisory>>(cache, &url, request).await {
            Ok(parsed) => parsed,
            Err(FetchError::Http(status)) if status.as_u16() == 403 || status.as_u16() == 429 => {
                return provider_err(
                    checked,
                    findings,
                    if token.is_some() {
                        "rate limited by the GitHub API"
                    } else {
                        "rate limited by GitHub unauthenticated API; set GITHUB_TOKEN to raise the limit"
                    },
                );
            }
            Err(err) => return provider_err(checked, findings, err.to_string()),
        };
        for advisory in parsed {
            for package in occurrences {
                findings.push(github_finding(package, &advisory));
            }
        }
    }

    provider_ok(
        checked,
        findings,
        capped_message(
            "queried global advisories API for malware matches",
            checked,
            total,
            "unauthenticated API rate limit",
        ),
    )
}

#[derive(Debug, Deserialize)]
struct GithubAdvisory {
    ghsa_id: String,
    cve_id: Option<String>,
    summary: String,
    description: Option<String>,
    html_url: String,
    severity: String,
    #[serde(default)]
    identifiers: Vec<GithubIdentifier>,
}

#[derive(Debug, Deserialize)]
struct GithubIdentifier {
    value: String,
}

fn github_finding(package: &PackageRef, advisory: &GithubAdvisory) -> Finding {
    let mut references = vec![advisory.html_url.clone()];
    if let Some(cve) = &advisory.cve_id {
        references.push(format!("https://nvd.nist.gov/vuln/detail/{cve}"));
    }
    for identifier in &advisory.identifiers {
        if identifier.value.starts_with("CVE-") {
            references.push(format!(
                "https://nvd.nist.gov/vuln/detail/{}",
                identifier.value
            ));
        }
    }
    references.sort();
    references.dedup();
    let cves = advisory
        .cve_id
        .iter()
        .cloned()
        .chain(advisory.identifiers.iter().map(|i| i.value.clone()));

    Finding::new(
        format!("github:{}:{}", advisory.ghsa_id, package.key()),
        format!("{} affects {}", advisory.ghsa_id, package.name),
        Severity::from_external(&advisory.severity),
        // This provider queries `type=malware` only (see the request URL).
        Category::Malware,
        "GitHub Advisory Database",
        Some(package.manifest_path.clone()),
        package.line,
        advisory
            .description
            .as_deref()
            .map(first_sentence)
            .unwrap_or_else(|| advisory.summary.clone()),
        Some(format!("{} {}@{}", package.ecosystem, package.name, package.version)),
        "Upgrade to a patched version, remove the package, or investigate the malware advisory before using it.",
    )
    .rule(RuleId::owned(format!("github:{}", advisory.ghsa_id)))
    .with_package(package.clone())
    .with_references(references)
    .with_cves(cves)
}

/// The first sentence of an advisory description, whitespace-collapsed and
/// truncated to at most 280 bytes on a UTF-8 character boundary.
pub(crate) fn first_sentence(value: &str) -> String {
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let sentence_end = collapsed
        .find(". ")
        .map(|idx| idx + 1)
        .unwrap_or(collapsed.len());
    let mut end = sentence_end.min(280);
    while !collapsed.is_char_boundary(end) {
        end -= 1;
    }
    collapsed[..end].to_string()
}

// Arch Linux Security Tracker (non-OSV source). Arch is a rolling release and
// is NOT in OSV, so it needs its own feed: https://security.archlinux.org/all.json
// (an array of Arch Vulnerability Groups, AVGs), each AVG listing affected
// `packages`, a `status` (Vulnerable/Fixed/Testing/Not affected), an optional
// `fixed` version, a `severity`, and `issues` (CVE ids). Pacman coordinates
// (ecosystem id `"arch"`) are matched with pacman's own version comparison.

#[derive(Debug, Deserialize)]
struct ArchGroup {
    name: String,
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    issues: Vec<String>,
}

async fn query_arch_security(
    client: &Client,
    packages: &[PackageRef],
    cache: Option<&Arc<KvCache>>,
) -> SingleProviderResult {
    let arch: Vec<&PackageRef> = packages.iter().filter(|p| p.ecosystem == "arch").collect();
    if arch.is_empty() {
        return provider_ok(0, Vec::new(), "no Arch packages discovered");
    }

    let url = "https://security.archlinux.org/all.json";
    let groups = match fetch_json_cached::<Vec<ArchGroup>>(cache, url, client.get(url)).await {
        Ok(groups) => groups,
        Err(err) => return provider_err(arch.len(), Vec::new(), err.to_string()),
    };

    let mut by_package: HashMap<&str, Vec<&ArchGroup>> = HashMap::new();
    for group in &groups {
        for pkg in &group.packages {
            by_package.entry(pkg.as_str()).or_default().push(group);
        }
    }

    let mut findings = Vec::new();
    for package in &arch {
        let Some(groups) = by_package.get(package.name.as_str()) else {
            continue;
        };
        for group in groups {
            if arch_is_vulnerable(&package.version, group) {
                findings.push(arch_finding(package, group));
            }
        }
    }

    provider_ok(
        arch.len(),
        findings,
        "matched against security.archlinux.org/all.json",
    )
}

/// Decide whether an installed Arch package `version` is vulnerable per an AVG.
/// `Not affected` is always safe; `Fixed` hits only versions older than `fixed`
/// per pacman `vercmp`; any other state (Vulnerable/Testing) has no released
/// fix and hits every installed version.
fn arch_is_vulnerable(version: &str, group: &ArchGroup) -> bool {
    match group.status.as_str() {
        "Not affected" => false,
        "Fixed" => match group.fixed.as_deref() {
            Some(fixed) if !fixed.is_empty() => {
                crate::version::pacman_vercmp(version, fixed) == std::cmp::Ordering::Less
            }
            _ => true,
        },
        _ => true,
    }
}

fn arch_finding(package: &PackageRef, group: &ArchGroup) -> Finding {
    let severity = match group.severity.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    };
    let cves = if group.issues.is_empty() {
        group.name.clone()
    } else {
        group.issues.join(", ")
    };
    let fix = match group.fixed.as_deref() {
        Some(fixed) if !fixed.is_empty() => format!("Upgrade to {fixed} or newer (`pacman -Syu`)."),
        _ => "No fixed release yet; monitor the advisory and consider mitigations.".to_string(),
    };
    Finding::new(
        format!("arch:{}:{}", group.name, package.key()),
        format!("Arch advisory {} affects {}", group.name, package.name),
        severity,
        Category::Vulnerability,
        ARCH_SECURITY_NAME,
        Some(package.manifest_path.clone()),
        package.line,
        format!(
            "{} {} is affected by {} ({}).",
            package.name, package.version, cves, group.name
        ),
        None,
        fix,
    )
    .rule(RuleId::owned(format!("arch:{}", group.name)))
    .with_references(vec![format!(
        "https://security.archlinux.org/{}",
        group.name
    )])
    .with_package((*package).clone())
    .with_cves(group.issues.iter().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn npm_doc(versions: &[(&str, Option<&str>)]) -> NpmAbbreviatedDoc {
        NpmAbbreviatedDoc {
            versions: versions
                .iter()
                .map(|(v, dep)| {
                    (
                        v.to_string(),
                        NpmAbbreviatedVersion {
                            deprecated: dep.map(str::to_string),
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn resolve_safe_npm_target_keeps_clean_target() {
        let doc = npm_doc(&[("4.17.21", None)]);
        assert_eq!(resolve_safe_npm_target("4.17.21", &doc), "4.17.21");
    }

    #[test]
    fn resolve_safe_npm_target_skips_a_deprecated_bad_release() {
        // Advisory data can lag the registry: OSV names a fixed version that
        // npm has since deprecated as a bad release, with the real fix
        // published above it.
        let doc = npm_doc(&[
            ("4.17.21", None),
            (
                "4.18.0",
                Some("Bad release. Please use lodash@4.17.21 instead."),
            ),
            ("4.18.1", None),
        ]);
        assert_eq!(resolve_safe_npm_target("4.18.0", &doc), "4.18.1");
    }

    #[test]
    fn resolve_safe_npm_target_never_recommends_a_downgrade() {
        // Only 4.17.21 (below target) is clean; nothing higher is. It must not
        // step backwards, so it keeps the flagged target rather than downgrade.
        let doc = npm_doc(&[
            ("4.17.21", None),
            ("4.18.0", Some("bad")),
            ("4.18.1", Some("also bad")),
        ]);
        assert_eq!(resolve_safe_npm_target("4.18.0", &doc), "4.18.0");
    }

    #[test]
    fn resolve_safe_npm_target_unknown_version_passes_through() {
        let doc = npm_doc(&[("1.0.0", None)]);
        assert_eq!(resolve_safe_npm_target("9.9.9", &doc), "9.9.9");
    }

    #[test]
    fn osv_fixed_version_picks_nearest_matching_fix() {
        let pkg = |name: &str, version: &str| PackageRef {
            ecosystem: "npm".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: PathBuf::from("/proj/package.json"),
            line: None,
        };
        let vuln: OsvVuln = serde_json::from_value(serde_json::json!({
            "id": "GHSA-x",
            "affected": [
                {
                    "package": { "ecosystem": "npm", "name": "lodash" },
                    "ranges": [
                        // Two streams fixed in the same advisory: the nearest
                        // upgrade for the current version wins, never a jump
                        // to the next major's fix.
                        { "type": "SEMVER", "events": [
                            { "introduced": "0" }, { "fixed": "4.17.21" }
                        ]},
                        { "type": "SEMVER", "events": [
                            { "introduced": "5.0.0-alpha.1" }, { "fixed": "5.0.0-rc.2" }
                        ]}
                    ]
                },
                {
                    "package": { "ecosystem": "npm", "name": "other" },
                    "ranges": [
                        { "type": "SEMVER", "events": [{ "fixed": "9.9.9" }] }
                    ]
                }
            ]
        }))
        .unwrap();
        assert_eq!(
            osv_fixed_version(&pkg("lodash", "4.17.19"), &vuln.affected).as_deref(),
            Some("4.17.21"),
            "nearest upgrade in the current stream wins over a major jump"
        );
        // No fixed events at all (e.g. unremediated malware) -> None.
        let none: OsvVuln = serde_json::from_value(serde_json::json!({
            "id": "MAL-1",
            "affected": [{ "package": { "ecosystem": "npm", "name": "evil" },
                           "versions": ["1.0.0"] }]
        }))
        .unwrap();
        assert_eq!(
            osv_fixed_version(&pkg("evil", "1.0.0"), &none.affected),
            None
        );
    }

    #[test]
    fn versionless_coordinates_match_malware_but_never_version_scoped_advisories() {
        // The unpinned-MCP-server shape: `npx server-foo` emits an npm
        // coordinate with an EMPTY version. OSV queried by name alone returns
        // the package's entire advisory history; none of it may become an
        // "affects this exact version" finding. Malware records still apply:
        // any version of a malicious name is a no.
        let unpinned = PackageRef {
            ecosystem: "npm".to_string(),
            name: "server-foo".to_string(),
            version: String::new(),
            manifest_path: PathBuf::from("/home/u/.mcp.json"),
            line: None,
        };
        assert!(!osv_match_applies(&unpinned, "GHSA-xxxx-yyyy-zzzz"));
        assert!(!osv_match_applies(&unpinned, "CVE-2024-1234"));
        assert!(osv_match_applies(&unpinned, "MAL-2026-0001"));
        assert!(
            osv_match_applies(&unpinned, "mal-2026-0002"),
            "case-insensitive"
        );

        // A pinned coordinate keeps every match (OSV already range-filtered
        // it server-side against the exact version).
        let pinned = PackageRef {
            version: "1.2.3".to_string(),
            ..unpinned
        };
        assert!(osv_match_applies(&pinned, "GHSA-xxxx-yyyy-zzzz"));
        assert!(osv_match_applies(&pinned, "MAL-2026-0001"));
    }

    #[test]
    fn npm_range_matches_respects_vulnerable_versions() {
        // The headline false positive: a patched lodash next to a vulnerable
        // one; the advisory must attach only inside its range.
        assert!(npm_range_matches("3.10.1", "<4.17.21"));
        assert!(!npm_range_matches("4.17.21", "<4.17.21"));
        assert!(npm_range_matches("4.17.20", "<4.17.21"));

        // Compound comparators (AND within an alternative).
        assert!(npm_range_matches("2.0.5", ">=2.0.0 <2.1.5"));
        assert!(!npm_range_matches("2.1.5", ">=2.0.0 <2.1.5"));
        assert!(!npm_range_matches("1.9.9", ">=2.0.0 <2.1.5"));

        // `||` alternatives (OR).
        assert!(npm_range_matches("2.1.6", "<=2.1.6 || >=3.0.0 <3.0.1"));
        assert!(npm_range_matches("3.0.0", "<=2.1.6 || >=3.0.0 <3.0.1"));
        assert!(!npm_range_matches("3.0.1", "<=2.1.6 || >=3.0.0 <3.0.1"));

        assert!(npm_range_matches("1.0.0", "=1.0.0"));
        assert!(npm_range_matches("1.0.0", "1.0.0"));
        assert!(!npm_range_matches("1.0.1", "=1.0.0"));
        assert!(npm_range_matches("9.9.9", "*"));
        assert!(npm_range_matches("9.9.9", ""), "missing range fails open");

        // Hyphen ranges are inclusive bounds (`lo - hi` == `>=lo <=hi`).
        assert!(npm_range_matches("1.2.3", "1.2.3 - 2.3.4"));
        assert!(npm_range_matches("2.0.0", "1.2.3 - 2.3.4"));
        assert!(npm_range_matches("2.3.4", "1.2.3 - 2.3.4"));
        assert!(!npm_range_matches("1.2.2", "1.2.3 - 2.3.4"));
        assert!(!npm_range_matches("2.3.5", "1.2.3 - 2.3.4"));

        // An operator spaced from its version binds to it, alone and in AND combinations.
        assert!(npm_range_matches("1.0.0", "< 1.2.3"));
        assert!(!npm_range_matches("1.2.3", "< 1.2.3"));
        assert!(npm_range_matches("2.5.0", ">= 2.0.0 < 3.0.0"));
        assert!(!npm_range_matches("3.0.0", ">= 2.0.0 < 3.0.0"));

        // Hyphen ranges and spaced comparators mixed with `||` alternatives.
        assert!(npm_range_matches("1.5.0", "1.0.0 - 2.0.0 || >= 3.0.0"));
        assert!(npm_range_matches("3.1.0", "1.0.0 - 2.0.0 || >= 3.0.0"));
        assert!(!npm_range_matches("2.5.0", "1.0.0 - 2.0.0 || >= 3.0.0"));

        // Prereleases order below their release.
        assert!(npm_range_matches("1.0.0-beta.1", "<1.0.0"));

        // Unparseable targets fail OPEN (over-report, never hide).
        assert!(npm_range_matches("1.5.0", "1.x"));
        assert!(npm_range_matches("1.5.0", "<next"));
        // ...including malformed hyphen/operator shapes.
        assert!(npm_range_matches("9.9.9", "- 2.0.0"));
        assert!(npm_range_matches("9.9.9", "1.0.0 -"));
        assert!(npm_range_matches("9.9.9", ">="));
    }

    #[test]
    fn arch_vulnerable_logic() {
        let fixed = ArchGroup {
            name: "AVG-1".into(),
            packages: vec!["openssl".into()],
            status: "Fixed".into(),
            severity: "High".into(),
            fixed: Some("3.0.8-1".into()),
            issues: vec!["CVE-2023-0286".into()],
        };
        assert!(arch_is_vulnerable("3.0.7-1", &fixed));
        assert!(!arch_is_vulnerable("3.0.8-1", &fixed));
        assert!(!arch_is_vulnerable("3.0.9-1", &fixed));

        let unpatched = ArchGroup {
            name: "AVG-2".into(),
            packages: vec!["foo".into()],
            status: "Vulnerable".into(),
            severity: "Critical".into(),
            fixed: None,
            issues: vec![],
        };
        assert!(arch_is_vulnerable("1.0-1", &unpatched));

        let not_affected = ArchGroup {
            name: "AVG-3".into(),
            packages: vec!["bar".into()],
            status: "Not affected".into(),
            severity: "Low".into(),
            fixed: None,
            issues: vec![],
        };
        assert!(!arch_is_vulnerable("1.0-1", &not_affected));
    }

    #[test]
    fn first_sentence_truncates_on_char_boundaries() {
        assert_eq!(first_sentence("Bad crate. Do not use."), "Bad crate.");
        assert_eq!(first_sentence("a\n b\t c"), "a b c");

        // A multibyte character straddling the 280-byte cap must not panic
        // and must be dropped whole. "é" is 2 bytes; place one so it spans
        // bytes 279..281.
        let long = format!("{}é and more text with no sentence break", "x".repeat(279));
        let truncated = first_sentence(&long);
        assert_eq!(truncated, "x".repeat(279));
        assert!(truncated.len() <= 280);

        // An em-dash (3 bytes) across the boundary likewise truncates cleanly.
        let dashed = format!("{}— tail", "y".repeat(278));
        let truncated = first_sentence(&dashed);
        assert_eq!(truncated, "y".repeat(278));
    }

    #[test]
    fn every_source_name_maps_to_a_telemetry_scanner_id() {
        // The status-row name comes from `IntelSource::name` in one place;
        // each must stay in the closed telemetry scanner-id map so
        // `scan_completed` events keep reporting every source that ran.
        for source in INTEL_SOURCES {
            assert!(
                crate::cloud::telemetry::scanner_telemetry_id(source.name).is_some(),
                "{} has no telemetry scanner id",
                source.name
            );
        }
    }

    #[test]
    fn unique_coordinates_dedupe_and_fan_out() {
        let pkg = |eco: &str, name: &str, version: &str, manifest: &str| PackageRef {
            ecosystem: eco.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: PathBuf::from(manifest),
            line: None,
        };
        let coordinates = unique_coordinates(vec![
            pkg("pypi", "requests", "2.31.0", "/a/requirements.txt"),
            pkg("pypi", "requests", "2.31.0", "/b/requirements.txt"),
            pkg("pypi", "requests", "2.30.0", "/c/requirements.txt"),
            // Same (name, version) in a DIFFERENT ecosystem stays distinct;
            // grouping across ecosystems would query one and mis-attribute
            // its advisories to the other.
            pkg("npm", "requests", "2.31.0", "/d/package-lock.json"),
        ]);
        assert_eq!(
            coordinates.len(),
            3,
            "same coordinate collapses; ecosystems never merge"
        );
        let dup = coordinates
            .iter()
            .find(|(rep, _)| rep.ecosystem == "pypi" && rep.version == "2.31.0")
            .expect("deduped coordinate present");
        assert_eq!(dup.1.len(), 2, "both occurrences kept for finding fan-out");
    }

    #[test]
    fn github_cap_lifts_only_with_a_token() {
        assert_eq!(github_package_cap(None, 55), GITHUB_UNAUTH_PACKAGE_CAP);
        assert_eq!(github_package_cap(Some("gho_x"), 55), 55);
        assert_eq!(github_package_cap(None, 7), 7);
    }

    #[test]
    fn capped_message_is_honest_about_truncation() {
        assert_eq!(capped_message("all good", 5, 5, "cap"), "all good");
        assert_eq!(
            capped_message("all good", 30, 500, "unauthenticated API rate limit"),
            "checked first 30 of 500 unique coordinates (unauthenticated API rate limit)"
        );
    }

    #[test]
    fn pypi_status_reports_total_failure_as_provider_error() {
        // Machine offline / PyPI down: every lookup failed. The row must go
        // red like the other sources', not claim the packages were checked.
        let status = pypi_status(
            3,
            3,
            3,
            Some("request failed: connect error".to_string()),
            Vec::new(),
        );
        assert!(!status.ok);
        assert_eq!(status.message, "request failed: connect error");
    }

    #[test]
    fn pypi_status_degrades_honestly_on_partial_failure() {
        let status = pypi_status(10, 10, 3, Some("HTTP 503".to_string()), Vec::new());
        assert!(status.ok);
        assert_eq!(status.message, "3 of 10 lookups failed (HTTP 503)");
    }

    #[test]
    fn pypi_status_reports_normally_when_all_lookups_succeed() {
        let status = pypi_status(5, 5, 0, None, Vec::new());
        assert!(status.ok);
        assert_eq!(
            status.message,
            "queried per-release PyPI JSON vulnerability metadata"
        );
        // The cap note still shows when the coordinate set was truncated.
        let capped = pypi_status(80, 120, 0, None, Vec::new());
        assert!(capped.ok);
        assert!(capped.message.contains("first 80 of 120"));
    }

    /// One-shot loopback HTTP server: serves `body` to the first connection,
    /// then exits. Enough to exercise the fetch ladder without the network.
    fn serve_once(body: &'static [u8]) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            // Drain the request head so the client doesn't see a reset.
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        });
        format!("http://{addr}/")
    }

    fn test_cache(dir: &tempfile::TempDir) -> Arc<KvCache> {
        Arc::new(KvCache::open_at(&dir.path().join("husk.db")).expect("open kv cache"))
    }

    #[tokio::test]
    async fn fetch_json_cached_serves_the_second_call_without_the_network() {
        // `serve_once` answers exactly one connection, so the second call can
        // only succeed if the cache serves it.
        let url = serve_once(br#"{"ok":true}"#);
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = test_cache(&dir);
        let client = Client::new();

        let first: serde_json::Value = fetch_json_cached(Some(&cache), &url, client.get(&url))
            .await
            .expect("first call fetches");
        let second: serde_json::Value = fetch_json_cached(Some(&cache), &url, client.get(&url))
            .await
            .expect("second call must come from cache");
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn fetch_json_cached_never_stores_an_unparseable_body() {
        let url = serve_once(b"not json at all");
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = test_cache(&dir);
        let client = Client::new();

        let err = fetch_json_cached::<serde_json::Value>(Some(&cache), &url, client.get(&url))
            .await
            .expect_err("garbage body must fail to parse");
        assert!(matches!(err, FetchError::Parse(_)));
        assert!(
            cache.get_fresh(&url, INTEL_CACHE_TTL).is_none(),
            "a body that failed to parse must not be cached"
        );
    }

    #[tokio::test]
    async fn fetch_body_rejects_a_body_over_the_cap() {
        let url = serve_once(b"0123456789abcdef");
        let client = Client::new();
        let err = fetch_body_capped(client.get(&url), 8)
            .await
            .expect_err("16-byte body over an 8-byte cap must be rejected");
        assert!(matches!(err, FetchError::BodyTooLarge));
    }

    #[tokio::test]
    async fn fetch_body_returns_a_body_within_the_cap() {
        let url = serve_once(b"ok body");
        let client = Client::new();
        let body = fetch_body_capped(client.get(&url), 64)
            .await
            .expect("body within cap");
        assert_eq!(body, b"ok body");
    }
}
