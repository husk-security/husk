//! Exploit-aware finding prioritization (CISA KEV + FIRST EPSS).
//!
//! A scanner that lists every CVE with equal weight burns the developer's
//! attention budget, the opposite of Husk's "seatbelt, not airport" thesis.
//! This module enriches findings with two free, authoritative exploitation
//! signals and pulls the dangerous ones to the top:
//!
//! - **CISA KEV** (Known Exploited Vulnerabilities): a CVE on this list is
//!   *actively exploited in the wild*. Always fix first.
//! - **FIRST EPSS** (Exploit Prediction Scoring System): a 0-to-1 probability
//!   the CVE will be exploited in the next 30 days.
//!
//! The fetch is best-effort and online; the annotation logic is pure and
//! unit-tested. Offline scans simply skip enrichment (no reordering). Both
//! feeds refresh upstream roughly daily, so fetched results are kept in the
//! [`KvCache`] TTL'd blob store and back-to-back scans skip the network. The
//! cache is a pure accelerator: a miss (absent, stale, or unreadable) plus a
//! network failure degrades to empty intel, never a scan failure.

use crate::cache::KvCache;
use crate::model::{ExploitInfo, Finding};
use crate::providers::cache_blocking;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
/// Cache key for the full CISA KEV catalog body.
const KEV_CACHE_KEY: &str = "intel:kev-catalog";
/// CISA updates the KEV catalog on business days; a day-old copy is fine.
const KEV_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// FIRST recomputes EPSS scores daily; 12h halves the worst-case staleness.
const EPSS_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// Per-CVE cache key for an EPSS score. The body is the score's decimal
/// string; an *empty* body is a negative entry (EPSS has no score for this
/// CVE) so known-absent ids aren't re-queried until the TTL lapses.
fn epss_cache_key(cve: &str) -> String {
    format!("intel:epss:{cve}")
}
/// The "fix soon" EPSS threshold. It is a *reporting* cutoff used by the scan
/// summaries (`cli`) and the web Scan callout to count high-exploit-probability
/// findings, NOT a ranking gate: `score.rs` folds EPSS into each finding's
/// score and owns the ordering, so the ranking needs no cutoff.
pub const EPSS_HIGH: f64 = 0.5;

/// The exploitation intelligence used to prioritize findings.
#[derive(Debug, Default, Clone)]
pub struct ExploitIntel {
    pub kev: HashSet<String>,
    pub epss: HashMap<String, f64>,
}

impl ExploitIntel {
    pub fn is_empty(&self) -> bool {
        self.kev.is_empty() && self.epss.is_empty()
    }
}

/// The CVE ids a finding references: the structured `Finding.cves` field when
/// the producer filled it (every advisory provider does), falling back to a
/// prose scan for sources that only carry CVEs in free text (npm audit titles,
/// intel-feed summaries).
pub fn finding_cves(finding: &Finding) -> Vec<String> {
    if !finding.cves.is_empty() {
        return finding.cves.clone();
    }
    extract_cves(finding)
}

/// Fallback extraction: uppercase `CVE-YYYY-NNNN` ids referenced anywhere in a
/// finding's prose (title, references, evidence, summary). Hand-rolled scan
/// (no regex dep). Prefer [`finding_cves`], which reads the structured field
/// first.
pub fn extract_cves(finding: &Finding) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut scan = |text: &str| {
        for cve in find_cves(text) {
            if seen.insert(cve.clone()) {
                out.push(cve);
            }
        }
    };
    scan(&finding.title);
    scan(&finding.summary);
    if let Some(evidence) = &finding.evidence {
        scan(evidence);
    }
    for reference in &finding.references {
        scan(reference);
    }
    out
}

/// Find every `CVE-<digits>-<digits>` token in `text`, normalized upper-case.
fn find_cves(text: &str) -> Vec<String> {
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(rel) = upper[i..].find("CVE-") {
        let start = i + rel;
        let mut j = start + 4;
        let year_start = j;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j - year_start == 4 && j < bytes.len() && bytes[j] == b'-' {
            let num_start = j + 1;
            j = num_start;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j > num_start {
                out.push(upper[start..j].to_string());
            }
        }
        // `j` never moves backwards from `start + 4`, so resume there: the
        // skipped bytes are all digits/hyphen and cannot start another "CVE-".
        i = j;
    }
    out
}

/// Annotate findings with their KEV/EPSS exploit info. Pure: no IO, no
/// reordering; `score.rs::score_report` folds KEV/EPSS into each finding's
/// score and owns the final ordering. Returns how many findings were flagged as
/// actively exploited (KEV).
pub fn prioritize(findings: &mut [Finding], intel: &ExploitIntel) -> usize {
    if intel.is_empty() {
        return 0;
    }
    let mut kev_count = 0;
    for finding in findings.iter_mut() {
        let cves = finding_cves(finding);
        if cves.is_empty() {
            continue;
        }
        let kev = cves.iter().any(|c| intel.kev.contains(c));
        let epss = cves
            .iter()
            .filter_map(|c| intel.epss.get(c).copied())
            .reduce(f64::max);
        if kev || epss.is_some() {
            if kev {
                kev_count += 1;
                finding
                    .references
                    .push("CISA KEV: actively exploited in the wild (fix first)".to_string());
            }
            if let Some(p) = epss {
                finding
                    .references
                    .push(format!("EPSS {:.0}% 30-day exploit probability", p * 100.0));
            }
            finding.exploit = Some(ExploitInfo { kev, epss });
        }
    }
    kev_count
}

/// Fetch CISA KEV + EPSS (for `cves`) best-effort, served from the TTL'd
/// [`KvCache`] when a fresh copy exists. Network/parse/cache errors yield an
/// empty intel set rather than failing the scan. Online only.
pub async fn fetch_exploit_intel(client: &Client, cves: &[String]) -> ExploitIntel {
    // An unopenable cache just means no acceleration, never a scan failure.
    // Opening is SQLite I/O too, so it also runs on the blocking pool.
    let cache = tokio::task::spawn_blocking(|| KvCache::open().ok().map(Arc::new))
        .await
        .ok()
        .flatten();
    fetch_exploit_intel_from(client, cves, cache.as_ref(), KEV_URL, EPSS_URL).await
}

/// URL- and cache-parameterized body of [`fetch_exploit_intel`], the seam
/// that lets offline tests point at an unreachable endpoint and a tempdir.
async fn fetch_exploit_intel_from(
    client: &Client,
    cves: &[String],
    cache: Option<&Arc<KvCache>>,
    kev_url: &str,
    epss_url: &str,
) -> ExploitIntel {
    let mut intel = ExploitIntel::default();
    if cves.is_empty() {
        return intel;
    }
    intel.kev = fetch_kev(client, cache, kev_url).await;
    intel.epss = fetch_epss(client, cves, cache, epss_url).await;
    intel
}

/// CISA KEV: one JSON document of all actively-exploited CVEs, cached whole.
async fn fetch_kev(client: &Client, cache: Option<&Arc<KvCache>>, url: &str) -> HashSet<String> {
    if let Some(cache) = cache {
        let cached = cache_blocking(cache, |c| c.get_fresh(KEV_CACHE_KEY, KEV_TTL))
            .await
            .flatten();
        if let Some(ids) = cached.and_then(|body| parse_kev(&body)) {
            return ids;
        }
    }
    let Ok(body) = crate::providers::fetch_body(client.get(url)).await else {
        return HashSet::new();
    };
    let Some(ids) = parse_kev(&body) else {
        return HashSet::new();
    };
    // Cache only a body that parsed as a KEV catalog (never an error page); a
    // failed put just costs the next scan a refetch.
    if let Some(cache) = cache {
        let _ = cache_blocking(cache, move |c| c.put(KEV_CACHE_KEY, &body)).await;
    }
    ids
}

/// Parse a KEV catalog body into its CVE id set. `None` when the body is not
/// a KEV catalog (bad JSON or no `vulnerabilities` array).
fn parse_kev(body: &[u8]) -> Option<HashSet<String>> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let vulns = value.get("vulnerabilities")?.as_array()?;
    Some(
        vulns
            .iter()
            .filter_map(|entry| entry.get("cveID").and_then(|v| v.as_str()))
            .map(|id| id.to_ascii_uppercase())
            .collect(),
    )
}

/// A cached EPSS body parsed into its score: the decimal string, validated to
/// a finite 0-to-1 probability. `None` for anything else (unparseable entry ==
/// miss; self-heals on the refetch's put).
fn parse_epss_body(body: &[u8]) -> Option<f64> {
    std::str::from_utf8(body)
        .ok()?
        .parse::<f64>()
        .ok()
        .filter(|score| score.is_finite() && (0.0..=1.0).contains(score))
}

/// EPSS: query only the CVEs we actually found, batched (API caps the list),
/// with per-CVE cache entries (incl. negative entries for score-less CVEs).
async fn fetch_epss(
    client: &Client,
    cves: &[String],
    cache: Option<&Arc<KvCache>>,
    url: &str,
) -> HashMap<String, f64> {
    let cves: Vec<String> = cves.iter().map(|cve| cve.to_ascii_uppercase()).collect();
    // Serve what we can from the cache (one blocking-pool trip for all the
    // reads); everything else goes to the network.
    let (mut epss, misses) = match cache {
        Some(cache) => {
            let lookups = cves.clone();
            cache_blocking(cache, move |c| {
                let mut hits = HashMap::new();
                let mut misses = Vec::new();
                for cve in lookups {
                    match c.get_fresh(&epss_cache_key(&cve), EPSS_TTL) {
                        // Negative entry: EPSS is known to have no score.
                        Some(body) if body.is_empty() => {}
                        Some(body) => match parse_epss_body(&body) {
                            Some(score) => {
                                hits.insert(cve, score);
                            }
                            None => misses.push(cve),
                        },
                        None => misses.push(cve),
                    }
                }
                (hits, misses)
            })
            .await
            // A failed join means nothing was read: everything is a miss.
            .unwrap_or_else(|| (HashMap::new(), cves.clone()))
        }
        None => (HashMap::new(), cves.clone()),
    };
    for chunk in misses.chunks(100) {
        let query = chunk.join(",");
        let fetched = crate::providers::fetch_json::<serde_json::Value>(
            client.get(url).query(&[("cve", query.as_str())]),
        )
        .await;
        let Ok(body) = fetched else { continue };
        let Some(data) = body.get("data").and_then(|v| v.as_array()) else {
            continue;
        };
        let mut returned: HashMap<String, f64> = HashMap::new();
        for row in data {
            let (Some(cve), Some(score)) = (
                row.get("cve").and_then(|v| v.as_str()),
                row.get("epss")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<f64>().ok())
                    .filter(|score| score.is_finite() && (0.0..=1.0).contains(score)),
            ) else {
                continue;
            };
            returned.insert(cve.to_ascii_uppercase(), score);
        }
        // A response with a valid `data` array is authoritative for the whole
        // chunk: cache each score, and negative-cache the queried CVEs it had
        // no score for. Chunks that failed above cached nothing; a network
        // blip never poisons the cache. One blocking-pool trip per chunk.
        let mut puts: Vec<(String, Vec<u8>)> = Vec::with_capacity(chunk.len());
        for cve in chunk {
            let body = match returned.get(cve) {
                Some(score) => {
                    epss.insert(cve.clone(), *score);
                    score.to_string().into_bytes()
                }
                None => Vec::new(),
            };
            puts.push((epss_cache_key(cve), body));
        }
        if let Some(cache) = cache {
            let _ = cache_blocking(cache, move |c| {
                for (key, body) in &puts {
                    let _ = c.put(key, body);
                }
            })
            .await;
        }
    }
    epss
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn finding(id: &str, title: &str) -> Finding {
        Finding::new(
            id,
            title,
            Severity::Medium,
            crate::rule::Category::Vulnerability,
            "OSV.dev",
            None,
            None,
            "summary",
            None,
            "fix it",
        )
    }

    #[test]
    fn extracts_cve_ids() {
        let f = finding(
            "osv:1",
            "GHSA-jfh8-c2jp-5v3q affects log4j (CVE-2021-44228, CVE-2021-45046)",
        );
        let cves = extract_cves(&f);
        assert!(cves.contains(&"CVE-2021-44228".to_string()));
        assert!(cves.contains(&"CVE-2021-45046".to_string()));
        let g = finding("x", "cve-bad and CVE-12-3 should not match");
        assert!(extract_cves(&g).is_empty());
    }

    #[test]
    fn annotates_kev_and_epss_without_reordering() {
        // prioritize() is annotate-only; score.rs owns the final ordering.
        let mut findings = vec![
            finding("a", "plain finding, no cve"),
            finding("b", "affects x (CVE-2020-0001)"), // EPSS 0.9
            finding("c", "affects y (CVE-2021-44228)"), // KEV
            finding("d", "affects z (CVE-2019-1234)"), // EPSS 0.1
        ];
        let mut intel = ExploitIntel::default();
        intel.kev.insert("CVE-2021-44228".into());
        intel.epss.insert("CVE-2020-0001".into(), 0.9);
        intel.epss.insert("CVE-2019-1234".into(), 0.1);

        let kev = prioritize(&mut findings, &intel);
        assert_eq!(kev, 1);
        // Input order is preserved; no sort happens here.
        let order: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(order, vec!["a", "b", "c", "d"]);
        let kev_finding = findings.iter().find(|f| f.id == "c").unwrap();
        assert!(kev_finding.exploit.as_ref().unwrap().kev);
        assert!(
            kev_finding
                .references
                .iter()
                .any(|r| r.contains("CISA KEV"))
        );
        let epss_finding = findings.iter().find(|f| f.id == "b").unwrap();
        let ex = epss_finding.exploit.as_ref().unwrap();
        assert!(!ex.kev);
        assert_eq!(ex.epss, Some(0.9));
    }

    #[test]
    fn structured_cves_win_over_prose() {
        // A finding with the structured field set is matched on it directly
        // (no prose scraping) even when the title mentions no CVE at all.
        let mut findings =
            vec![finding("a", "GHSA-xxxx affects pkg").with_cves(vec!["cve-2021-44228".into()])];
        let mut intel = ExploitIntel::default();
        intel.kev.insert("CVE-2021-44228".into());
        assert_eq!(prioritize(&mut findings, &intel), 1);
        assert!(findings[0].exploit.as_ref().unwrap().kev);
        // with_cves normalized the id to upper-case.
        assert_eq!(findings[0].cves, vec!["CVE-2021-44228".to_string()]);
    }

    #[test]
    fn empty_intel_is_a_no_op() {
        let mut findings = vec![finding("a", "CVE-2020-0001")];
        assert_eq!(prioritize(&mut findings, &ExploitIntel::default()), 0);
        assert!(findings[0].exploit.is_none());
    }

    #[test]
    fn parse_kev_accepts_a_catalog_and_rejects_garbage() {
        let catalog = br#"{"vulnerabilities":[{"cveID":"cve-2021-44228"},{"cveID":"CVE-2023-1"},{"notes":"no id"}]}"#;
        let ids = parse_kev(catalog).expect("catalog parses");
        assert!(ids.contains("CVE-2021-44228")); // normalized upper-case
        assert!(ids.contains("CVE-2023-1"));
        assert_eq!(ids.len(), 2);
        assert!(parse_kev(b"not json").is_none());
        assert!(parse_kev(br#"{"error":"rate limited"}"#).is_none());
    }

    // Offline fetch tests: an unreachable loopback endpoint (port 1, instant
    // connection-refused) stands in for the network, and the KvCache lives in
    // a tempdir, never the developer's real cache.
    const DEAD_URL: &str = "http://127.0.0.1:1/unreachable";

    fn test_cache(dir: &tempfile::TempDir) -> Arc<KvCache> {
        Arc::new(KvCache::open_at(&dir.path().join("husk.db")).expect("open kv cache"))
    }

    #[tokio::test]
    async fn fresh_cache_serves_intel_without_the_network() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = test_cache(&dir);
        cache
            .put(
                KEV_CACHE_KEY,
                br#"{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}"#,
            )
            .expect("seed kev");
        cache
            .put(&epss_cache_key("CVE-2020-0001"), b"0.9")
            .expect("seed epss");
        // Negative entry: EPSS is known to have no score for this CVE.
        cache
            .put(&epss_cache_key("CVE-2019-1234"), b"")
            .expect("seed negative");

        let cves = vec![
            "CVE-2021-44228".to_string(),
            "CVE-2020-0001".to_string(),
            "CVE-2019-1234".to_string(),
        ];
        let client = Client::new();
        // Every lookup is answerable from the cache, so the dead URL is never
        // hit; a network attempt would return empty and fail the asserts.
        let intel =
            fetch_exploit_intel_from(&client, &cves, Some(&cache), DEAD_URL, DEAD_URL).await;
        assert!(intel.kev.contains("CVE-2021-44228"));
        assert_eq!(intel.epss.get("CVE-2020-0001"), Some(&0.9));
        assert!(!intel.epss.contains_key("CVE-2019-1234"));
    }

    #[tokio::test]
    async fn cache_miss_plus_network_failure_degrades_to_empty_intel() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = test_cache(&dir);
        let cves = vec!["CVE-2021-44228".to_string()];
        let client = Client::new();
        // With a cache (empty) and without one: both degrade to empty intel.
        let intel =
            fetch_exploit_intel_from(&client, &cves, Some(&cache), DEAD_URL, DEAD_URL).await;
        assert!(intel.is_empty());
        let intel = fetch_exploit_intel_from(&client, &cves, None, DEAD_URL, DEAD_URL).await;
        assert!(intel.is_empty());
        // A failed fetch must not poison the cache with anything.
        assert!(cache.get_fresh(KEV_CACHE_KEY, KEV_TTL).is_none());
        assert!(
            cache
                .get_fresh(&epss_cache_key("CVE-2021-44228"), EPSS_TTL)
                .is_none()
        );
    }

    #[tokio::test]
    async fn stale_cache_entries_are_misses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = test_cache(&dir);
        let over_a_day_ago = chrono::Utc::now().timestamp() - 25 * 60 * 60;
        cache
            .put_at(
                KEV_CACHE_KEY,
                br#"{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}"#,
                over_a_day_ago,
            )
            .expect("seed stale kev");
        cache
            .put_at(&epss_cache_key("CVE-2021-44228"), b"0.9", over_a_day_ago)
            .expect("seed stale epss");

        let cves = vec!["CVE-2021-44228".to_string()];
        let client = Client::new();
        // Stale entries fall through to the network (dead here) → empty intel.
        let intel =
            fetch_exploit_intel_from(&client, &cves, Some(&cache), DEAD_URL, DEAD_URL).await;
        assert!(intel.is_empty());
    }
}
