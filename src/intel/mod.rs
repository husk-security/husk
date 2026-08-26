//! The local advisory mirror: OSV advisory data as per-ecosystem SQLite
//! files on disk, so scans match coordinates locally (fast, offline, no
//! inventory leaves the machine) instead of depending on live provider
//! requests. Live queries remain a freshness top-up in `crate::providers`;
//! this mirror is the floor under them.
//!
//! Layout under `cache::intel_dir()`: one `<ecosystem>.db` per OSV ecosystem
//! plus `state.json` recording what was synced when. The files are published
//! by husk's infrastructure and fetched invisibly by [`sync`] (the published
//! format is documented there). Matching lives in [`match_packages`]: exact
//! version enumeration first, then range evaluation through [`semantic`],
//! the Rust port of osv-scalibr's ecosystem-native version ordering; range
//! types it cannot evaluate are counted and reported, never guessed.
//!
//! Failure posture, per the fail-loud rule: an unsynced or stale mirror is
//! stated on the provider row (and fails an offline scan's row outright);
//! nothing here ever silently narrows coverage.

pub mod fresh;
pub mod semantic;
pub mod sync;

use crate::model::{Finding, PackageRef, ProviderStatus};
use anyhow::Result;
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Bumped when the per-ecosystem database schema changes; a mismatched file
/// is ignored (and re-synced), never misread.
pub const INTEL_SCHEMA_VERSION: &str = "1";

/// Mirror data older than this fails its provider row: week-old advisory
/// data behind a green scan is the silent weakening husk must never do.
pub const STALE_AFTER_DAYS: i64 = 7;

/// The provider-row name for the mirror. Distinct from the live `OSV.dev`
/// row; findings from both carry the `OSV.dev` source and dedup by id.
pub const MIRROR_ROW: &str = "OSV mirror";

/// One `<ecosystem>.db` file: `meta` (schema version, ecosystem, built_at),
/// `advisories` (trimmed OSV record JSON), and `affected` (name lookup).
/// The platform builder creates real files with this exact schema; the
/// client only needs it to build test fixtures (unit and integration).
pub fn create_schema(conn: &Connection, ecosystem: &str, built_at: &str) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS advisories (
             id TEXT PRIMARY KEY,
             modified TEXT NOT NULL,
             record TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS affected (
             name TEXT NOT NULL,
             advisory_id TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_affected_name ON affected(name);",
    )?;
    let mut put = conn.prepare("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)")?;
    put.execute(["schema_version", INTEL_SCHEMA_VERSION])?;
    put.execute(["ecosystem", ecosystem])?;
    put.execute(["built_at", built_at])?;
    Ok(())
}

/// `<ecosystem>.db` file name for an OSV ecosystem ("crates.io", "GitHub
/// Actions"): non-alphanumeric characters become `-` so names stay portable.
pub fn ecosystem_file(ecosystem: &str) -> String {
    let safe: String = ecosystem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{safe}.db")
}

/// Client-side sync state: which ecosystem files exist locally and when they
/// were fetched, written by [`sync`] and read for staleness reporting.
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct MirrorState {
    /// RFC 3339 time of the last successful sync.
    #[serde(default)]
    pub synced_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Per-ecosystem sha256 of the local file, keyed by OSV ecosystem name.
    #[serde(default)]
    pub files: HashMap<String, String>,
}

pub fn load_state(dir: &Path) -> MirrorState {
    std::fs::read_to_string(dir.join("state.json"))
        .ok()
        .and_then(|body| serde_json::from_str(&body).ok())
        .unwrap_or_default()
}

pub fn save_state(dir: &Path, state: &MirrorState) -> Result<()> {
    crate::paths::write_private(
        &dir.join("state.json"),
        serde_json::to_string_pretty(state)?.as_bytes(),
    )
}

/// What matching against the mirror produced, plus everything the provider
/// row needs to be honest about coverage.
#[derive(Debug, Default)]
pub struct MirrorMatch {
    pub findings: Vec<Finding>,
    /// Coordinates that had a local database to check against.
    pub checked: usize,
    /// Affected ranges present in matched-name records that no local
    /// comparator could evaluate (e.g. distro version schemes).
    pub unevaluated_ranges: usize,
    /// OSV ecosystems in the inventory with no local database file.
    pub missing_ecosystems: Vec<String>,
}

/// Match every eligible coordinate against the local mirror. Read-only over
/// the mirror databases; a missing or unreadable one is reported, never
/// fatal. The single write is the self-repair described on [`OpenFailure`].
pub fn match_packages(dir: &Path, packages: &[PackageRef]) -> MirrorMatch {
    let mut result = MirrorMatch::default();
    // Group by the base ecosystem file: "Debian:12" lives in Debian.db.
    let mut by_file: HashMap<String, Vec<(&PackageRef, String)>> = HashMap::new();
    for package in packages {
        if let Some(osv_ecosystem) = package.osv_ecosystem() {
            let base = osv_ecosystem
                .split_once(':')
                .map(|(base, _)| base.to_string())
                .unwrap_or_else(|| osv_ecosystem.clone());
            by_file
                .entry(base)
                .or_default()
                .push((package, osv_ecosystem));
        }
    }
    for (base, coords) in by_file {
        let path = dir.join(ecosystem_file(&base));
        let conn = match open_readonly(&path) {
            Ok(conn) => conn,
            Err(failure) => {
                if matches!(failure, OpenFailure::Corrupt) {
                    sync::invalidate(dir, &base);
                }
                result.missing_ecosystems.push(base);
                continue;
            }
        };
        for (package, osv_ecosystem) in coords {
            // Damage past the header only shows when a page is actually
            // read. The rest of this file is no more trustworthy, so stop
            // reading it and let the next sync replace it.
            if let Err(err) = match_one(&conn, package, &osv_ecosystem, &mut result) {
                if is_corruption(&err) {
                    sync::invalidate(dir, &base);
                }
                result.missing_ecosystems.push(base.clone());
                break;
            }
            result.checked += 1;
        }
    }
    result.missing_ecosystems.sort();
    result.missing_ecosystems.dedup();
    result
}

/// Why a mirror database could not be read, and with it whether the client
/// can repair itself. `state.json` records the sha256 of the artifact each
/// database came from, and [`sync`] skips an ecosystem whose recorded hash
/// still matches the index, so a file that is wrong stays wrong until the
/// publisher happens to change it. Dropping the record is the repair, and
/// only [`OpenFailure::Corrupt`] is worth repairing that way.
enum OpenFailure {
    /// No file yet: sync re-fetches it from its own existence check.
    Absent,
    /// SQLite rejected the file, so the bytes on disk are not the database
    /// whose hash was recorded.
    Corrupt,
    /// Readable but unusable right now: a concurrent delta write holds it,
    /// or its schema version is one this build does not know. Re-fetching
    /// the same bytes would not help, so the recorded hash stands.
    Unusable,
}

fn open_readonly(path: &Path) -> std::result::Result<Connection, OpenFailure> {
    if !path.exists() {
        return Err(OpenFailure::Absent);
    }
    let opened = (|| -> rusqlite::Result<(Connection, String)> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        // A daemon's delta write may hold the file briefly; waiting beats
        // silently reading nothing while a transaction commits.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version = conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )?;
        Ok((conn, version))
    })();
    match opened {
        Ok((conn, version)) if version == INTEL_SCHEMA_VERSION => Ok(conn),
        Ok(_) => Err(OpenFailure::Unusable),
        Err(err) if is_corruption(&err) => Err(OpenFailure::Corrupt),
        Err(_) => Err(OpenFailure::Unusable),
    }
}

/// Whether a SQLite failure says the file itself is wrong. A busy or locked
/// database is a concurrent delta write clearing on its own, never a reason
/// to throw the file away.
fn is_corruption(err: &rusqlite::Error) -> bool {
    !matches!(
        err.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
}

fn match_one(
    conn: &Connection,
    package: &PackageRef,
    osv_ecosystem: &str,
    out: &mut MirrorMatch,
) -> rusqlite::Result<()> {
    let mut statement = conn.prepare_cached(
        "SELECT a.id, a.record FROM affected f JOIN advisories a ON a.id = f.advisory_id
         WHERE f.name = ?1",
    )?;
    let rows = statement.query_map([&package.name], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (advisory_id, record) = row?;
        // The shared versionless rule: without a version only MAL- applies.
        if !crate::providers::osv_advisory_applies(package, &advisory_id) {
            continue;
        }
        let Ok(parsed) = serde_json::from_str::<MatchRecord>(&record) else {
            continue;
        };
        // Withdrawn records are dropped at write time (bundle build and
        // delta apply); skipping any that still exist keeps a retracted
        // advisory from firing off older stored data.
        if parsed.withdrawn.is_some() {
            continue;
        }
        let mut unevaluated = 0usize;
        if record_applies(&parsed, package, osv_ecosystem, &mut unevaluated)
            && let Some(finding) = crate::providers::finding_from_osv_record(package, &record)
        {
            out.findings.push(finding);
        }
        out.unevaluated_ranges += unevaluated;
    }
    Ok(())
}

/// The subset of an OSV record the matcher reads. The stored record is the
/// trimmed upstream JSON, so `providers::finding_from_osv_record` reads the
/// same bytes with its own schema.
#[derive(Debug, serde::Deserialize)]
struct MatchRecord {
    withdrawn: Option<serde_json::Value>,
    #[serde(default)]
    affected: Vec<MatchAffected>,
}

#[derive(Debug, serde::Deserialize)]
struct MatchAffected {
    package: Option<MatchPackage>,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    ranges: Vec<MatchRange>,
}

#[derive(Debug, serde::Deserialize)]
struct MatchPackage {
    name: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, serde::Deserialize)]
struct MatchRange {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    events: Vec<MatchEvent>,
}

#[derive(Debug, serde::Deserialize)]
struct MatchEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

fn record_applies(
    record: &MatchRecord,
    package: &PackageRef,
    osv_ecosystem: &str,
    unevaluated: &mut usize,
) -> bool {
    for affected in &record.affected {
        let Some(affected_package) = &affected.package else {
            continue;
        };
        if affected_package.name != package.name || affected_package.ecosystem != osv_ecosystem {
            continue;
        }
        // A versionless coordinate already passed the MAL-only gate: any
        // version of a malicious name is a hit.
        if package.version.is_empty() {
            return true;
        }
        if affected
            .versions
            .iter()
            .any(|version| version == &package.version)
        {
            return true;
        }
        for range in &affected.ranges {
            match range_applies(range, osv_ecosystem, &package.version) {
                RangeVerdict::Affected => return true,
                RangeVerdict::NotAffected => {}
                RangeVerdict::Unevaluated => *unevaluated += 1,
            }
        }
    }
    false
}

enum RangeVerdict {
    Affected,
    NotAffected,
    Unevaluated,
}

/// Walk a range's events in upstream order (the OSV spec requires producers
/// to sort them): `introduced` opens coverage, `fixed` closes it exclusively,
/// `last_affected` closes it inclusively.
type VersionCompare<'a> = Box<dyn Fn(&str, &str) -> Option<std::cmp::Ordering> + 'a>;

fn range_applies(range: &MatchRange, osv_ecosystem: &str, version: &str) -> RangeVerdict {
    // Comparison semantics come from the ported osv-scalibr `semantic`
    // library: SEMVER-type ranges use Semver 2.0.0 ordering by spec;
    // ECOSYSTEM-type ranges use the ecosystem's native ordering.
    let compare: VersionCompare<'_> = match range.kind.as_str() {
        "SEMVER" => Box::new(|a: &str, b: &str| Some(semantic::compare_semver_str(a, b))),
        "ECOSYSTEM" => Box::new(move |a: &str, b: &str| semantic::compare_str(osv_ecosystem, a, b)),
        "GIT" => return RangeVerdict::NotAffected,
        _ => return RangeVerdict::Unevaluated,
    };
    let mut affected = false;
    for event in &range.events {
        if let Some(introduced) = &event.introduced {
            if introduced == "0"
                || matches!(compare(version, introduced), Some(order) if order >= std::cmp::Ordering::Equal)
            {
                affected = true;
            } else if compare(version, introduced).is_none() {
                return RangeVerdict::Unevaluated;
            }
        }
        if let Some(fixed) = &event.fixed {
            match compare(version, fixed) {
                Some(order) if order >= std::cmp::Ordering::Equal => affected = false,
                Some(_) => {}
                None => return RangeVerdict::Unevaluated,
            }
        }
        if let Some(last) = &event.last_affected {
            match compare(version, last) {
                Some(std::cmp::Ordering::Greater) => affected = false,
                Some(_) => {}
                None => return RangeVerdict::Unevaluated,
            }
        }
    }
    if affected {
        RangeVerdict::Affected
    } else {
        RangeVerdict::NotAffected
    }
}

/// The mirror's provider row: age and coverage stated plainly, and the rules
/// that decide when a mirror problem must read as a failure. `fresh` is the
/// scan-time OSV delta result when one ran; a successful delta makes even an
/// old base bundle current, and a failed one is said out loud.
pub fn provider_row(
    dir: &Path,
    matched: &MirrorMatch,
    online: bool,
    fresh: Option<&fresh::FreshOutcome>,
) -> ProviderStatus {
    let state = load_state(dir);
    let age_days = state
        .synced_at
        .map(|at| (chrono::Utc::now() - at).num_days());
    let (ok, message) = match age_days {
        None if online => (
            true,
            "not synced yet; live queries cover this scan while the mirror downloads".to_string(),
        ),
        None => (
            false,
            "no local advisory data yet; this offline scan has no advisory coverage".to_string(),
        ),
        Some(age) if age > STALE_AFTER_DAYS => match fresh {
            Some(f) if f.ecosystems > 0 && f.failed.is_empty() => (
                true,
                format!(
                    "advisory data refreshed from OSV at scan time; base bundle is {age} day(s) old"
                ),
            ),
            _ => (
                false,
                format!(
                    "advisory data is {age} day(s) old and could not be refreshed at scan time"
                ),
            ),
        },
        Some(age) => {
            let mut message = format!(
                "matched {} advisory finding(s); data synced {age} day(s) ago",
                matched.findings.len()
            );
            if matched.unevaluated_ranges > 0 {
                message.push_str(&format!(
                    "; {} range(s) not locally evaluable",
                    matched.unevaluated_ranges
                ));
            }
            if !matched.missing_ecosystems.is_empty() {
                message.push_str(&format!(
                    "; no local data for {}",
                    matched.missing_ecosystems.join(", ")
                ));
            }
            (true, message)
        }
    };
    let mut message = message;
    if let Some(f) = fresh {
        if f.applied > 0 {
            message.push_str(&format!(
                "; {} advisory update(s) pulled from OSV at scan time",
                f.applied
            ));
        }
        if !f.failed.is_empty() {
            let names: Vec<&str> = f
                .failed
                .iter()
                .map(|(ecosystem, _)| ecosystem.as_str())
                .collect();
            message.push_str(&format!(
                "; scan-time refresh failed for {}",
                names.join(", ")
            ));
        }
    }
    ProviderStatus {
        name: MIRROR_ROW.to_string(),
        ok,
        checked_packages: matched.checked,
        findings: matched.findings.len(),
        message,
    }
}

/// `intel_dir`, but never fatal to a scan: a failure to create the cache dir
/// means matching is skipped and the row explains why.
pub fn dir() -> Option<PathBuf> {
    crate::cache::intel_dir().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, ecosystem: &str, name: &str, body: serde_json::Value) -> String {
        serde_json::json!({
            "id": id,
            "summary": format!("{id} affects {name}"),
            "modified": "2026-08-01T00:00:00Z",
            "affected": [{
                "package": {"ecosystem": ecosystem, "name": name},
                "versions": body["versions"],
                "ranges": body["ranges"],
            }],
        })
        .to_string()
    }

    fn mirror_with(dir: &Path, ecosystem: &str, rows: &[(&str, &str, String)]) {
        let conn = Connection::open(dir.join(ecosystem_file(ecosystem))).expect("open");
        create_schema(&conn, ecosystem, "2026-08-01T00:00:00Z").expect("schema");
        for (id, name, record) in rows {
            conn.execute(
                "INSERT INTO advisories (id, modified, record) VALUES (?1, '2026-08-01', ?2)",
                [id, record.as_str()],
            )
            .expect("advisory");
            conn.execute(
                "INSERT INTO affected (name, advisory_id) VALUES (?1, ?2)",
                [name, id],
            )
            .expect("affected");
        }
    }

    fn coordinate(ecosystem: &str, name: &str, version: &str) -> PackageRef {
        PackageRef {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: PathBuf::from("/p/Cargo.lock"),
            line: None,
        }
    }

    #[test]
    fn semver_range_matches_the_h2_case() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = record(
            "RUSTSEC-2026-0258",
            "crates.io",
            "h2",
            serde_json::json!({
                "versions": [],
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "0.4.16"}
                ]}],
            }),
        );
        mirror_with(
            dir.path(),
            "crates.io",
            &[("RUSTSEC-2026-0258", "h2", record)],
        );

        let hit = match_packages(dir.path(), &[coordinate("cargo", "h2", "0.4.15")]);
        assert_eq!(hit.findings.len(), 1, "0.4.15 is affected");
        let fixed = match_packages(dir.path(), &[coordinate("cargo", "h2", "0.4.17")]);
        assert!(fixed.findings.is_empty(), "0.4.17 is past the fix");
    }

    #[test]
    fn enumerated_versions_match_exactly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = record(
            "MAL-0001",
            "npm",
            "evil-pkg",
            serde_json::json!({"versions": ["1.0.0", "1.0.1"], "ranges": []}),
        );
        mirror_with(dir.path(), "npm", &[("MAL-0001", "evil-pkg", record)]);

        let hit = match_packages(dir.path(), &[coordinate("npm", "evil-pkg", "1.0.1")]);
        assert_eq!(hit.findings.len(), 1);
        let miss = match_packages(dir.path(), &[coordinate("npm", "evil-pkg", "2.0.0")]);
        assert!(miss.findings.is_empty());
    }

    #[test]
    fn versionless_coordinates_match_malware_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mal = record(
            "MAL-0002",
            "npm",
            "typo-squat",
            serde_json::json!({"versions": ["1.0.0"], "ranges": []}),
        );
        let vuln = record(
            "GHSA-xxxx",
            "npm",
            "typo-squat",
            serde_json::json!({"versions": ["1.0.0"], "ranges": []}),
        );
        mirror_with(
            dir.path(),
            "npm",
            &[
                ("MAL-0002", "typo-squat", mal),
                ("GHSA-xxxx", "typo-squat", vuln),
            ],
        );

        let hits = match_packages(dir.path(), &[coordinate("npm", "typo-squat", "")]);
        assert_eq!(hits.findings.len(), 1, "only the MAL record applies");
    }

    #[test]
    fn pep440_ranges_cover_pypi() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = record(
            "PYSEC-1",
            "PyPI",
            "requests",
            serde_json::json!({
                "versions": [],
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "2.20.0"}
                ]}],
            }),
        );
        mirror_with(dir.path(), "PyPI", &[("PYSEC-1", "requests", record)]);

        let hit = match_packages(dir.path(), &[coordinate("pypi", "requests", "2.19.1")]);
        assert_eq!(hit.findings.len(), 1);
        let fixed = match_packages(dir.path(), &[coordinate("pypi", "requests", "2.20.0")]);
        assert!(fixed.findings.is_empty());
    }

    #[test]
    fn distro_ecosystem_ranges_are_evaluated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = record(
            "DSA-1",
            "Debian:12",
            "openssl",
            serde_json::json!({
                "versions": [],
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "3.0.11-1~deb12u1"}
                ]}],
            }),
        );
        mirror_with(dir.path(), "Debian", &[("DSA-1", "openssl", record)]);

        let result = match_packages(dir.path(), &[coordinate("debian:12", "openssl", "3.0.9-1")]);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.unevaluated_ranges, 0);

        let fixed = match_packages(
            dir.path(),
            &[coordinate("debian:12", "openssl", "3.0.11-1~deb12u1")],
        );
        assert!(fixed.findings.is_empty());
        assert_eq!(fixed.unevaluated_ranges, 0);
    }

    #[test]
    fn unknown_range_types_are_counted_not_guessed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = record(
            "DSA-2",
            "Debian:12",
            "openssl",
            serde_json::json!({
                "versions": [],
                "ranges": [{"type": "FUTURE_TYPE", "events": [
                    {"introduced": "0"}, {"fixed": "3.0.11-1~deb12u1"}
                ]}],
            }),
        );
        mirror_with(dir.path(), "Debian", &[("DSA-2", "openssl", record)]);

        let result = match_packages(dir.path(), &[coordinate("debian:12", "openssl", "3.0.9-1")]);
        assert!(result.findings.is_empty());
        assert_eq!(result.unevaluated_ranges, 1);
    }

    #[test]
    fn a_missing_ecosystem_file_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = match_packages(dir.path(), &[coordinate("npm", "left-pad", "1.3.0")]);
        assert!(result.findings.is_empty());
        assert_eq!(result.missing_ecosystems, vec!["npm".to_string()]);
    }

    #[test]
    fn a_corrupt_database_is_reported_never_fatal() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("npm.db"), b"this is not a sqlite file").expect("write");
        let result = match_packages(dir.path(), &[coordinate("npm", "left-pad", "1.3.0")]);
        assert!(result.findings.is_empty());
        assert_eq!(result.missing_ecosystems, vec!["npm".to_string()]);
    }

    #[test]
    fn an_unknown_schema_version_is_ignored_loudly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let record = record(
            "MAL-9",
            "npm",
            "evil-pkg",
            serde_json::json!({"versions": ["1.0.0"], "ranges": []}),
        );
        mirror_with(dir.path(), "npm", &[("MAL-9", "evil-pkg", record)]);
        let conn = Connection::open(dir.path().join("npm.db")).expect("open");
        conn.execute(
            "UPDATE meta SET value = '999' WHERE key = 'schema_version'",
            [],
        )
        .expect("bump version");
        drop(conn);

        let result = match_packages(dir.path(), &[coordinate("npm", "evil-pkg", "1.0.0")]);
        assert!(
            result.findings.is_empty(),
            "a future schema is never misread"
        );
        assert_eq!(result.missing_ecosystems, vec!["npm".to_string()]);
    }

    #[test]
    fn withdrawn_records_never_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let withdrawn = serde_json::json!({
            "id": "GHSA-with-draw-n001",
            "modified": "2026-08-01T00:00:00Z",
            "withdrawn": "2026-08-02T00:00:00Z",
            "summary": "retracted",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "was-bad"},
                "versions": ["1.0.0"],
            }],
        })
        .to_string();
        mirror_with(
            dir.path(),
            "npm",
            &[("GHSA-with-draw-n001", "was-bad", withdrawn)],
        );

        let result = match_packages(dir.path(), &[coordinate("npm", "was-bad", "1.0.0")]);
        assert!(
            result.findings.is_empty(),
            "a retracted advisory stays quiet"
        );
    }

    #[test]
    fn provider_row_states_every_sync_posture() {
        let dir = tempfile::tempdir().expect("tempdir");
        let matched = MirrorMatch::default();

        let row = provider_row(dir.path(), &matched, true, None);
        assert!(row.ok, "unsynced online: live queries cover the scan");
        let row = provider_row(dir.path(), &matched, false, None);
        assert!(
            !row.ok,
            "unsynced offline: no advisory coverage is a failure"
        );
        assert!(row.message.contains("no local advisory data"));

        let state = MirrorState {
            synced_at: Some(chrono::Utc::now()),
            files: HashMap::new(),
        };
        save_state(dir.path(), &state).expect("save");
        let row = provider_row(dir.path(), &matched, true, None);
        assert!(row.ok, "a fresh sync is a healthy row");

        let state = MirrorState {
            synced_at: Some(chrono::Utc::now() - chrono::Duration::days(STALE_AFTER_DAYS + 3)),
            files: HashMap::new(),
        };
        save_state(dir.path(), &state).expect("save");
        let row = provider_row(dir.path(), &matched, true, None);
        assert!(!row.ok, "stale data with no delta is a failure");

        let delta_ok = fresh::FreshOutcome {
            ecosystems: 2,
            applied: 5,
            failed: Vec::new(),
        };
        let row = provider_row(dir.path(), &matched, true, Some(&delta_ok));
        assert!(
            row.ok,
            "a successful scan-time delta makes stale data current"
        );

        let delta_failed = fresh::FreshOutcome {
            ecosystems: 2,
            applied: 0,
            failed: vec![("npm".to_string(), "boom".to_string())],
        };
        let row = provider_row(dir.path(), &matched, true, Some(&delta_failed));
        assert!(!row.ok, "stale data with a failed delta stays a failure");
        assert!(row.message.contains("scan-time refresh failed"));
    }

    #[test]
    fn a_corrupt_state_file_reads_as_never_synced() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("state.json"), b"{not json").expect("write");
        let state = load_state(dir.path());
        assert!(state.synced_at.is_none());
        assert!(state.files.is_empty());
    }
}
