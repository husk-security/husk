//! Scan-time advisory freshness: pull what changed since the mirror was
//! built straight from OSV, so a scan sees an advisory published minutes
//! ago without waiting for the next bundle.
//!
//! OSV publishes a `modified_id.csv` per ecosystem (newest first, one
//! `modified,id` line per record) next to per-record JSON files. For every
//! local mirror database this module reads the head of that csv down to the
//! local watermark, fetches the handful of changed records, and upserts them
//! into the database inside one transaction. The watermark (`meta` key
//! `modified_watermark`, falling back to the newest `modified` already
//! stored) then advances, so the next scan's delta starts where this one
//! ended.
//!
//! The whole pass runs under the caller's time budget and never blocks a
//! scan on failure: every problem lands in [`FreshOutcome::failed`] and is
//! stated on the mirror's provider row, per the fail-loud rule. A delta
//! larger than [`MAX_DELTA_RECORDS`] is left for the next bundle sync
//! rather than half-applied.

use anyhow::{Context, Result};
use futures::StreamExt;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// Where OSV publishes per-ecosystem dumps, csvs, and per-record JSON;
/// `HUSK_OSV_URL` overrides the base for tests.
pub const OSV_BASE_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities";

/// Above this many changed records the mirror is too far behind for a
/// scan-time top-up; the bundle sync owns catching up.
pub const MAX_DELTA_RECORDS: usize = 500;

/// How many record fetches run concurrently per ecosystem.
const RECORD_FETCH_CONCURRENCY: usize = 6;

fn base_url() -> String {
    std::env::var("HUSK_OSV_URL")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OSV_BASE_URL.to_string())
}

#[derive(Debug, Default)]
pub struct FreshOutcome {
    /// Local databases a delta check ran against.
    pub ecosystems: usize,
    /// Records upserted across all databases.
    pub applied: usize,
    /// Per-ecosystem failures, each one surfaced on the provider row.
    pub failed: Vec<(String, String)>,
}

/// Run the delta pass over every local mirror database. Never returns an
/// error: failures are data for the provider row.
pub async fn refresh(dir: &Path) -> FreshOutcome {
    let mut outcome = FreshOutcome::default();
    let locals = local_databases(dir);
    if locals.is_empty() {
        return outcome;
    }
    // Connect and per-read timeouts bound a hung server even when a caller
    // (the daemon) runs the refresh outside the scan's own time budget.
    let client = match reqwest::Client::builder()
        .user_agent(format!("husk/{}", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            outcome
                .failed
                .push(("all".to_string(), format!("http client: {err}")));
            return outcome;
        }
    };
    for (ecosystem, path) in locals {
        outcome.ecosystems += 1;
        match refresh_one(&client, &ecosystem, &path).await {
            Ok(applied) => outcome.applied += applied,
            Err(err) => outcome.failed.push((ecosystem, format!("{err:#}"))),
        }
    }
    outcome
}

/// Every readable mirror database in `dir` with the schema version this
/// build understands, as (OSV ecosystem name, path).
fn local_databases(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "db") {
            continue;
        }
        let Ok(conn) = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) else {
            continue;
        };
        let version: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .ok();
        if version.as_deref() != Some(super::INTEL_SCHEMA_VERSION) {
            continue;
        }
        let ecosystem: Option<String> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'ecosystem'",
                [],
                |row| row.get(0),
            )
            .ok();
        if let Some(ecosystem) = ecosystem {
            out.push((ecosystem, path));
        }
    }
    out.sort();
    out
}

async fn refresh_one(client: &reqwest::Client, ecosystem: &str, path: &Path) -> Result<usize> {
    let Some(watermark) = read_watermark(path)? else {
        // An empty database has no anchor to delta from; the bundle sync
        // owns filling it.
        return Ok(0);
    };
    let delta = fetch_csv_head(client, ecosystem, &watermark).await?;
    anyhow::ensure!(
        delta.len() <= MAX_DELTA_RECORDS,
        "over {MAX_DELTA_RECORDS} records behind; waiting for the next bundle"
    );
    if delta.is_empty() {
        return Ok(0);
    }
    let base = base_url();
    let records: Vec<Result<(String, String, String)>> = futures::stream::iter(
        delta
            .into_iter()
            .map(|(modified, id)| fetch_record(client, &base, ecosystem, modified, id)),
    )
    .buffer_unordered(RECORD_FETCH_CONCURRENCY)
    .collect()
    .await;
    let records: Vec<(String, String, String)> = records
        .into_iter()
        .collect::<Result<Vec<_>>>()
        .context("fetching changed records")?;
    let applied = records.len();
    let mut conn = Connection::open(path)?;
    // A concurrent scan holds read transactions on this file; wait for them
    // rather than failing the whole delta on a transient lock.
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    apply_records(&mut conn, &records)?;
    Ok(applied)
}

/// The delta anchor: the explicit watermark a previous delta wrote, else the
/// newest `modified` the database holds (a freshly synced bundle has only
/// the latter).
fn read_watermark(path: &Path) -> Result<Option<String>> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let explicit: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'modified_watermark'",
            [],
            |row| row.get(0),
        )
        .ok();
    if explicit.is_some() {
        return Ok(explicit);
    }
    let newest: Option<String> =
        conn.query_row("SELECT MAX(modified) FROM advisories", [], |row| row.get(0))?;
    Ok(newest)
}

/// Stream the head of `modified_id.csv` and stop at the first line at or
/// below the watermark: the file is newest first, so everything after it is
/// already local. Returns (modified, id) pairs, newest first. Reads at most
/// one line past [`MAX_DELTA_RECORDS`] so the caller can tell "too far
/// behind" from an exact-cap delta.
async fn fetch_csv_head(
    client: &reqwest::Client,
    ecosystem: &str,
    watermark: &str,
) -> Result<Vec<(String, String)>> {
    let url = format!(
        "{}/{}/modified_id.csv",
        base_url(),
        urlencoding::encode(ecosystem)
    );
    let response = client
        .get(&url)
        .send()
        .await?
        .error_for_status()
        .context("fetching modified_id.csv")?;
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    let mut out = Vec::new();
    let mut anchored = false;
    'stream: while let Some(chunk) = stream.next().await {
        buffer.push_str(&String::from_utf8_lossy(chunk?.as_ref()));
        while let Some(newline) = buffer.find('\n') {
            let line = buffer[..newline].trim().to_string();
            buffer.drain(..=newline);
            if !push_delta_line(&line, watermark, &mut out) {
                anchored = true;
                break 'stream;
            }
            if out.len() > MAX_DELTA_RECORDS {
                break 'stream;
            }
        }
    }
    if !anchored && !buffer.trim().is_empty() && out.len() <= MAX_DELTA_RECORDS {
        anchored = !push_delta_line(buffer.trim(), watermark, &mut out);
    }
    // A real csv always anchors (a row at or below the watermark) or yields
    // rows above it. Neither means the body was not the csv (a captive
    // portal, an error page), and claiming a clean refresh off it would put
    // a green row over stale data.
    anyhow::ensure!(
        anchored || !out.is_empty(),
        "modified_id.csv had no recognizable rows"
    );
    Ok(out)
}

/// Parse one csv line into `out`. Returns false when the line is at or
/// below the watermark, which ends the walk. Lines that are not
/// `timestamp,id` (a header, blanks) are skipped.
fn push_delta_line(line: &str, watermark: &str, out: &mut Vec<(String, String)>) -> bool {
    if line.is_empty() {
        return true;
    }
    let Some((modified, id)) = line.split_once(',') else {
        return true;
    };
    if !modified.starts_with(|c: char| c.is_ascii_digit()) {
        return true;
    }
    // RFC 3339 UTC timestamps order lexicographically.
    if modified <= watermark {
        return false;
    }
    out.push((modified.to_string(), id.to_string()));
    true
}

async fn fetch_record(
    client: &reqwest::Client,
    base: &str,
    ecosystem: &str,
    modified: String,
    id: String,
) -> Result<(String, String, String)> {
    let url = format!(
        "{base}/{}/{}.json",
        urlencoding::encode(ecosystem),
        urlencoding::encode(&id)
    );
    let record = client
        .get(&url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("fetching {id}"))?
        .text()
        .await?;
    Ok((id, modified, record))
}

/// Upsert changed records and advance the watermark in one transaction, so
/// an interrupted delta leaves the database exactly as it was.
fn apply_records(conn: &mut Connection, records: &[(String, String, String)]) -> Result<()> {
    let tx = conn.transaction()?;
    let mut newest: Option<&str> = None;
    for (id, modified, record) in records {
        // The bundle builder drops withdrawn records; the delta must remove
        // them too, or a retracted advisory keeps firing until the next
        // bundle. A withdrawal still advances the watermark: it was applied.
        if is_withdrawn(record) {
            tx.execute("DELETE FROM advisories WHERE id = ?1", [id.as_str()])?;
            tx.execute("DELETE FROM affected WHERE advisory_id = ?1", [id.as_str()])?;
        } else {
            tx.execute(
                "INSERT OR REPLACE INTO advisories (id, modified, record) VALUES (?1, ?2, ?3)",
                [id.as_str(), modified.as_str(), record.as_str()],
            )?;
            tx.execute("DELETE FROM affected WHERE advisory_id = ?1", [id.as_str()])?;
            for name in affected_names(record) {
                tx.execute(
                    "INSERT INTO affected (name, advisory_id) VALUES (?1, ?2)",
                    [name.as_str(), id.as_str()],
                )?;
            }
        }
        if newest.is_none_or(|current| modified.as_str() > current) {
            newest = Some(modified);
        }
    }
    if let Some(newest) = newest {
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('modified_watermark', ?1)",
            [newest],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn is_withdrawn(record: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Record {
        withdrawn: Option<serde_json::Value>,
    }
    serde_json::from_str::<Record>(record).is_ok_and(|record| record.withdrawn.is_some())
}

fn affected_names(record: &str) -> Vec<String> {
    #[derive(serde::Deserialize)]
    struct Record {
        #[serde(default)]
        affected: Vec<Affected>,
    }
    #[derive(serde::Deserialize)]
    struct Affected {
        package: Option<Package>,
    }
    #[derive(serde::Deserialize)]
    struct Package {
        name: String,
    }
    let Ok(parsed) = serde_json::from_str::<Record>(record) else {
        return Vec::new();
    };
    let mut names: Vec<String> = parsed
        .affected
        .into_iter()
        .filter_map(|affected| affected.package.map(|package| package.name))
        .collect();
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_walk_stops_at_the_watermark() {
        let mut out = Vec::new();
        for line in [
            "modified,id",
            "2026-08-21T09:00:00Z,RUSTSEC-2026-0300",
            "2026-08-20T12:00:00Z,RUSTSEC-2026-0299",
            "2026-08-19T00:00:00Z,RUSTSEC-2026-0258",
        ] {
            if !push_delta_line(line, "2026-08-20T00:00:00Z", &mut out) {
                break;
            }
        }
        assert_eq!(
            out,
            vec![
                (
                    "2026-08-21T09:00:00Z".to_string(),
                    "RUSTSEC-2026-0300".to_string()
                ),
                (
                    "2026-08-20T12:00:00Z".to_string(),
                    "RUSTSEC-2026-0299".to_string()
                ),
            ]
        );
    }

    #[test]
    fn upserts_advance_the_watermark_and_rebuild_name_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crates-io.db");
        let mut conn = Connection::open(&path).expect("open");
        crate::intel::create_schema(&conn, "crates.io", "2026-08-01T00:00:00Z").expect("schema");
        conn.execute(
            "INSERT INTO advisories (id, modified, record) VALUES
             ('RUSTSEC-2026-0258', '2026-08-01T00:00:00Z', '{}')",
            [],
        )
        .expect("seed");
        conn.execute(
            "INSERT INTO affected (name, advisory_id) VALUES ('h2', 'RUSTSEC-2026-0258')",
            [],
        )
        .expect("seed name");

        let record = serde_json::json!({
            "id": "RUSTSEC-2026-0258",
            "modified": "2026-08-19T12:00:00Z",
            "affected": [
                {"package": {"ecosystem": "crates.io", "name": "h2"}},
                {"package": {"ecosystem": "crates.io", "name": "h2-old"}},
            ],
        })
        .to_string();
        apply_records(
            &mut conn,
            &[(
                "RUSTSEC-2026-0258".to_string(),
                "2026-08-19T12:00:00Z".to_string(),
                record,
            )],
        )
        .expect("apply");

        assert_eq!(
            read_watermark(&path).expect("watermark"),
            Some("2026-08-19T12:00:00Z".to_string())
        );
        let names: Vec<String> = conn
            .prepare(
                "SELECT name FROM affected WHERE advisory_id = 'RUSTSEC-2026-0258' ORDER BY name",
            )
            .expect("prepare")
            .query_map([], |row| row.get(0))
            .expect("query")
            .flatten()
            .collect();
        assert_eq!(names, vec!["h2".to_string(), "h2-old".to_string()]);
    }

    #[test]
    fn empty_databases_are_left_to_the_bundle_sync() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("npm.db");
        let conn = Connection::open(&path).expect("open");
        crate::intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
        assert_eq!(read_watermark(&path).expect("watermark"), None);
    }
}
