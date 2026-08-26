//! Re-fetchable scan caches under the XDG cache directory (`~/.cache/husk`).
//!
//! Two artifacts live here, both safe to delete at any time:
//! - **`latest-report.json`** plus up to [`KEPT_REPORTS`]` - 1` archived
//!   predecessors (`report-<stamp>.json`): full [`ScanReport`]s, versioned by
//!   an envelope so a schema drift or version bump simply misses (no
//!   migration); loaders fall back through the archives newest-first.
//! - **`husk.db`**: the SQLite per-file findings index ([`ScanCache`]): a
//!   rescan skips re-reading files whose size/mtime fingerprint is unchanged,
//!   keyed by [`SCAN_INDEX_VERSION`] (see its docs for the bump rule). The same
//!   database also holds the [`KvCache`] TTL'd blob store for re-fetchable
//!   network artifacts (the KEV catalog, EPSS scores).
//!
//! The location resolves through [`cache_dir`], which honours the
//! [`CACHE_DIR_ENV`] override so tests and sandboxes never touch the
//! developer's real cache. (Durable per-user *state* lives in `~/.husk`
//! instead; see [`crate::paths`].)
//!
//! Re-fetchable is not the same as public: both artifacts name every finding,
//! every package, and every absolute path a scan visited, so the directory is
//! created 0700 and the files 0600, exactly like `~/.husk`. Both are also
//! pruned on open, since a cache that only ever grows is a liability of its own.

use crate::model::{Finding, ScanReport};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

const CACHE_VERSION: &str = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_PKG_VERSION"));
/// Cache key for per-file scan findings. The trailing `-vN` MUST be bumped
/// whenever detector LOGIC changes (a new/edited `Check`, a confidence/severity
/// rule) or the SHAPE of a cached `Finding` changes (its id format included);
/// the crate version alone does not move between dev builds, so without a bump
/// the SQLite index serves *stale* findings for unchanged files and your
/// detector change silently has no effect on a rescan.
pub const SCAN_INDEX_VERSION: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "-",
    env!("CARGO_PKG_VERSION"),
    "-scan-index-v8"
);

#[derive(Debug, Deserialize, Serialize)]
struct CacheEnvelope {
    version: String,
    saved_at: DateTime<Utc>,
    report: ScanReport,
}

/// Per-project reports kept on disk, evicted oldest-first by mtime. A report
/// is stored under a name derived from *what it covered*, never from when it
/// ran, so scanning one project can no longer evict another project's result:
/// this is what lets every surface serve the freshest result per project.
/// The machine report has its own name and is never evicted by this cap.
pub const KEPT_REPORTS: usize = 16;

const MACHINE_REPORT: &str = "machine-report.json";
const PROJECT_PREFIX: &str = "project-";

/// `project-<8 hex of the roots key>.json`. Hashed rather than slugged: a
/// roots key is made of absolute paths, and a filename is not the place to
/// spell out where someone's code lives.
fn project_report_name(roots: &[PathBuf]) -> String {
    let digest = crate::hash::sha256(crate::history::roots_key(roots).as_bytes());
    format!("{PROJECT_PREFIX}{}.json", hex::encode(&digest[..4]))
}

/// Where a report of this shape is stored, relative to [`report_dir`]. Public
/// so a test can seed a cache husk will actually find, rather than pinning a
/// filename that then drifts from the writer.
pub fn report_name(report: &ScanReport) -> String {
    match report.kind {
        crate::model::ScanKind::Machine => MACHINE_REPORT.to_string(),
        crate::model::ScanKind::Project => project_report_name(&report.roots),
    }
}

/// Where stored reports live, for surfaces that tell the user about the cache.
pub fn report_dir() -> Result<PathBuf> {
    cache_dir()
}

/// The newest stored *project* report over exactly these roots.
pub fn load_latest_report(roots: &[PathBuf]) -> Result<Option<ScanReport>> {
    Ok(read_report(&cache_dir()?.join(project_report_name(roots))))
}

/// The newest stored machine report, whatever home it covered. Machine
/// posture is per-machine, not per-roots, so kind is the whole key.
pub fn load_machine_report() -> Result<Option<ScanReport>> {
    Ok(read_report(&cache_dir()?.join(MACHINE_REPORT)))
}

/// The newest stored project report of any roots: the web session's
/// open-with-something fallback when these exact roots have never been
/// scanned. Machine posture has its own surface.
#[cfg(feature = "web")]
pub fn load_any_project_report() -> Result<Option<ScanReport>> {
    let dir = cache_dir()?;
    Ok(stored_report_paths(&dir)
        .into_iter()
        .filter(|path| is_project_report(path))
        .find_map(|path| read_report(&path)))
}

/// The newest stored report of any kind: "show me whatever we know" for
/// surfaces like `husk status`.
pub fn load_any_latest_report() -> Result<Option<ScanReport>> {
    let dir = cache_dir()?;
    Ok(stored_report_paths(&dir)
        .into_iter()
        .find_map(|path| read_report(&path)))
}

/// Every stored report, newest-first, skipping the ones this build cannot
/// read. The join every per-project view is built from.
pub fn stored_reports() -> Result<Vec<ScanReport>> {
    let dir = cache_dir()?;
    Ok(stored_report_paths(&dir)
        .into_iter()
        .filter_map(|path| read_report(&path))
        .collect())
}

fn read_report(path: &Path) -> Option<ScanReport> {
    parse_cache_envelope(&fs::read_to_string(path).ok()?)
}

/// Parse a cache envelope's raw contents. `None` covers a version mismatch, a
/// report shape older than this build renders, and a parse failure; the last
/// almost always means the on-disk schema drifted during development while
/// `CARGO_PKG_VERSION` stayed put (it isn't bumped per dev build), so the
/// version string alone can't catch it. Every case means the same thing to a
/// caller: no usable cache. A derived field missing from an older report would
/// otherwise render as a zero, which is worse than rescanning.
fn parse_cache_envelope(contents: &str) -> Option<ScanReport> {
    let envelope = serde_json::from_str::<CacheEnvelope>(contents).ok()?;
    (envelope.version == CACHE_VERSION
        && envelope.report.api_version >= crate::model::REPORT_API_VERSION)
        .then_some(envelope.report)
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
}

fn is_project_report(path: &Path) -> bool {
    let name = file_name(path);
    name.starts_with(PROJECT_PREFIX) && name.ends_with(".json")
}

fn is_stored_report(path: &Path) -> bool {
    is_project_report(path) || file_name(path) == MACHINE_REPORT
}

/// Stored report paths newest-first by mtime. Unlike the old stamped-archive
/// scheme there is no name ordering to lean on: a name says which target a
/// report covers, and mtime says how old it is.
fn stored_report_paths(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| is_stored_report(path))
        .map(|path| {
            let modified = fs::metadata(&path).and_then(|m| m.modified()).ok();
            (modified, path)
        })
        .collect::<Vec<_>>();
    paths.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    paths.into_iter().map(|(_, path)| path).collect()
}

pub fn save_latest_report(report: &ScanReport) -> Result<PathBuf> {
    save_latest_report_in(&cache_dir_private()?, report)
}

fn save_latest_report_in(dir: &Path, report: &ScanReport) -> Result<PathBuf> {
    let path = dir.join(report_name(report));
    let envelope = CacheEnvelope {
        version: CACHE_VERSION.to_string(),
        saved_at: Utc::now(),
        report: report.clone(),
    };
    // Owner-only: the report names every finding and every absolute path the
    // scan touched, so on a shared machine it is as sensitive as the findings
    // themselves, not the re-fetchable data the rest of the cache holds.
    crate::paths::write_private(&path, &serde_json::to_vec_pretty(&envelope)?)?;
    prune_stored_reports(dir);
    Ok(path)
}

/// Cap the project reports at [`KEPT_REPORTS`], dropping the least recently
/// written. Also sweeps `*.tmp` partial writes and any `*.json` left by an
/// older naming scheme, which no loader can find any more.
fn prune_stored_reports(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut project_reports = Vec::new();
    for path in entries.flatten().map(|entry| entry.path()) {
        let name = file_name(&path);
        if name.ends_with(".tmp") || (name.ends_with(".json") && !is_stored_report(&path)) {
            let _ = fs::remove_file(path);
        } else if is_project_report(&path) {
            project_reports.push(path);
        }
    }
    if project_reports.len() <= KEPT_REPORTS {
        return;
    }
    let oldest_first = {
        let mut paths = stored_report_paths(dir);
        paths.retain(|path| is_project_report(path));
        paths.reverse();
        paths
    };
    for path in oldest_first
        .into_iter()
        .take(project_reports.len() - KEPT_REPORTS)
    {
        let _ = fs::remove_file(path);
    }
}

/// A cached report older than this is *stale*: every surface that serves one
/// (status, the TUI header, the web banner) warns that the picture may
/// be out of date. One day balances signal against nagging: package installs
/// and advisory publications move on a daily cadence.
pub const STALE_REPORT_AFTER_HOURS: i64 = 24;

/// Human-readable age for the stale-scan warning: `"45 minutes"`,
/// `"26 hours"`, `"3 days"`. Hours until two full days, then days; the
/// granularity a "go rescan" nudge needs, nothing finer.
pub fn format_age(age: chrono::Duration) -> String {
    let minutes = age.num_minutes().max(0);
    if minutes < 120 {
        return format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" });
    }
    let hours = age.num_hours();
    if hours < 48 {
        return format!("{hours} hours");
    }
    format!("{} days", age.num_days())
}

/// The one-line stale-scan warning, or `None` while the report is fresh
/// (younger than [`STALE_REPORT_AFTER_HOURS`]).
pub fn stale_notice(generated_at: DateTime<Utc>, now: DateTime<Utc>) -> Option<String> {
    let age = now - generated_at;
    if age <= chrono::Duration::hours(STALE_REPORT_AFTER_HOURS) {
        return None;
    }
    Some(format!(
        "last scan: {} ago. Run `husk scan` to refresh",
        format_age(age)
    ))
}

/// Environment override for the cache directory (tests, sandboxes, CI). When
/// set and non-empty, `HUSK_CACHE_DIR` replaces `~/.cache/husk` wholesale;
/// the seam that keeps `cargo test` off the developer's real scan cache on
/// every platform (unlike `XDG_CACHE_HOME`, which macOS ignores).
pub const CACHE_DIR_ENV: &str = "HUSK_CACHE_DIR";

fn cache_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(CACHE_DIR_ENV).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let base = dirs::cache_dir().context("could not locate XDG cache directory")?;
    Ok(base.join("husk"))
}

/// The cache directory, created if missing and enforced owner-only (0700).
/// Every writer resolves through this; readers use [`cache_dir`] and must not
/// create anything. The cache holds the full finding set, the package
/// inventory, and every absolute path ever scanned, so it is not
/// world-readable even though its contents are re-fetchable.
fn cache_dir_private() -> Result<PathBuf> {
    let dir = cache_dir()?;
    crate::paths::ensure_dir_private(&dir)?;
    Ok(dir)
}

/// The scan-index database path, with the cache directory created 0700.
/// SQLite creates the file itself, so the mode is asserted after the open.
fn scan_index_path() -> Result<PathBuf> {
    Ok(cache_dir_private()?.join("husk.db"))
}

/// The local advisory mirror directory (per-ecosystem SQLite files plus
/// `state.json`), created 0700 like the rest of the cache: advisory data is
/// public, but which ecosystems a machine holds is inventory-shaped.
pub fn intel_dir() -> Result<PathBuf> {
    let dir = cache_dir_private()?.join("intel");
    crate::paths::ensure_dir_private(&dir)?;
    Ok(dir)
}

/// How long an untouched [`KvCache`] row survives. Every caller's TTL is
/// measured in hours (the KEV catalog, EPSS scores), and a live key is
/// rewritten on each re-fetch, so a row not written for a month belongs to a
/// key nothing asks for any more.
const KV_MAX_AGE_SECS: i64 = 30 * 24 * 60 * 60;

/// Free space that justifies rewriting the whole database. VACUUM is O(size)
/// and takes the write lock, so it must never run on an ordinary open; pages
/// only reach the freelist after a prune, and a prune only happens on a
/// scanner-version change (which orphans the entire index at once) or when a
/// key stops being fetched. Both are rare, and 64 MiB of dead pages is worth
/// one rewrite.
const VACUUM_FREE_BYTES: i64 = 64 * 1024 * 1024;

/// Tighten the database and the WAL sidecars SQLite creates alongside it: all
/// three carry finding and path data, and SQLite opens them with the process
/// umask. Best-effort, like every other cache operation.
fn restrict_database(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let _ = crate::paths::restrict_existing_file(Path::new(&name));
    }
}

/// Drop every `file_scans` row written by a different scanner version.
///
/// [`SCAN_INDEX_VERSION`] embeds the crate version, so a release orphans the
/// entire index at once; without this prune the database grows without bound
/// across upgrades. Rows for a different `max_file_bytes` are kept: that
/// dimension is a live scan option, not a dead generation.
fn prune_stale_versions(connection: &Connection) {
    // `min`/`max` over the leading column of `idx_file_scans_version` are index
    // seeks, so the case that happens on every ordinary open (one version
    // present, nothing to delete) costs two lookups. The `DELETE` itself needs
    // rowids and therefore scans the table, which is why it is not the thing
    // run unconditionally: an index holding a large tree would pay that scan
    // once per cache open, and every walk stage opens its own.
    let bounds = connection.query_row(
        "SELECT min(scanner_version), max(scanner_version) FROM file_scans",
        [],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        },
    );
    let Ok((Some(low), Some(high))) = bounds else {
        return;
    };
    if low == SCAN_INDEX_VERSION && high == SCAN_INDEX_VERSION {
        return;
    }
    let Ok(deleted) = connection.execute(
        "DELETE FROM file_scans WHERE scanner_version <> ?1",
        params![SCAN_INDEX_VERSION],
    ) else {
        return;
    };
    if deleted > 0 {
        vacuum_if_bloated(connection);
    }
}

/// Drop `kv` rows untouched for longer than [`KV_MAX_AGE_SECS`]. A live key is
/// rewritten on every re-fetch, so only keys nothing asks for any more age out;
/// otherwise a retired cache key's blob stays in the file forever.
fn prune_aged_entries(connection: &Connection, now: i64) {
    let Ok(deleted) = connection.execute(
        "DELETE FROM kv WHERE fetched_at < ?1",
        params![now.saturating_sub(KV_MAX_AGE_SECS)],
    ) else {
        return;
    };
    if deleted > 0 {
        vacuum_if_bloated(connection);
    }
}

/// Reclaim the database file if a prune left enough free pages behind. Two
/// cheap pragmas on the common path. Best-effort: a failed VACUUM (another
/// husk process holds the write lock) means a larger file, never a failed scan.
fn vacuum_if_bloated(connection: &Connection) {
    let free_pages = connection
        .query_row("PRAGMA freelist_count", [], |row| row.get::<_, i64>(0))
        .unwrap_or(0);
    let page_size = connection
        .query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
        .unwrap_or(0);
    if free_pages.saturating_mul(page_size) >= VACUUM_FREE_BYTES {
        let _ = connection.execute_batch("VACUUM");
    }
}

/// One walk's batched view of the per-file findings index, keyed to a single
/// scanner version + size cap: the whole matching table slice is loaded into
/// an in-memory map in ONE query at open, consulted lock-free during the walk
/// ([`ScanCache::lookup`]), and every newly scanned file is queued
/// ([`ScanCache::record`]) and written back in ONE transaction at
/// [`ScanCache::flush`]. The per-file hot path never touches SQLite: a
/// per-file design pays two globally-mutexed SQLite round-trips per file,
/// which serializes the walker threads and dominates warm rescans.
///
/// Memory: the map holds a path string + findings JSON per previously indexed
/// file. Findings are sparse (almost every blob is `[]`), so this is on the
/// order of a couple hundred bytes per file: a few MB at a 20k-file
/// corpus, and still tens-of-MB acceptable at ~1M files. Revisit
/// with a size guard only if real scans outgrow that.
pub struct ScanCache {
    connection: Mutex<Connection>,
    max_file_bytes: u64,
    cached: HashMap<String, CachedFile>,
    pending: Mutex<Vec<PendingFile>>,
}

/// One previously indexed file, as loaded from `file_scans`. Findings stay as
/// their stored JSON: deserialization happens per cache *hit* on the walker
/// threads (parallel), not serially at load time.
struct CachedFile {
    size: u64,
    modified_ns: i128,
    bytes_scanned: u64,
    findings_json: String,
}

/// One freshly scanned file queued for the end-of-walk write-back.
struct PendingFile {
    path: String,
    size: u64,
    modified_ns: i128,
    bytes_scanned: u64,
    findings_json: String,
}

#[derive(Clone, Copy)]
pub struct FileFingerprint {
    size: u64,
    modified_ns: i128,
}

/// Lock a cache mutex, absorbing poison: a panicked walker thread must not
/// take the cache (and with it the whole scan) down.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

impl ScanCache {
    pub fn open(max_file_bytes: u64) -> Result<Self> {
        Self::open_at(&scan_index_path()?, max_file_bytes)
    }

    /// Open at an explicit database path, the seam that keeps unit tests in a
    /// tempdir, off the developer's real cache.
    pub fn open_at(path: &Path, max_file_bytes: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("open scan index {}", path.display()))?;
        // Concurrent husk processes (a daemon rescan racing an agent hook, or
        // parallel test children) share this db; without a busy timeout the
        // second opener gets an immediate SQLITE_BUSY while the first holds
        // the creation/WAL lock, failing its whole scan. Wait instead.
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS file_scans (
                path TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                modified_ns TEXT NOT NULL,
                scanner_version TEXT NOT NULL,
                max_file_bytes INTEGER NOT NULL,
                bytes_scanned INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_file_scans_version
                ON file_scans(scanner_version, max_file_bytes);",
        )?;
        restrict_database(path);
        prune_stale_versions(&connection);
        // A failed bulk load degrades to an empty map (every file is a miss);
        // the write-back side stays usable so the next scan is warm again.
        let cached = Self::load_all(&connection, max_file_bytes).unwrap_or_default();
        Ok(Self {
            connection: Mutex::new(connection),
            max_file_bytes,
            cached,
            pending: Mutex::new(Vec::new()),
        })
    }

    /// The one read: every row for this scanner version + size cap. Rows that
    /// fail to parse are simply absent (a miss, rescanned and overwritten).
    fn load_all(
        connection: &Connection,
        max_file_bytes: u64,
    ) -> Result<HashMap<String, CachedFile>> {
        let mut statement = connection.prepare(
            "SELECT path, size, modified_ns, bytes_scanned, findings_json
             FROM file_scans
             WHERE scanner_version = ?1 AND max_file_bytes = ?2",
        )?;
        let rows =
            statement.query_map(params![SCAN_INDEX_VERSION, max_file_bytes as i64], |row| {
                let path: String = row.get(0)?;
                // SQLite stores integers as i64; rusqlite does not map u64
                // directly (a u64 can overflow i64), so read i64 and widen.
                let size: i64 = row.get(1)?;
                let modified_ns: String = row.get(2)?;
                let bytes_scanned: i64 = row.get(3)?;
                let findings_json: String = row.get(4)?;
                Ok((path, size, modified_ns, bytes_scanned, findings_json))
            })?;
        let mut cached = HashMap::new();
        for row in rows {
            let (path, size, modified_ns, bytes_scanned, findings_json) = row?;
            let Ok(modified_ns) = modified_ns.parse::<i128>() else {
                continue;
            };
            cached.insert(
                path,
                CachedFile {
                    size: size as u64,
                    modified_ns,
                    bytes_scanned: bytes_scanned as u64,
                    findings_json,
                },
            );
        }
        Ok(cached)
    }

    /// The cached findings for `path`, if its fingerprint is unchanged.
    /// Pure in-memory: no SQLite, no lock. Undeserializable findings are a
    /// miss (the file is rescanned and the row overwritten at flush).
    pub fn lookup(&self, path: &Path, fingerprint: FileFingerprint) -> Option<(Vec<Finding>, u64)> {
        let entry = self.cached.get(&path.display().to_string())?;
        if entry.size != fingerprint.size || entry.modified_ns != fingerprint.modified_ns {
            return None;
        }
        let findings = serde_json::from_str(&entry.findings_json).ok()?;
        Some((findings, entry.bytes_scanned))
    }

    /// Queue a freshly scanned file for the end-of-walk write-back. The JSON
    /// serialization happens here on the walker thread (parallel); the queue
    /// push is the only synchronization on the scan path, and only for files
    /// that actually got scanned (zero contention on a fully warm rescan).
    pub fn record(
        &self,
        path: &Path,
        fingerprint: FileFingerprint,
        bytes_scanned: u64,
        findings: &[Finding],
    ) {
        let Ok(findings_json) = serde_json::to_string(findings) else {
            return;
        };
        lock(&self.pending).push(PendingFile {
            path: path.display().to_string(),
            size: fingerprint.size,
            modified_ns: fingerprint.modified_ns,
            bytes_scanned,
            findings_json,
        });
    }

    /// The one write: upsert every queued file in a single transaction. The
    /// cache is a pure accelerator, so a failed write-back means a slower next
    /// scan, never a failed one; errors are swallowed.
    pub fn flush(&self) {
        let pending = std::mem::take(&mut *lock(&self.pending));
        if pending.is_empty() {
            return;
        }
        let _ = self.write_back(&pending);
    }

    fn write_back(&self, pending: &[PendingFile]) -> Result<()> {
        let mut connection = lock(&self.connection);
        let transaction = connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                "INSERT INTO file_scans
                    (path, size, modified_ns, scanner_version, max_file_bytes, bytes_scanned, findings_json, scanned_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(path) DO UPDATE SET
                    size = excluded.size,
                    modified_ns = excluded.modified_ns,
                    scanner_version = excluded.scanner_version,
                    max_file_bytes = excluded.max_file_bytes,
                    bytes_scanned = excluded.bytes_scanned,
                    findings_json = excluded.findings_json,
                    scanned_at = excluded.scanned_at",
            )?;
            let scanned_at = Utc::now().to_rfc3339();
            for file in pending {
                statement.execute(params![
                    file.path,
                    file.size as i64,
                    file.modified_ns.to_string(),
                    SCAN_INDEX_VERSION,
                    self.max_file_bytes as i64,
                    file.bytes_scanned as i64,
                    file.findings_json,
                    scanned_at,
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }
}

/// A tiny TTL'd blob store in the scan-index database (`husk.db`).
///
/// For re-fetchable network artifacts whose upstream refresh cadence is
/// measured in hours (the CISA KEV catalog, FIRST EPSS scores): read with
/// [`KvCache::get_fresh`], write with [`KvCache::put`]. The cache is a pure
/// accelerator: every failure (open, read, corrupt row, stale entry) must
/// look like a plain miss to the caller, never a new failure mode, so
/// `get_fresh` swallows errors into `None` and callers ignore `put` errors.
pub struct KvCache {
    connection: Mutex<Connection>,
}

impl KvCache {
    pub fn open() -> Result<Self> {
        Self::open_at(&scan_index_path()?)
    }

    /// Open at an explicit database path, the seam that keeps unit tests in a
    /// tempdir, off the developer's real cache.
    pub fn open_at(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let connection =
            Connection::open(path).with_context(|| format!("open kv cache {}", path.display()))?;
        // Same concurrency posture as `ScanCache`: another husk process (or the
        // scan index side of this one) may hold the db; wait, don't fail.
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                fetched_at INTEGER NOT NULL,
                body BLOB NOT NULL
            );",
        )?;
        restrict_database(path);
        prune_aged_entries(&connection, Utc::now().timestamp());
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// The body stored under `key`, if it was written within `ttl`. Absent,
    /// stale, future-stamped (clock skew), and unreadable entries are all the
    /// same thing to the caller: `None`, re-fetch.
    pub fn get_fresh(&self, key: &str, ttl: std::time::Duration) -> Option<Vec<u8>> {
        self.get_fresh_at(key, ttl, Utc::now().timestamp())
    }

    /// Clock-injected core of [`KvCache::get_fresh`] (the TTL test seam).
    pub fn get_fresh_at(&self, key: &str, ttl: std::time::Duration, now: i64) -> Option<Vec<u8>> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let (fetched_at, body) = connection
            .query_row(
                "SELECT fetched_at, body FROM kv WHERE key = ?1",
                params![key],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .ok()
            .flatten()?;
        // A negative age (future-stamped row) fails the u64 conversion → miss.
        let age = u64::try_from(now.checked_sub(fetched_at)?).ok()?;
        (age <= ttl.as_secs()).then_some(body)
    }

    /// Store `body` under `key`, stamped now. Overwrites any prior entry.
    pub fn put(&self, key: &str, body: &[u8]) -> Result<()> {
        self.put_at(key, body, Utc::now().timestamp())
    }

    /// Timestamp-injected core of [`KvCache::put`] (the TTL test seam).
    pub fn put_at(&self, key: &str, body: &[u8], fetched_at: i64) -> Result<()> {
        let connection = self
            .connection
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        connection.execute(
            "INSERT INTO kv (key, fetched_at, body) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET
                fetched_at = excluded.fetched_at,
                body = excluded.body",
            params![key, fetched_at, body],
        )?;
        Ok(())
    }
}

pub fn fingerprint(metadata: &fs::Metadata) -> FileFingerprint {
    let modified_ns = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| {
            i128::from(duration.as_secs()) * 1_000_000_000i128 + i128::from(duration.subsec_nanos())
        })
        .unwrap_or(0);
    FileFingerprint {
        size: metadata.len(),
        modified_ns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_notice_fires_only_past_the_threshold() {
        let now = Utc::now();
        assert_eq!(stale_notice(now, now), None, "fresh report");
        assert_eq!(
            stale_notice(now - chrono::Duration::hours(23), now),
            None,
            "within the 24h window"
        );
        assert_eq!(
            stale_notice(now - chrono::Duration::hours(26), now).as_deref(),
            Some("last scan: 26 hours ago. Run `husk scan` to refresh")
        );
        assert_eq!(
            stale_notice(now - chrono::Duration::days(3), now).as_deref(),
            Some("last scan: 3 days ago. Run `husk scan` to refresh")
        );
    }

    #[test]
    fn age_formatting_scales_minutes_hours_days() {
        assert_eq!(format_age(chrono::Duration::minutes(1)), "1 minute");
        assert_eq!(format_age(chrono::Duration::minutes(45)), "45 minutes");
        assert_eq!(format_age(chrono::Duration::hours(3)), "3 hours");
        assert_eq!(format_age(chrono::Duration::hours(26)), "26 hours");
        assert_eq!(format_age(chrono::Duration::days(2)), "2 days");
        assert_eq!(format_age(chrono::Duration::days(10)), "10 days");
        // A clock skewed backwards never panics or goes negative.
        assert_eq!(format_age(chrono::Duration::minutes(-5)), "0 minutes");
    }

    #[test]
    fn schema_drift_is_treated_as_no_cache_not_an_error() {
        // A cached report from a build whose ScanReport schema has since
        // changed (crate version unchanged between dev builds) must not crash
        // every command that reads the cache; it should look like no cache.
        let stale = format!(
            r#"{{"version":"{CACHE_VERSION}","saved_at":"2024-01-01T00:00:00Z","report":{{"totally":"unrecognizable"}}}}"#
        );
        assert!(parse_cache_envelope(&stale).is_none());
    }

    #[test]
    fn version_mismatch_is_treated_as_no_cache() {
        let report = serde_json::to_string(&ScanReport::empty(vec![])).unwrap();
        let mismatched = format!(
            r#"{{"version":"husk-0.0.0-ancient","saved_at":"2024-01-01T00:00:00Z","report":{report}}}"#
        );
        assert!(parse_cache_envelope(&mismatched).is_none());
    }

    #[test]
    fn a_report_from_an_older_shape_is_treated_as_no_cache() {
        // Fields this build derives are absent there, and serde would fill them
        // with a zero the UI would then render as a count.
        let mut report = ScanReport::empty(vec![]);
        report.api_version = crate::model::REPORT_API_VERSION - 1;
        let json = serde_json::to_string(&report).unwrap();
        let older = format!(
            r#"{{"version":"{CACHE_VERSION}","saved_at":"2024-01-01T00:00:00Z","report":{json}}}"#
        );
        assert!(parse_cache_envelope(&older).is_none());
    }

    fn report_for(root: &str) -> ScanReport {
        ScanReport::empty(vec![PathBuf::from(root)])
    }

    fn machine_report_for(root: &str) -> ScanReport {
        let mut report = report_for(root);
        report.kind = crate::model::ScanKind::Machine;
        report
    }

    fn load_project(dir: &Path, root: &str) -> Option<ScanReport> {
        read_report(&dir.join(project_report_name(&[PathBuf::from(root)])))
    }

    #[test]
    fn saving_the_same_roots_twice_replaces_that_project_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        save_latest_report_in(dir.path(), &report_for("/only")).expect("save");
        save_latest_report_in(dir.path(), &report_for("/only")).expect("resave");

        assert!(load_project(dir.path(), "/only").is_some());
        assert_eq!(
            stored_report_paths(dir.path()).len(),
            1,
            "one file per scanned target, not one per run"
        );
    }

    /// The retention rule this storage layout exists for: a project's result
    /// stays readable however many *other* projects are scanned after it.
    #[test]
    fn scanning_other_projects_never_evicts_a_projects_result() {
        let dir = tempfile::tempdir().expect("tempdir");
        save_latest_report_in(dir.path(), &report_for("/first")).expect("save");
        for i in 0..(KEPT_REPORTS - 2) {
            save_latest_report_in(dir.path(), &report_for(&format!("/other{i}"))).expect("save");
        }

        let kept = load_project(dir.path(), "/first").expect("first project still stored");
        assert_eq!(kept.roots, vec![PathBuf::from("/first")]);
    }

    #[test]
    fn project_reports_are_capped_least_recent_out() {
        let dir = tempfile::tempdir().expect("tempdir");
        for i in 0..(KEPT_REPORTS + 3) {
            save_latest_report_in(dir.path(), &report_for(&format!("/root{i}"))).expect("save");
            // mtime resolution is coarse enough that same-millisecond writes
            // would make eviction order arbitrary.
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let stored = stored_report_paths(dir.path());
        assert_eq!(stored.len(), KEPT_REPORTS);
        assert!(
            load_project(dir.path(), "/root0").is_none(),
            "oldest evicted"
        );
        let newest = format!("/root{}", KEPT_REPORTS + 2);
        assert!(load_project(dir.path(), &newest).is_some(), "newest kept");
    }

    #[test]
    fn a_machine_report_is_never_evicted_by_project_scans() {
        let dir = tempfile::tempdir().expect("tempdir");
        save_latest_report_in(dir.path(), &machine_report_for("/home/user")).expect("save machine");
        for i in 0..(KEPT_REPORTS + 3) {
            save_latest_report_in(dir.path(), &report_for(&format!("/root{i}"))).expect("save");
        }

        let machine = read_report(&dir.path().join(MACHINE_REPORT)).expect("machine kept");
        assert_eq!(machine.kind, crate::model::ScanKind::Machine);
    }

    #[test]
    fn a_report_left_by_an_older_naming_scheme_is_swept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let orphan = dir.path().join("latest-report.json");
        fs::write(&orphan, b"{}").expect("write orphan");
        save_latest_report_in(dir.path(), &report_for("/current")).expect("save");

        assert!(
            !orphan.exists(),
            "unreachable report removed, not left to rot"
        );
        assert!(load_project(dir.path(), "/current").is_some());
    }

    #[test]
    fn kv_round_trips_and_overwrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = KvCache::open_at(&dir.path().join("husk.db")).expect("open kv cache");
        let ttl = std::time::Duration::from_secs(60);
        assert!(cache.get_fresh("k", ttl).is_none());
        cache.put("k", b"one").expect("put");
        assert_eq!(cache.get_fresh("k", ttl).as_deref(), Some(&b"one"[..]));
        cache.put("k", b"two").expect("overwrite");
        assert_eq!(cache.get_fresh("k", ttl).as_deref(), Some(&b"two"[..]));
        assert!(cache.get_fresh("other", ttl).is_none());
    }

    #[test]
    fn kv_entries_expire_after_ttl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = KvCache::open_at(&dir.path().join("husk.db")).expect("open kv cache");
        let now = 1_700_000_000i64;
        cache.put_at("k", b"body", now - 3_600).expect("put");
        let hour = std::time::Duration::from_secs(3_600);
        assert!(cache.get_fresh_at("k", 2 * hour, now).is_some());
        assert!(cache.get_fresh_at("k", hour / 2, now).is_none());
        // A future-stamped entry (clock skew) is a miss, not "infinitely fresh".
        cache.put_at("skew", b"x", now + 999).expect("put");
        assert!(cache.get_fresh_at("skew", 2 * hour, now).is_none());
    }

    #[test]
    fn kv_shares_the_scan_index_database_file() {
        // KvCache lives in the same husk.db as ScanCache; both must be able
        // to open the same file (WAL + busy_timeout) without clobbering each
        // other's tables.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("husk.db");
        let cache = KvCache::open_at(&path).expect("open kv cache");
        cache.put("k", b"v").expect("put");
        let again = KvCache::open_at(&path).expect("reopen");
        assert_eq!(
            again
                .get_fresh("k", std::time::Duration::from_secs(60))
                .as_deref(),
            Some(&b"v"[..])
        );
    }

    fn sample_finding() -> Finding {
        Finding::from_rule("git-hook")
            .id("test-finding")
            .summary("a cached finding")
    }

    #[test]
    fn scan_cache_round_trips_across_sessions_after_flush() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("husk.db");
        let path = Path::new("/scanned/file.txt");
        let fingerprint = FileFingerprint {
            size: 42,
            modified_ns: 1_700_000_000_000_000_000,
        };

        let cache = ScanCache::open_at(&db, 1024).expect("open");
        assert!(cache.lookup(path, fingerprint).is_none());
        cache.record(path, fingerprint, 42, &[sample_finding()]);
        // Unflushed writes are invisible to a new session...
        let unflushed = ScanCache::open_at(&db, 1024).expect("reopen");
        assert!(unflushed.lookup(path, fingerprint).is_none());
        // ...and one flush makes them durable.
        cache.flush();
        let warm = ScanCache::open_at(&db, 1024).expect("reopen");
        let (findings, bytes_scanned) = warm.lookup(path, fingerprint).expect("cache hit");
        assert_eq!(bytes_scanned, 42);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "test-finding");
    }

    #[test]
    fn scan_cache_misses_on_changed_fingerprint_or_size_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("husk.db");
        let path = Path::new("/scanned/file.txt");
        let fingerprint = FileFingerprint {
            size: 42,
            modified_ns: 1_700_000_000_000_000_000,
        };
        let cache = ScanCache::open_at(&db, 1024).expect("open");
        cache.record(path, fingerprint, 42, &[]);
        cache.flush();

        let warm = ScanCache::open_at(&db, 1024).expect("reopen");
        assert!(warm.lookup(path, fingerprint).is_some());
        let touched = FileFingerprint {
            modified_ns: fingerprint.modified_ns + 1,
            ..fingerprint
        };
        assert!(warm.lookup(path, touched).is_none());
        let grown = FileFingerprint {
            size: fingerprint.size + 1,
            ..fingerprint
        };
        assert!(warm.lookup(path, grown).is_none());
        // A different size cap is a different cache dimension entirely.
        let other_cap = ScanCache::open_at(&db, 2048).expect("reopen with other cap");
        assert!(other_cap.lookup(path, fingerprint).is_none());
    }

    #[test]
    fn scan_cache_misses_on_scanner_version_change() {
        // Rows written by an older detector version must never serve stale
        // findings; the SCAN_INDEX_VERSION bump rule depends on it.
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("husk.db");
        let path = Path::new("/scanned/file.txt");
        let fingerprint = FileFingerprint {
            size: 42,
            modified_ns: 1_700_000_000_000_000_000,
        };
        let cache = ScanCache::open_at(&db, 1024).expect("open");
        cache.record(path, fingerprint, 42, &[]);
        cache.flush();

        let connection = Connection::open(&db).expect("open raw");
        connection
            .execute(
                "UPDATE file_scans SET scanner_version = 'husk-0.0.0-ancient'",
                [],
            )
            .expect("age the row");
        drop(connection);

        let warm = ScanCache::open_at(&db, 1024).expect("reopen");
        assert!(warm.lookup(path, fingerprint).is_none());
    }

    /// Rows in `file_scans`, regardless of scanner version.
    fn row_count(db: &Path, table: &str) -> i64 {
        let connection = Connection::open(db).expect("open raw");
        connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("count")
    }

    #[test]
    fn scan_cache_prunes_rows_left_by_another_scanner_version() {
        // SCAN_INDEX_VERSION embeds the crate version, so every release
        // orphans the whole index; unpruned, those rows are dead weight forever.
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("husk.db");
        let fingerprint = FileFingerprint {
            size: 42,
            modified_ns: 1_700_000_000_000_000_000,
        };
        let cache = ScanCache::open_at(&db, 1024).expect("open");
        cache.record(Path::new("/scanned/old.txt"), fingerprint, 42, &[]);
        cache.flush();

        let connection = Connection::open(&db).expect("open raw");
        connection
            .execute(
                "UPDATE file_scans SET scanner_version = 'husk-0.0.0-ancient'",
                [],
            )
            .expect("age the row");
        drop(connection);
        assert_eq!(row_count(&db, "file_scans"), 1, "row present before open");

        let warm = ScanCache::open_at(&db, 1024).expect("reopen");
        assert_eq!(
            row_count(&db, "file_scans"),
            0,
            "stale-version rows are deleted, not merely ignored"
        );
        // Rows for the current version survive the prune.
        warm.record(Path::new("/scanned/new.txt"), fingerprint, 42, &[]);
        warm.flush();
        drop(warm);
        ScanCache::open_at(&db, 1024).expect("reopen");
        assert_eq!(row_count(&db, "file_scans"), 1, "current rows are kept");
    }

    #[test]
    fn kv_rows_untouched_past_the_max_age_are_deleted_on_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("husk.db");
        let cache = KvCache::open_at(&db).expect("open kv cache");
        let now = Utc::now().timestamp();
        cache
            .put_at("retired", b"body", now - KV_MAX_AGE_SECS - 1)
            .expect("put aged");
        cache.put_at("live", b"body", now).expect("put fresh");
        drop(cache);

        let reopened = KvCache::open_at(&db).expect("reopen");
        assert_eq!(row_count(&db, "kv"), 1, "only the aged row is deleted");
        assert!(
            reopened
                .get_fresh("live", std::time::Duration::from_secs(60))
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_database_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("husk.db");
        fs::write(&db, b"").expect("seed");
        fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).expect("loosen");
        let cache = ScanCache::open_at(&db, 1024).expect("open");
        cache.record(
            Path::new("/scanned/file.txt"),
            FileFingerprint {
                size: 1,
                modified_ns: 1,
            },
            1,
            &[],
        );
        cache.flush();
        for suffix in ["", "-wal"] {
            let path = PathBuf::from(format!("{}{suffix}", db.display()));
            if let Ok(metadata) = fs::metadata(&path) {
                assert_eq!(
                    metadata.permissions().mode() & 0o777,
                    0o600,
                    "{} must not be readable by other local users",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn scan_cache_open_fails_cleanly_on_an_unusable_database() {
        // The walk degrades to a full uncached scan when the cache can't open
        // (`ScanCache::open(..).ok()`), so open must error, not panic.
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(ScanCache::open_at(dir.path(), 1024).is_err());
    }

    #[test]
    fn matching_version_and_valid_report_round_trips() {
        let report = ScanReport::empty(vec![]);
        let envelope = serde_json::to_string(&CacheEnvelope {
            version: CACHE_VERSION.to_string(),
            saved_at: Utc::now(),
            report: report.clone(),
        })
        .unwrap();
        let loaded = parse_cache_envelope(&envelope).expect("should parse");
        assert_eq!(loaded.roots, report.roots);
    }
}
