//! The local advisory mirror end to end: bundle bootstrap (index + sha256 +
//! atomic swap), the scan-time OSV delta (upserts, withdrawals, failure
//! isolation), local range matching parity against recorded live OSV
//! verdicts, and the honest provider row a scan must always carry. All
//! offline: HTTP endpoints are loopback stubs, advisory data is recorded
//! fixtures under `tst/intel/`.

mod common;

use husk::intel::{self, fresh, sync};
use husk::model::PackageRef;
use husk::rule::Category;
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn package(ecosystem: &str, name: &str, version: &str) -> PackageRef {
    PackageRef {
        ecosystem: ecosystem.to_string(),
        name: name.to_string(),
        version: version.to_string(),
        manifest_path: PathBuf::from("/home/dev/project/lockfile"),
        line: None,
    }
}

/// Insert one advisory row plus its `affected` name rows, the same rows the
/// platform builder and the delta writer produce.
fn insert_advisory(conn: &Connection, id: &str, modified: &str, record: &str, names: &[&str]) {
    conn.execute(
        "INSERT OR REPLACE INTO advisories (id, modified, record) VALUES (?1, ?2, ?3)",
        [id, modified, record],
    )
    .expect("insert advisory");
    for name in names {
        conn.execute(
            "INSERT INTO affected (name, advisory_id) VALUES (?1, ?2)",
            [*name, id],
        )
        .expect("insert affected");
    }
}

fn osv_record(
    id: &str,
    ecosystem: &str,
    name: &str,
    modified: &str,
    versions: serde_json::Value,
    ranges: serde_json::Value,
) -> String {
    serde_json::json!({
        "id": id,
        "modified": modified,
        "summary": format!("{id} affects {name}"),
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": name},
            "versions": versions,
            "ranges": ranges,
        }],
    })
    .to_string()
}

fn zip_single(entry_name: &str, content: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(&mut cursor);
    writer
        .start_file(
            entry_name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .expect("start zip entry");
    writer.write_all(content).expect("write zip entry");
    writer.finish().expect("finish zip");
    cursor.into_inner()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn index_json(entries: &[(&str, &str, String, usize)]) -> Vec<u8> {
    let rows: Vec<serde_json::Value> = entries
        .iter()
        .map(|(ecosystem, file, sha256, bytes)| {
            serde_json::json!({
                "ecosystem": ecosystem,
                "file": file,
                "sha256": sha256,
                "bytes": bytes,
                "records": 1,
                "built_at": "2026-08-20T00:00:00Z",
            })
        })
        .collect();
    serde_json::to_vec(&rows).expect("serialize index")
}

type Routes = Arc<HashMap<String, (&'static str, Vec<u8>)>>;

/// Serve `routes` (request path to status + body) on a loopback listener,
/// one response per connection, until the returned handle is dropped with
/// the test's runtime.
async fn serve_routes(
    routes: HashMap<String, (&'static str, Vec<u8>)>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let address = format!(
        "http://{}",
        listener.local_addr().expect("listener address")
    );
    let routes: Routes = Arc::new(routes);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(handle_connection(socket, routes.clone()));
        }
    });
    (address, handle)
}

async fn handle_connection(mut socket: tokio::net::TcpStream, routes: Routes) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let head = loop {
        let Ok(read) = socket.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break String::from_utf8_lossy(&raw[..end]).to_string();
        }
    };
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let (status, body) = routes
        .get(&path)
        .map(|(status, body)| (*status, body.clone()))
        .unwrap_or(("404 Not Found", b"no such file".to_vec()));
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.write_all(&body).await;
    let _ = socket.shutdown().await;
}

fn advisory_count(path: &Path) -> i64 {
    let conn = Connection::open(path).expect("open db");
    conn.query_row("SELECT COUNT(*) FROM advisories", [], |row| row.get(0))
        .expect("count")
}

// The env guard must intentionally span the awaits: the URL overrides are
// process environment, and each async test here runs single-threaded.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn bundle_bootstrap_delta_and_match_cover_the_full_path() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let scratch = tempfile::tempdir().expect("tempdir");

    // The published bundle: evil-a (malware) and evil-w (later withdrawn).
    let db_path = scratch.path().join("npm.db");
    let conn = Connection::open(&db_path).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    let record_a = osv_record(
        "MAL-2026-9001",
        "npm",
        "evil-a",
        "2026-08-01T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "MAL-2026-9001",
        "2026-08-01T00:00:00Z",
        &record_a,
        &["evil-a"],
    );
    let record_w = osv_record(
        "GHSA-wwww-wwww-wwww",
        "npm",
        "evil-w",
        "2026-08-01T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "GHSA-wwww-wwww-wwww",
        "2026-08-01T00:00:00Z",
        &record_w,
        &["evil-w"],
    );
    drop(conn);
    let zip = zip_single("npm.db", &std::fs::read(&db_path).expect("read db"));

    // The delta: evil-b is new, evil-w has been withdrawn upstream.
    let record_b = osv_record(
        "GHSA-bbbb-bbbb-bbbb",
        "npm",
        "evil-b",
        "2026-08-22T10:00:00Z",
        serde_json::json!([]),
        serde_json::json!([{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "2.0.0"}
        ]}]),
    );
    let withdrawn_b = serde_json::json!({
        "id": "GHSA-wwww-wwww-wwww",
        "modified": "2026-08-22T09:00:00Z",
        "withdrawn": "2026-08-22T09:00:00Z",
        "summary": "withdrawn upstream",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "evil-w"},
            "versions": ["1.0.0"],
        }],
    })
    .to_string();
    let csv = "2026-08-22T10:00:00Z,GHSA-bbbb-bbbb-bbbb\n\
               2026-08-22T09:00:00Z,GHSA-wwww-wwww-wwww\n\
               2026-08-01T00:00:00Z,MAL-2026-9001\n";

    let mut routes = HashMap::new();
    routes.insert(
        "/index.json".to_string(),
        (
            "200 OK",
            index_json(&[("npm", "npm.db.zip", sha256_hex(&zip), zip.len())]),
        ),
    );
    routes.insert("/npm.db.zip".to_string(), ("200 OK", zip));
    routes.insert(
        "/npm/modified_id.csv".to_string(),
        ("200 OK", csv.as_bytes().to_vec()),
    );
    routes.insert(
        "/npm/GHSA-bbbb-bbbb-bbbb.json".to_string(),
        ("200 OK", record_b.into_bytes()),
    );
    routes.insert(
        "/npm/GHSA-wwww-wwww-wwww.json".to_string(),
        ("200 OK", withdrawn_b.into_bytes()),
    );
    let (address, _server) = serve_routes(routes).await;
    let mut env = common::EnvVarGuard::acquire();
    env.set("HUSK_INTEL_URL", &address);
    env.set("HUSK_OSV_URL", &address);

    let outcome = sync::sync(mirror.path(), None).await.expect("sync");
    assert!(outcome.failed.is_empty(), "failed: {:?}", outcome.failed);
    assert_eq!(outcome.updated.len(), 1);
    assert_eq!(outcome.unchanged, 0);
    assert!(intel::load_state(mirror.path()).synced_at.is_some());

    let delta = fresh::refresh(mirror.path()).await;
    assert!(delta.failed.is_empty(), "failed: {:?}", delta.failed);
    assert_eq!(delta.ecosystems, 1);
    assert_eq!(delta.applied, 2, "the new record and the withdrawal");

    let packages = [
        package("npm", "evil-a", "1.0.0"),
        package("npm", "evil-b", "1.5.0"),
        package("npm", "evil-b", "2.0.0"),
        package("npm", "evil-w", "1.0.0"),
    ];
    let matched = intel::match_packages(mirror.path(), &packages);
    assert_eq!(matched.checked, 4);
    assert!(matched.missing_ecosystems.is_empty());
    let mut ids: Vec<&str> = matched
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect();
    ids.sort();
    assert_eq!(ids.len(), 2, "ids: {ids:?}");
    assert!(ids[0].starts_with("osv:GHSA-bbbb-bbbb-bbbb:"), "{}", ids[0]);
    assert!(ids[1].starts_with("osv:MAL-2026-9001:"), "{}", ids[1]);
    let malware = matched
        .findings
        .iter()
        .find(|finding| finding.id.starts_with("osv:MAL-"))
        .expect("malware finding");
    assert_eq!(malware.category, Category::Malware);

    let row = intel::provider_row(mirror.path(), &matched, true, Some(&delta));
    assert_eq!(row.name, "OSV mirror");
    assert!(row.ok);
    assert!(
        row.message.contains("pulled from OSV"),
        "message: {}",
        row.message
    );
}

// See above for the guard-across-await rationale.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn a_sha256_mismatch_rejects_the_artifact() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let zip = zip_single("npm.db", b"whatever the content, the hash is wrong");
    let mut routes = HashMap::new();
    routes.insert(
        "/index.json".to_string(),
        (
            "200 OK",
            index_json(&[("npm", "npm.db.zip", "0".repeat(64), zip.len())]),
        ),
    );
    routes.insert("/npm.db.zip".to_string(), ("200 OK", zip));
    let (address, _server) = serve_routes(routes).await;
    let mut env = common::EnvVarGuard::acquire();
    env.set("HUSK_INTEL_URL", &address);

    let outcome = sync::sync(mirror.path(), None).await.expect("sync runs");
    assert_eq!(outcome.updated.len(), 0);
    assert_eq!(outcome.failed.len(), 1);
    assert_eq!(outcome.failed[0].0, "npm");
    assert!(
        outcome.failed[0].1.contains("sha256 mismatch"),
        "error: {}",
        outcome.failed[0].1
    );
    assert!(
        !mirror.path().join("npm.db").exists(),
        "a rejected artifact must never be swapped in"
    );
    let state = intel::load_state(mirror.path());
    assert!(state.files.is_empty());
    assert!(
        state.synced_at.is_none(),
        "a failed sync must not refresh the staleness clock"
    );
}

// See above for the guard-across-await rationale.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn a_failed_download_keeps_the_previous_database_serving() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let conn = Connection::open(mirror.path().join("npm.db")).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    let record = osv_record(
        "MAL-2026-9002",
        "npm",
        "evil-old",
        "2026-08-01T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "MAL-2026-9002",
        "2026-08-01T00:00:00Z",
        &record,
        &["evil-old"],
    );
    drop(conn);
    let synced_at = chrono::Utc::now() - chrono::Duration::days(2);
    let state = intel::MirrorState {
        synced_at: Some(synced_at),
        files: HashMap::from([("npm".to_string(), "oldsha".to_string())]),
    };
    intel::save_state(mirror.path(), &state).expect("save state");

    // The index advertises a new hash but the artifact itself is missing.
    let mut routes = HashMap::new();
    routes.insert(
        "/index.json".to_string(),
        (
            "200 OK",
            index_json(&[("npm", "npm.db.zip", "1".repeat(64), 128)]),
        ),
    );
    let (address, _server) = serve_routes(routes).await;
    let mut env = common::EnvVarGuard::acquire();
    env.set("HUSK_INTEL_URL", &address);

    let outcome = sync::sync(mirror.path(), None).await.expect("sync runs");
    assert_eq!(outcome.failed.len(), 1);

    let matched = intel::match_packages(mirror.path(), &[package("npm", "evil-old", "1.0.0")]);
    assert_eq!(
        matched.findings.len(),
        1,
        "the previous database keeps serving verdicts"
    );
    let state = intel::load_state(mirror.path());
    assert_eq!(state.synced_at, Some(synced_at));
    assert_eq!(state.files.get("npm"), Some(&"oldsha".to_string()));
}

// See above for the guard-across-await rationale.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn a_malformed_index_is_an_error_and_an_oversized_one_is_rejected() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let mut routes = HashMap::new();
    routes.insert(
        "/index.json".to_string(),
        ("200 OK", b"<html>captive portal</html>".to_vec()),
    );
    let (address, _server) = serve_routes(routes).await;
    let mut env = common::EnvVarGuard::acquire();
    env.set("HUSK_INTEL_URL", &address);
    let err = sync::sync(mirror.path(), None)
        .await
        .expect_err("garbage is not an index");
    assert!(
        format!("{err:#}").contains("parsing intel index"),
        "error: {err:#}"
    );
    assert!(intel::load_state(mirror.path()).synced_at.is_none());

    let mut routes = HashMap::new();
    routes.insert(
        "/index.json".to_string(),
        ("200 OK", vec![b' '; 4 * 1024 * 1024 + 16]),
    );
    let (address, _server) = serve_routes(routes).await;
    env.set("HUSK_INTEL_URL", &address);
    let err = sync::sync(mirror.path(), None)
        .await
        .expect_err("an oversized index must be rejected");
    assert!(format!("{err:#}").contains("larger than"), "error: {err:#}");
}

// See above for the guard-across-await rationale.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn a_deleted_database_is_refetched_despite_a_matching_hash() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let scratch = tempfile::tempdir().expect("tempdir");
    let db_path = scratch.path().join("npm.db");
    let conn = Connection::open(&db_path).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    drop(conn);
    let zip = zip_single("npm.db", &std::fs::read(&db_path).expect("read db"));
    let sha = sha256_hex(&zip);

    // The recorded hash matches the index, but the file itself is gone.
    let state = intel::MirrorState {
        synced_at: Some(chrono::Utc::now()),
        files: HashMap::from([("npm".to_string(), sha.clone())]),
    };
    intel::save_state(mirror.path(), &state).expect("save state");

    let mut routes = HashMap::new();
    routes.insert(
        "/index.json".to_string(),
        (
            "200 OK",
            index_json(&[("npm", "npm.db.zip", sha, zip.len())]),
        ),
    );
    routes.insert("/npm.db.zip".to_string(), ("200 OK", zip));
    let (address, _server) = serve_routes(routes).await;
    let mut env = common::EnvVarGuard::acquire();
    env.set("HUSK_INTEL_URL", &address);

    let outcome = sync::sync(mirror.path(), None).await.expect("sync");
    assert!(outcome.failed.is_empty(), "failed: {:?}", outcome.failed);
    assert_eq!(
        outcome.updated.len(),
        1,
        "the missing file must re-download"
    );
    assert!(mirror.path().join("npm.db").exists());
}

// See above for the guard-across-await rationale.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn a_corrupt_database_is_refetched_despite_a_matching_hash() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let scratch = tempfile::tempdir().expect("tempdir");
    let db_path = scratch.path().join("npm.db");
    let conn = Connection::open(&db_path).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    let record = osv_record(
        "MAL-2026-9003",
        "npm",
        "evil-c",
        "2026-08-01T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "MAL-2026-9003",
        "2026-08-01T00:00:00Z",
        &record,
        &["evil-c"],
    );
    drop(conn);
    let zip = zip_single("npm.db", &std::fs::read(&db_path).expect("read db"));
    let sha = sha256_hex(&zip);

    // The client holds that artifact's hash, but its copy of the database
    // was damaged after the download that recorded it.
    std::fs::write(mirror.path().join("npm.db"), b"truncated to nothing usable")
        .expect("corrupt the database");
    let state = intel::MirrorState {
        synced_at: Some(chrono::Utc::now()),
        files: HashMap::from([("npm".to_string(), sha.clone())]),
    };
    intel::save_state(mirror.path(), &state).expect("save state");

    let matched = intel::match_packages(mirror.path(), &[package("npm", "evil-c", "1.0.0")]);
    assert!(
        matched.findings.is_empty(),
        "a corrupt file matches nothing"
    );
    assert_eq!(matched.missing_ecosystems, vec!["npm".to_string()]);
    assert!(
        !intel::load_state(mirror.path()).files.contains_key("npm"),
        "a hash recorded for bytes SQLite rejects must not survive the read"
    );

    let mut routes = HashMap::new();
    routes.insert(
        "/index.json".to_string(),
        (
            "200 OK",
            index_json(&[("npm", "npm.db.zip", sha, zip.len())]),
        ),
    );
    routes.insert("/npm.db.zip".to_string(), ("200 OK", zip));
    let (address, _server) = serve_routes(routes).await;
    let mut env = common::EnvVarGuard::acquire();
    env.set("HUSK_INTEL_URL", &address);

    // The index still publishes the very hash the corrupt copy was recorded
    // under, so without the repair above this sync would skip the ecosystem.
    let outcome = sync::sync(mirror.path(), None).await.expect("sync");
    assert!(outcome.failed.is_empty(), "failed: {:?}", outcome.failed);
    assert_eq!(
        outcome.updated.len(),
        1,
        "the corrupt file must re-download"
    );
    assert_eq!(outcome.unchanged, 0);
    let repaired = intel::match_packages(mirror.path(), &[package("npm", "evil-c", "1.0.0")]);
    assert_eq!(
        repaired.findings.len(),
        1,
        "the replaced database serves verdicts again"
    );
}

#[test]
fn a_readable_or_absent_database_keeps_its_recorded_hash() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let conn = Connection::open(mirror.path().join("npm.db")).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    let record = osv_record(
        "MAL-2026-9004",
        "npm",
        "evil-d",
        "2026-08-01T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "MAL-2026-9004",
        "2026-08-01T00:00:00Z",
        &record,
        &["evil-d"],
    );
    drop(conn);
    let state = intel::MirrorState {
        synced_at: Some(chrono::Utc::now()),
        files: HashMap::from([
            ("npm".to_string(), "npm-sha".to_string()),
            ("crates.io".to_string(), "crates-sha".to_string()),
        ]),
    };
    intel::save_state(mirror.path(), &state).expect("save state");

    // npm is healthy; crates.io has a recorded hash but no local file, the
    // ordinary state after a partial sync. Neither is a repair case, and a
    // scan that re-downloaded either would be re-downloading every scan.
    let matched = intel::match_packages(
        mirror.path(),
        &[
            package("npm", "evil-d", "1.0.0"),
            package("cargo", "h2", "0.4.15"),
        ],
    );
    assert_eq!(matched.findings.len(), 1);
    assert_eq!(matched.missing_ecosystems, vec!["crates.io".to_string()]);
    let state = intel::load_state(mirror.path());
    assert_eq!(state.files.get("npm"), Some(&"npm-sha".to_string()));
    assert_eq!(
        state.files.get("crates.io"),
        Some(&"crates-sha".to_string())
    );
}

#[test]
fn an_unknown_schema_version_keeps_its_hash_rather_than_looping() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let conn = Connection::open(mirror.path().join("npm.db")).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    conn.execute(
        "UPDATE meta SET value = '999' WHERE key = 'schema_version'",
        [],
    )
    .expect("bump the schema version");
    drop(conn);
    let state = intel::MirrorState {
        synced_at: Some(chrono::Utc::now()),
        files: HashMap::from([("npm".to_string(), "npm-sha".to_string())]),
    };
    intel::save_state(mirror.path(), &state).expect("save state");

    let matched = intel::match_packages(mirror.path(), &[package("npm", "evil-d", "1.0.0")]);
    assert_eq!(matched.missing_ecosystems, vec!["npm".to_string()]);
    assert_eq!(
        intel::load_state(mirror.path()).files.get("npm"),
        Some(&"npm-sha".to_string()),
        "the file is intact and the index would only serve it again; \
         dropping the hash would re-download it on every sync"
    );
}

// See above for the guard-across-await rationale.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn a_partial_delta_failure_leaves_the_database_unchanged() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let db_path = mirror.path().join("npm.db");
    let conn = Connection::open(&db_path).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    let record = osv_record(
        "MAL-2026-9003",
        "npm",
        "evil-base",
        "2026-08-01T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "MAL-2026-9003",
        "2026-08-01T00:00:00Z",
        &record,
        &["evil-base"],
    );
    drop(conn);

    // Two changed records; only the first is fetchable.
    let csv = "2026-08-22T10:00:00Z,GHSA-good-good-good\n\
               2026-08-22T09:00:00Z,GHSA-gone-gone-gone\n\
               2026-08-01T00:00:00Z,MAL-2026-9003\n";
    let record_good = osv_record(
        "GHSA-good-good-good",
        "npm",
        "evil-new",
        "2026-08-22T10:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    let mut routes = HashMap::new();
    routes.insert(
        "/npm/modified_id.csv".to_string(),
        ("200 OK", csv.as_bytes().to_vec()),
    );
    routes.insert(
        "/npm/GHSA-good-good-good.json".to_string(),
        ("200 OK", record_good.into_bytes()),
    );
    let (address, _server) = serve_routes(routes).await;
    let mut env = common::EnvVarGuard::acquire();
    env.set("HUSK_OSV_URL", &address);

    let delta = fresh::refresh(mirror.path()).await;
    assert_eq!(delta.failed.len(), 1);
    assert_eq!(delta.failed[0].0, "npm");
    assert_eq!(delta.applied, 0);
    assert_eq!(
        advisory_count(&db_path),
        1,
        "a half-fetched delta must not half-apply"
    );
    let conn = Connection::open(&db_path).expect("open");
    let watermark: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'modified_watermark'",
            [],
            |row| row.get(0),
        )
        .ok();
    assert_eq!(watermark, None, "the watermark must not advance");
}

// See above for the guard-across-await rationale.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn an_oversized_delta_defers_to_the_bundle_sync() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let db_path = mirror.path().join("npm.db");
    let conn = Connection::open(&db_path).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    let record = osv_record(
        "MAL-2026-9004",
        "npm",
        "evil-base",
        "2026-08-01T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "MAL-2026-9004",
        "2026-08-01T00:00:00Z",
        &record,
        &["evil-base"],
    );
    drop(conn);

    let mut csv = String::new();
    for i in 0..(fresh::MAX_DELTA_RECORDS + 5) {
        csv.push_str(&format!(
            "2026-08-22T10:00:{:02}.{:06}Z,GHSA-{i}\n",
            i % 60,
            i
        ));
    }
    let mut routes = HashMap::new();
    routes.insert(
        "/npm/modified_id.csv".to_string(),
        ("200 OK", csv.into_bytes()),
    );
    let (address, _server) = serve_routes(routes).await;
    let mut env = common::EnvVarGuard::acquire();
    env.set("HUSK_OSV_URL", &address);

    let delta = fresh::refresh(mirror.path()).await;
    assert_eq!(delta.failed.len(), 1);
    assert!(
        delta.failed[0].1.contains("behind"),
        "error: {}",
        delta.failed[0].1
    );
    assert_eq!(advisory_count(&db_path), 1, "nothing may half-apply");
}

// See above for the guard-across-await rationale.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn a_garbage_csv_is_a_failure_not_a_clean_refresh() {
    let mirror = tempfile::tempdir().expect("tempdir");
    let db_path = mirror.path().join("npm.db");
    let conn = Connection::open(&db_path).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    let record = osv_record(
        "MAL-2026-9005",
        "npm",
        "evil-base",
        "2026-08-01T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "MAL-2026-9005",
        "2026-08-01T00:00:00Z",
        &record,
        &["evil-base"],
    );
    drop(conn);

    let mut routes = HashMap::new();
    routes.insert(
        "/npm/modified_id.csv".to_string(),
        (
            "200 OK",
            b"<html><body>hotel wifi login</body></html>".to_vec(),
        ),
    );
    let (address, _server) = serve_routes(routes).await;
    let mut env = common::EnvVarGuard::acquire();
    env.set("HUSK_OSV_URL", &address);

    let delta = fresh::refresh(mirror.path()).await;
    assert_eq!(
        delta.failed.len(),
        1,
        "a non-csv body must not read as an empty delta"
    );
    assert!(
        delta.failed[0].1.contains("no recognizable rows"),
        "error: {}",
        delta.failed[0].1
    );
}

/// Build a mirror database from a recorded live OSV record under
/// `tst/intel/`, exactly as the platform builder and delta writer would.
fn mirror_from_fixture(dir: &Path, base_ecosystem: &str, file: &str) {
    let record = std::fs::read_to_string(common::crate_root().join("tst/intel").join(file))
        .expect("read fixture");
    let value: serde_json::Value = serde_json::from_str(&record).expect("parse fixture");
    let id = value["id"].as_str().expect("fixture id");
    let modified = value["modified"].as_str().unwrap_or("2026-08-01T00:00:00Z");
    let mut names: Vec<&str> = value["affected"]
        .as_array()
        .expect("fixture affected")
        .iter()
        .filter_map(|affected| affected["package"]["name"].as_str())
        .collect();
    names.sort();
    names.dedup();
    let conn = Connection::open(dir.join(intel::ecosystem_file(base_ecosystem))).expect("open");
    intel::create_schema(&conn, base_ecosystem, modified).expect("schema");
    insert_advisory(&conn, id, modified, &record, &names);
}

/// Recorded live OSV verdicts, replayed through the mirror path: for each
/// recorded record, versions the live API reports affected must match and
/// versions at or past the fix must not. Also locks the two case traps:
/// NuGet names and VSCode publisher ids match case-sensitively.
#[test]
fn mirror_verdicts_match_recorded_live_osv_verdicts() {
    struct Case {
        fixture: &'static str,
        base: &'static str,
        ecosystem: &'static str,
        name: &'static str,
        affected: &'static [&'static str],
        unaffected: &'static [&'static str],
    }
    let cases = [
        Case {
            fixture: "npm-GHSA-35jh-r3h4-6jhm.json",
            base: "npm",
            ecosystem: "npm",
            name: "lodash",
            affected: &["4.17.20", "0.9.0"],
            unaffected: &["4.17.21"],
        },
        // last_affected closes inclusively: 4.5.0 is the last bad release.
        Case {
            fixture: "npm-GHSA-35jh-r3h4-6jhm.json",
            base: "npm",
            ecosystem: "npm",
            name: "lodash.template",
            affected: &["4.5.0"],
            unaffected: &["4.5.1"],
        },
        Case {
            fixture: "pypi-PYSEC-2018-28.json",
            base: "PyPI",
            ecosystem: "pypi",
            name: "requests",
            affected: &["2.19.1", "2.3.0"],
            unaffected: &["2.20.0", "2.31.0"],
        },
        Case {
            fixture: "crates-RUSTSEC-2020-0071.json",
            base: "crates.io",
            ecosystem: "cargo",
            name: "time",
            affected: &["0.1.43", "0.2.7", "0.2.22"],
            unaffected: &["0.2.23", "0.3.36", "0.2.6"],
        },
        Case {
            fixture: "go-GO-2022-0969.json",
            base: "Go",
            ecosystem: "go",
            name: "golang.org/x/net",
            affected: &["v0.0.0-20210226172049-e18ecbb05110"],
            unaffected: &["v0.1.0"],
        },
        Case {
            fixture: "go-GO-2022-0969.json",
            base: "Go",
            ecosystem: "go",
            name: "stdlib",
            affected: &["1.18.5", "1.19.0"],
            unaffected: &["1.18.6", "1.19.1"],
        },
        Case {
            fixture: "nuget-GHSA-5crp-9r3c-p9vr.json",
            base: "NuGet",
            ecosystem: "nuget",
            name: "Newtonsoft.Json",
            affected: &["12.0.3", "9.0.1"],
            unaffected: &["13.0.1", "13.0.3"],
        },
        Case {
            fixture: "vscode-MAL-2026-5161.json",
            base: "VSCode",
            ecosystem: "vscode-extension",
            name: "nrwl.angular-console",
            affected: &["18.95.0"],
            unaffected: &["18.94.0"],
        },
    ];
    for case in &cases {
        let dir = tempfile::tempdir().expect("tempdir");
        mirror_from_fixture(dir.path(), case.base, case.fixture);
        for version in case.affected {
            let matched =
                intel::match_packages(dir.path(), &[package(case.ecosystem, case.name, version)]);
            assert_eq!(
                matched.findings.len(),
                1,
                "{} {}@{version} must match through the mirror",
                case.ecosystem,
                case.name
            );
            assert_eq!(
                matched.unevaluated_ranges, 0,
                "{}: every range in this record must be locally evaluable",
                case.fixture
            );
        }
        for version in case.unaffected {
            let matched =
                intel::match_packages(dir.path(), &[package(case.ecosystem, case.name, version)]);
            assert!(
                matched.findings.is_empty(),
                "{} {}@{version} must NOT match through the mirror",
                case.ecosystem,
                case.name
            );
        }
    }
}

#[test]
fn name_case_traps_hold_in_the_mirror_path() {
    // NuGet: OSV matches case-sensitively, so the scanner preserves the
    // registered casing and the mirror must too. A lowercased coordinate
    // finding nothing here is the same behavior as the live API.
    let dir = tempfile::tempdir().expect("tempdir");
    mirror_from_fixture(dir.path(), "NuGet", "nuget-GHSA-5crp-9r3c-p9vr.json");
    let matched =
        intel::match_packages(dir.path(), &[package("nuget", "newtonsoft.json", "12.0.3")]);
    assert!(
        matched.findings.is_empty(),
        "a lowercased NuGet name matches nothing, exactly like live OSV"
    );

    // VSCode: publisher.name is case-sensitive in OSV.
    let dir = tempfile::tempdir().expect("tempdir");
    mirror_from_fixture(dir.path(), "VSCode", "vscode-MAL-2026-5161.json");
    let matched = intel::match_packages(
        dir.path(),
        &[package(
            "vscode-extension",
            "NRWL.Angular-Console",
            "18.95.0",
        )],
    );
    assert!(
        matched.findings.is_empty(),
        "a case-mangled publisher id matches nothing, exactly like live OSV"
    );

    // The versionless malware rule still applies to extension coordinates.
    let matched = intel::match_packages(
        dir.path(),
        &[package("vscode-extension", "nrwl.angular-console", "")],
    );
    assert_eq!(matched.findings.len(), 1);
    assert_eq!(matched.findings[0].category, Category::Malware);
}

#[test]
fn matching_stays_correct_during_concurrent_delta_writes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("npm.db");
    let conn = Connection::open(&db_path).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-01T00:00:00Z").expect("schema");
    let record = osv_record(
        "MAL-2026-9006",
        "npm",
        "evil-steady",
        "2026-08-01T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "MAL-2026-9006",
        "2026-08-01T00:00:00Z",
        &record,
        &["evil-steady"],
    );
    drop(conn);

    let writer_path = db_path.clone();
    let writer =
        std::thread::spawn(move || {
            let mut conn = Connection::open(&writer_path).expect("open for writing");
            conn.busy_timeout(std::time::Duration::from_secs(5))
                .expect("busy timeout");
            for i in 0..200 {
                let tx = conn.transaction().expect("begin");
                tx.execute(
                "INSERT OR REPLACE INTO advisories (id, modified, record) VALUES (?1, ?2, '{}')",
                [format!("GHSA-noise-{i}"), format!("2026-08-22T00:00:{:02}Z", i % 60)],
            )
            .expect("insert");
                tx.execute(
                    "INSERT INTO affected (name, advisory_id) VALUES ('noise-pkg', ?1)",
                    [format!("GHSA-noise-{i}")],
                )
                .expect("insert affected");
                tx.commit().expect("commit");
            }
        });
    for _ in 0..100 {
        let matched = intel::match_packages(dir.path(), &[package("npm", "evil-steady", "1.0.0")]);
        assert!(
            matched.missing_ecosystems.is_empty(),
            "the database must stay readable during writes"
        );
        assert_eq!(
            matched.findings.len(),
            1,
            "the advisory must never flicker out during a concurrent write"
        );
    }
    writer.join().expect("writer thread");
}

fn write_lockfile(project: &Path, name: &str, version: &str) {
    std::fs::create_dir_all(project).expect("create project");
    let mut packages = serde_json::Map::new();
    packages.insert(String::new(), serde_json::json!({"name": "intel-fixture"}));
    packages.insert(
        format!("node_modules/{name}"),
        serde_json::json!({"version": version}),
    );
    let lock = serde_json::json!({
        "name": "intel-fixture",
        "lockfileVersion": 3,
        "packages": packages,
    });
    std::fs::write(
        project.join("package-lock.json"),
        serde_json::to_vec_pretty(&lock).expect("serialize lock"),
    )
    .expect("write lockfile");
}

#[test]
fn offline_ci_fails_closed_when_the_mirror_has_never_synced() {
    let state = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(state.path().join("cache")).expect("create cache");
    let project = state.path().join("project");
    write_lockfile(&project, "left-pad", "1.3.0");

    let output = common::run_husk(
        &state,
        &[
            "ci",
            "--offline",
            project.to_str().expect("utf8 path"),
            "--no-home-inventory",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "an offline gate without advisory data must fail closed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OSV mirror"), "stderr: {stderr}");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("ci prints the report as JSON");
    let row = report["providers"]
        .as_array()
        .expect("providers array")
        .iter()
        .find(|row| row["name"] == "OSV mirror")
        .expect("the mirror row is always present");
    assert_eq!(row["ok"], false);
    assert!(
        row["message"]
            .as_str()
            .expect("message")
            .contains("no local advisory data"),
        "message: {}",
        row["message"]
    );
}

#[test]
fn offline_ci_matches_through_a_synced_mirror_and_gates() {
    let state = tempfile::tempdir().expect("tempdir");
    let intel_dir = state.path().join("cache").join("intel");
    std::fs::create_dir_all(&intel_dir).expect("create intel dir");
    let conn = Connection::open(intel_dir.join("npm.db")).expect("open");
    intel::create_schema(&conn, "npm", "2026-08-24T00:00:00Z").expect("schema");
    let record = osv_record(
        "MAL-2026-9100",
        "npm",
        "husk-mirror-test-evil",
        "2026-08-24T00:00:00Z",
        serde_json::json!(["1.0.0"]),
        serde_json::json!([]),
    );
    insert_advisory(
        &conn,
        "MAL-2026-9100",
        "2026-08-24T00:00:00Z",
        &record,
        &["husk-mirror-test-evil"],
    );
    drop(conn);
    let mirror_state = intel::MirrorState {
        synced_at: Some(chrono::Utc::now()),
        files: HashMap::from([("npm".to_string(), "recorded".to_string())]),
    };
    intel::save_state(&intel_dir, &mirror_state).expect("save state");

    let project = state.path().join("project");
    write_lockfile(&project, "husk-mirror-test-evil", "1.0.0");

    let output = common::run_husk(
        &state,
        &[
            "ci",
            "--offline",
            project.to_str().expect("utf8 path"),
            "--no-home-inventory",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "a mirror-matched critical finding must fail the gate; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("ci prints the report as JSON");
    let row = report["providers"]
        .as_array()
        .expect("providers array")
        .iter()
        .find(|row| row["name"] == "OSV mirror")
        .expect("mirror row");
    assert_eq!(row["ok"], true, "row: {row}");
    assert!(row["findings"].as_u64().expect("count") >= 1);
    let ids: Vec<&str> = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|finding| finding["id"].as_str())
        .collect();
    assert!(
        ids.iter().any(|id| id.starts_with("osv:MAL-2026-9100:")),
        "ids: {ids:?}"
    );
}
