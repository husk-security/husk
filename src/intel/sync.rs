//! Fetch pre-built mirror databases published by husk's infrastructure.
//!
//! This module is the public half of the bundle contract; the builder that
//! produces the artifacts is private server code. The published layout is:
//!
//! - `index.json`: a JSON array of [`IndexEntry`] rows, one per ecosystem.
//! - one `<ecosystem>.db.zip` per row: a ZIP holding a single SQLite file in
//!   the schema `super::create_schema` defines (versioned by
//!   [`super::INTEL_SCHEMA_VERSION`]; a client ignores files whose schema
//!   version it does not know, loudly).
//! - `ATTRIBUTION.md`: the licenses of the upstream advisory databases.
//!
//! Sync reads `index.json`, downloads the artifacts whose sha256 differs
//! from the local copy, verifies each download against the index hash, and
//! swaps files in atomically. Only ecosystems present in the machine's last
//! scan inventory are fetched (plus the dev core when no inventory exists
//! yet). Runs invisibly from scan start and the daemon; there is no user
//! command.

use anyhow::{Context, Result};
use sha2::Digest;
use std::collections::HashSet;
use std::path::Path;

/// One row of the published `index.json`: what a client needs to decide
/// whether to fetch an ecosystem's database.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct IndexEntry {
    pub ecosystem: String,
    /// The compressed artifact file name (`<ecosystem>.db.zip`).
    pub file: String,
    /// sha256 of the compressed artifact, the client's skip/verify key.
    pub sha256: String,
    pub bytes: u64,
    pub records: u64,
    pub built_at: String,
}

/// Where the platform publishes the bundle: the R2 bucket's own CDN domain,
/// so downloads come straight from Cloudflare's edge with no husk server in
/// the path. `HUSK_INTEL_URL` overrides the base for tests and air-gapped
/// hosts serving their own copy.
pub const DEFAULT_BASE_URL: &str = "https://intel.husk-security.dev";

pub fn base_url() -> String {
    std::env::var("HUSK_INTEL_URL")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
}

#[derive(Debug, Default)]
pub struct SyncOutcome {
    pub updated: Vec<(String, u64)>,
    pub unchanged: usize,
    pub failed: Vec<(String, String)>,
}

/// The OSV base ecosystems worth syncing for this machine: everything the
/// last stored report's inventory maps into, else the dev core. `all` skips
/// the filter entirely.
pub fn wanted_ecosystems(all: bool) -> Option<HashSet<String>> {
    if all {
        return None;
    }
    let mut wanted: HashSet<String> = HashSet::new();
    if let Ok(Some(report)) = crate::cache::load_any_latest_report() {
        for package in &report.packages {
            if let Some(osv_ecosystem) = package.osv_ecosystem() {
                let base = osv_ecosystem
                    .split_once(':')
                    .map(|(base, _)| base.to_string())
                    .unwrap_or(osv_ecosystem);
                wanted.insert(base);
            }
        }
    }
    if wanted.is_empty() {
        for ecosystem in ["crates.io", "npm", "PyPI", "Go"] {
            wanted.insert(ecosystem.to_string());
        }
    }
    Some(wanted)
}

/// Drop an ecosystem's recorded hash so the next [`sync`] fetches it again.
/// That hash is the skip key: while it matches the index the local file is
/// taken to be the published one, so a database that turns out to be
/// unreadable would otherwise stay broken until the publisher happened to
/// rebuild it. Best effort by design, since the caller is a scan that must
/// finish either way.
pub fn invalidate(dir: &Path, ecosystem: &str) {
    let mut state = super::load_state(dir);
    if state.files.remove(ecosystem).is_some() {
        let _ = super::save_state(dir, &state);
    }
}

/// A published index is a few KB; anything bigger is a broken or hostile
/// server and must not be buffered into memory.
const MAX_INDEX_BYTES: usize = 4 * 1024 * 1024;

pub async fn sync(dir: &Path, wanted: Option<HashSet<String>>) -> Result<SyncOutcome> {
    // No total timeout: the artifacts are large and a slow link is legal.
    // Connect and per-read timeouts still bound a dead or hung server.
    let client = reqwest::Client::builder()
        .user_agent(format!("husk/{}", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(30))
        .build()?;
    let base = base_url();
    let response = client
        .get(format!("{base}/index.json"))
        .send()
        .await?
        .error_for_status()
        .context("fetching intel index")?;
    let body = read_capped(response, MAX_INDEX_BYTES)
        .await
        .context("reading intel index")?;
    let index: Vec<IndexEntry> = serde_json::from_slice(&body).context("parsing intel index")?;

    let mut state = super::load_state(dir);
    let mut outcome = SyncOutcome::default();
    for entry in index {
        if let Some(wanted) = &wanted
            && !wanted.contains(&entry.ecosystem)
        {
            continue;
        }
        // The hash alone is not enough to skip: a recorded hash whose file
        // was deleted from the cache must re-fetch, or the ecosystem is
        // silently uncovered forever.
        if state.files.get(&entry.ecosystem) == Some(&entry.sha256)
            && dir.join(super::ecosystem_file(&entry.ecosystem)).exists()
        {
            outcome.unchanged += 1;
            continue;
        }
        match fetch_entry(&client, &base, dir, &entry).await {
            Ok(()) => {
                state
                    .files
                    .insert(entry.ecosystem.clone(), entry.sha256.clone());
                outcome.updated.push((entry.ecosystem, entry.bytes));
            }
            Err(err) => outcome.failed.push((entry.ecosystem, format!("{err:#}"))),
        }
    }
    // A failed download must not refresh the staleness clock: `synced_at`
    // asserts the local set matches the index, and the provider row's age
    // check depends on that being true.
    if outcome.failed.is_empty() {
        state.synced_at = Some(chrono::Utc::now());
    }
    super::save_state(dir, &state)?;
    Ok(outcome)
}

/// Download one artifact, verify its sha256 against the index, extract the
/// single database file, and rename it into place. The rename is the swap:
/// a scan reading mid-sync sees the old file or the new one, never a torn
/// write.
async fn fetch_entry(
    client: &reqwest::Client,
    base: &str,
    dir: &Path,
    entry: &IndexEntry,
) -> Result<()> {
    use futures::StreamExt;
    use std::io::Write;
    let mut download = tempfile::NamedTempFile::new_in(dir)?;
    let response = client
        .get(format!("{base}/{}", entry.file))
        .send()
        .await?
        .error_for_status()?;
    let mut stream = response.bytes_stream();
    let mut written = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        written += chunk.len() as u64;
        // The index states each artifact's exact size; a longer body can
        // only hash-fail later, so stop paying for it now.
        anyhow::ensure!(
            written <= entry.bytes,
            "artifact exceeds the {} bytes the index declares",
            entry.bytes
        );
        download.write_all(chunk.as_ref())?;
    }
    let digest = sha256_file(download.path())?;
    anyhow::ensure!(
        digest == entry.sha256,
        "sha256 mismatch for {} (expected {}, got {digest})",
        entry.file,
        entry.sha256
    );

    let db_name = super::ecosystem_file(&entry.ecosystem);
    let target = dir.join(&db_name);
    let download_path = download.path().to_path_buf();
    let extracted = tempfile::NamedTempFile::new_in(dir)?;
    let extracted_path = extracted.path().to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut archive = zip::ZipArchive::new(std::fs::File::open(&download_path)?)?;
        let mut entry = archive.by_index(0).context("empty intel artifact")?;
        let mut out = std::fs::File::create(&extracted_path)?;
        std::io::copy(&mut entry, &mut out)?;
        Ok(())
    })
    .await??;
    extracted
        .persist(&target)
        .context("swapping intel database")?;
    Ok(())
}

async fn read_capped(response: reqwest::Response, cap: usize) -> Result<Vec<u8>> {
    use futures::StreamExt;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            body.len() + chunk.len() <= cap,
            "response larger than {cap} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut hasher = sha2::Sha256::new();
    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0u8; 65536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
