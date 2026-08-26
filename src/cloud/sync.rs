//! Inventory sync and retroactive-alerts client for the optional Husk
//! backend (`/api/v1`).
//!
//! Everything in this module is opt-in: it is only reached from explicit
//! commands run by a logged-in user (`husk sync`, `husk alerts`). Nothing
//! here runs during a normal scan, and nothing phones home on its own.
//!
//! Every function takes the backend base URL and a shared
//! [`reqwest::Client`], so callers control transport policy and tests can
//! point at a local server. Callers are expected to pass a currently valid
//! access token; refreshing expired tokens is the auth layer's job.

use super::{api_url, null_to_default};
use crate::model::{PackageRef, Severity};
use anyhow::{Context, Result, anyhow, bail, ensure};
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Hard cap on packages per inventory snapshot; mirrors the backend limit
/// so an oversized local inventory degrades to a truncated upload instead
/// of a rejected one.
pub const MAX_SYNC_PACKAGES: usize = 20_000;

// Per-field limits enforced by the backend. Entries exceeding them are
// dropped client-side because the backend rejects the whole snapshot
// otherwise.
const MAX_ECOSYSTEM_LEN: usize = 64;
const MAX_NAME_LEN: usize = 512;
const MAX_VERSION_LEN: usize = 128;

const GET_TIMEOUT: Duration = Duration::from_secs(10);
const PUT_TIMEOUT: Duration = Duration::from_secs(30);

const HUSK_VERSION_HEADER: &str = "X-Husk-Version";
const MACHINE_CACHE_FILE: &str = "machine.json";

/// One `{ecosystem, name, version}` row in an inventory snapshot. The
/// derive order (ecosystem, name, version) defines the upload sort order.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct InventoryPackage {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// Maps discovered packages onto the unique, sorted `{ecosystem, name,
/// version}` set the backend stores. Entries the backend would reject
/// (empty fields, control characters, oversized values) are dropped
/// instead of failing the whole snapshot, ecosystems are lowercased to
/// match server-side normalization, and the result is deterministically
/// capped at [`MAX_SYNC_PACKAGES`].
pub fn build_inventory_payload(packages: &[PackageRef]) -> Vec<InventoryPackage> {
    let mut unique = BTreeSet::new();
    for package in packages {
        let Some(ecosystem) = clean_field(&package.ecosystem, MAX_ECOSYSTEM_LEN) else {
            continue;
        };
        let Some(name) = clean_field(&package.name, MAX_NAME_LEN) else {
            continue;
        };
        let Some(version) = clean_field(&package.version, MAX_VERSION_LEN) else {
            continue;
        };
        unique.insert(InventoryPackage {
            ecosystem: ecosystem.to_lowercase(),
            name,
            version,
        });
    }
    unique.into_iter().take(MAX_SYNC_PACKAGES).collect()
}

fn clean_field(value: &str, max_len: usize) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > max_len
        || trimmed.chars().any(char::is_control)
    {
        return None;
    }
    Some(trimmed.to_string())
}

/// Result of an accepted inventory upload.
#[derive(Clone, Debug)]
pub struct SyncReport {
    /// Machine the backend accepted the snapshot for.
    pub machine_id: String,
    /// Unique packages in the accepted snapshot, as confirmed by the server.
    pub uploaded: usize,
    /// Alerts newly created by server-side intel matching.
    pub new_alerts: u64,
}

#[derive(Deserialize)]
struct InventoryAccepted {
    packages: usize,
    new_alerts: u64,
}

#[derive(Serialize)]
struct InventoryPut<'a> {
    packages: &'a [InventoryPackage],
}

/// Uploads this machine's package inventory snapshot
/// (`PUT /api/v1/machines/{machine_id}/inventory`).
///
/// Machine-id discovery: the device-flow token is bound to exactly one
/// machine server-side, but the token grant response does not include that
/// machine's id, so the CLI cannot know it directly. The backend rejects
/// uploads for foreign machines with 403 (and deleted machines with 404),
/// which makes a reliable probe: try the locally cached id
/// (`~/.husk/machine.json`), then every account machine newest-created
/// first, and remember whichever id the backend accepts.
pub async fn sync_inventory(
    base_url: &str,
    client: &Client,
    access_token: &str,
    packages: &[PackageRef],
) -> Result<SyncReport> {
    let payload = build_inventory_payload(packages);
    let husk_home = crate::paths::husk_home().ok();
    let cached = husk_home.as_deref().and_then(read_cached_machine_id);

    // Phase one: the locally cached id.
    let mut tried = BTreeSet::new();
    for id in candidate_machine_ids(cached.as_deref(), &[]) {
        tried.insert(id.clone());
        if let Some(report) =
            try_put_inventory(base_url, client, access_token, &id, &payload).await?
        {
            remember_machine_id(husk_home.as_deref(), &report.machine_id);
            return Ok(report);
        }
    }

    // Phase two: discover via the account machine list.
    let machines = list_machines(base_url, client, access_token)
        .await
        .context("could not list account machines to locate this machine")?;
    for id in candidate_machine_ids(None, &machines) {
        if !tried.insert(id.clone()) {
            continue;
        }
        if let Some(report) =
            try_put_inventory(base_url, client, access_token, &id, &payload).await?
        {
            remember_machine_id(husk_home.as_deref(), &report.machine_id);
            return Ok(report);
        }
    }

    bail!(
        "the backend did not accept this machine's inventory: no machine on the account matches the current credential; verify the backend and credential configuration"
    )
}

/// One upload probe. `Ok(None)` means "wrong machine, keep probing"
/// (403 foreign machine / 404 deleted machine); transport errors and
/// other HTTP failures abort discovery immediately.
async fn try_put_inventory(
    base_url: &str,
    client: &Client,
    access_token: &str,
    machine_id: &str,
    packages: &[InventoryPackage],
) -> Result<Option<SyncReport>> {
    let url = api_url(
        base_url,
        &format!("/api/v1/machines/{machine_id}/inventory"),
    );
    let response = client
        .put(url)
        .bearer_auth(access_token)
        .header(HUSK_VERSION_HEADER, env!("CARGO_PKG_VERSION"))
        .timeout(PUT_TIMEOUT)
        .json(&InventoryPut { packages })
        .send()
        .await
        .context("inventory upload request failed")?;

    match response.status() {
        status if status.is_success() => {
            let accepted: InventoryAccepted = response
                .json()
                .await
                .context("invalid inventory upload response")?;
            Ok(Some(SyncReport {
                machine_id: machine_id.to_string(),
                uploaded: accepted.packages,
                new_alerts: accepted.new_alerts,
            }))
        }
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Ok(None),
        _ => Err(api_error(response, "inventory upload").await),
    }
}

/// Probe order for machine-id discovery: the locally cached id, then
/// account machines newest-created first. Implausible and duplicate ids
/// are dropped.
pub fn candidate_machine_ids(cached: Option<&str>, machines: &[MachineInfo]) -> Vec<String> {
    let mut ordered: Vec<String> = Vec::new();
    let mut push = |id: &str| {
        if is_safe_id(id) && !ordered.iter().any(|seen| seen == id) {
            ordered.push(id.to_string());
        }
    };
    if let Some(cached) = cached {
        push(cached);
    }
    let mut by_age: Vec<&MachineInfo> = machines.iter().collect();
    // Newest-created first; machines without a timestamp go last. The sort
    // is stable, so ties keep the server's newest-seen-first order.
    by_age.sort_by_key(|m| std::cmp::Reverse(m.created_at));
    for machine in by_age {
        push(&machine.id);
    }
    ordered
}

/// Ids are backend-issued UUIDs; anything else (for example a corrupted
/// cache file) must never be interpolated into a request path.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// One machine from `GET /api/v1/account/machines`. Only the fields
/// machine-id discovery reads are modeled; serde drops the rest of the
/// response.
#[derive(Clone, Debug, Deserialize)]
pub struct MachineInfo {
    pub id: String,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct MachinesResponse {
    machines: Vec<MachineInfo>,
}

/// Lists the account's machines (`GET /api/v1/account/machines`),
/// in the backend's newest-seen-first order.
pub async fn list_machines(
    base_url: &str,
    client: &Client,
    access_token: &str,
) -> Result<Vec<MachineInfo>> {
    let url = api_url(base_url, "/api/v1/account/machines");
    let response = client
        .get(url)
        .bearer_auth(access_token)
        .timeout(GET_TIMEOUT)
        .send()
        .await
        .context("machine list request failed")?;
    if !response.status().is_success() {
        return Err(api_error(response, "machine list").await);
    }
    let body: MachinesResponse = response
        .json()
        .await
        .context("invalid machine list response")?;
    Ok(body.machines)
}

#[derive(Deserialize, Serialize)]
struct MachineIdCache {
    machine_id: String,
}

/// Reads the machine id remembered by a previous successful sync from
/// `<husk_home>/machine.json`. Returns `None` for missing, unreadable, or
/// implausible contents; the caller falls back to discovery.
pub fn read_cached_machine_id(husk_home: &Path) -> Option<String> {
    let contents = fs::read_to_string(husk_home.join(MACHINE_CACHE_FILE)).ok()?;
    let cache: MachineIdCache = serde_json::from_str(&contents).ok()?;
    is_safe_id(&cache.machine_id).then_some(cache.machine_id)
}

/// Remembers the machine id the backend accepted, creating `<husk_home>`
/// (mode 0700 on Unix) when needed.
pub fn write_cached_machine_id(husk_home: &Path, machine_id: &str) -> Result<()> {
    ensure!(is_safe_id(machine_id), "invalid machine id");
    crate::paths::ensure_dir_private(husk_home)?;
    let path = husk_home.join(MACHINE_CACHE_FILE);
    let cache = MachineIdCache {
        machine_id: machine_id.to_string(),
    };
    crate::paths::write_atomic(&path, &serde_json::to_vec_pretty(&cache)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn remember_machine_id(husk_home: Option<&Path>, machine_id: &str) {
    let Some(home) = husk_home else {
        return;
    };
    if read_cached_machine_id(home).as_deref() == Some(machine_id) {
        return;
    }
    // Best effort: the cache only saves probing on the next sync, so a
    // failed write must never fail the sync that just succeeded.
    let _ = write_cached_machine_id(home, machine_id);
}

/// Server-side state filter for [`fetch_alerts`]. Only the states the
/// `husk alerts` CLI can ask for (the default open view, or `--all`) are
/// modeled; grow this alongside the CLI surface, not ahead of it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AlertStateFilter {
    #[default]
    Open,
    All,
}

impl AlertStateFilter {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::All => "all",
        }
    }
}

impl fmt::Display for AlertStateFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One alert from `GET /api/v1/alerts`, joined server-side with the
/// matching intel entry and machine name. Unknown fields are tolerated so
/// older CLIs keep working as the backend grows.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CloudAlert {
    pub id: String,
    pub machine_id: String,
    #[serde(default)]
    pub machine_name: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    /// `open`, `acked`, or `resolved`.
    pub state: String,
    /// Intel severity as sent by the backend; see [`CloudAlert::severity_level`].
    pub severity: String,
    /// `malware`, `compromised`, `typosquat`, or `vulnerable`.
    pub verdict: String,
    #[serde(default)]
    pub summary: String,
    /// Nullable server-side (`references` is a jsonb column); `null` is empty.
    #[serde(default, deserialize_with = "null_to_default")]
    pub references: Vec<String>,
    pub first_seen_at: DateTime<Utc>,
}

impl CloudAlert {
    /// Backend severity mapped onto the local severity scale.
    pub fn severity_level(&self) -> Severity {
        Severity::from_external(&self.severity)
    }
}

#[derive(Deserialize)]
struct AlertsResponse {
    alerts: Vec<CloudAlert>,
}

/// Parses a `GET /api/v1/alerts` response body.
pub fn parse_alerts_response(body: &str) -> Result<Vec<CloudAlert>> {
    let parsed: AlertsResponse = serde_json::from_str(body).context("invalid alerts response")?;
    Ok(parsed.alerts)
}

/// Fetches the account's alerts (`GET /api/v1/alerts?state=...`).
pub async fn fetch_alerts(
    base_url: &str,
    client: &Client,
    access_token: &str,
    state_filter: AlertStateFilter,
) -> Result<Vec<CloudAlert>> {
    let url = api_url(base_url, "/api/v1/alerts");
    let response = client
        .get(url)
        .query(&[("state", state_filter.as_str())])
        .bearer_auth(access_token)
        .timeout(GET_TIMEOUT)
        .send()
        .await
        .context("alerts request failed")?;
    if !response.status().is_success() {
        return Err(api_error(response, "alerts").await);
    }
    let body = response
        .text()
        .await
        .context("alerts response read failed")?;
    parse_alerts_response(&body)
}

#[derive(Deserialize)]
struct ApiErrorBody {
    #[serde(default)]
    message: String,
}

/// Builds a readable error from a non-success backend response, preferring
/// the backend's own `{code, message}` JSON message over the bare status.
async fn api_error(response: reqwest::Response, what: &str) -> anyhow::Error {
    let status = response.status();
    let message = response
        .text()
        .await
        .ok()
        .and_then(|body| serde_json::from_str::<ApiErrorBody>(&body).ok())
        .map(|body| body.message)
        .filter(|message| !message.is_empty());
    match message {
        Some(message) => anyhow!("{what} failed: {message} (HTTP {status})"),
        None => anyhow!("{what} failed: HTTP {status}"),
    }
}
