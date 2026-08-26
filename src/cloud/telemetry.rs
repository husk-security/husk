//! Opt-in, anonymous daily usage telemetry.
//!
//! This module is the client half of husk's published telemetry policy,
//! modeled on the Go toolchain's transparent telemetry: one aggregate report
//! per completed UTC calendar day, carrying bucketed counters and nothing
//! else. The policy is a promise, and the code keeps it:
//!
//! - **Off by default.** Nothing is recorded or sent until the user opts in:
//!   `husk telemetry on`, or answering yes to the one-time ask that follows
//!   the first successful interactive scan (the CLI prompt, the TUI pane, or
//!   the web card, all over this one consent state, so no surface re-asks).
//!   Consent lives in the `telemetry` field of `~/.husk/config.json` (see
//!   [`super::HuskCloudConfig`]).
//! - **No identifier, ever.** A report carries no UUID, no machine id, no
//!   fingerprint, and no timestamp finer than the UTC day. Two reports from
//!   the same install are indistinguishable from two installs (except for the
//!   single `first_report` flag on an install's first accepted report).
//! - **Kill switches are honored.** `DO_NOT_TRACK=1` and
//!   `HUSK_TELEMETRY_DISABLED=1` silence telemetry (accumulation and upload)
//!   even after an explicit opt-in, and CI runs (`CI=true`) are suppressed
//!   unless `HUSK_TELEMETRY=1` is set.
//! - **Coarse data only.** The counter names are a closed set (see
//!   [`counters`]): subcommand words, session markers, and bucketed scan
//!   measurements. Never file paths, package names, hostnames, usernames,
//!   command arguments, or error text.
//! - **Never in the way.** Counters accumulate in
//!   `~/.husk/telemetry/current.json`; a completed day becomes one report in
//!   `~/.husk/telemetry/pending/` (capped at [`MAX_PENDING_REPORTS`]; oldest
//!   are dropped) and uploads via a detached task with a [`FLUSH_TIMEOUT`]
//!   deadline. Every husk invocation rolls a completed day over and flushes
//!   the spool, so delivery never depends on a scan happening; a day with no
//!   counters sends nothing. Upload failures are logged to stderr and the
//!   report stays spooled; a command never fails because of telemetry.
//! - **Inspectable.** `husk telemetry status --payload` renders the current
//!   day's counters and every pending report verbatim.

use super::{HuskCloudConfig, TelemetryConsent, api_url, env_truthy};
use crate::paths::{ensure_dir_private, write_atomic};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

/// Version of the telemetry wire schema (one flat daily report object).
const SCHEMA_VERSION: u32 = 3;

/// Maximum number of unsent daily reports kept on disk; oldest are dropped.
/// Roughly a month of offline use before history starts falling off.
pub const MAX_PENDING_REPORTS: usize = 30;

/// Maximum number of counters one report may carry; bumps of new keys beyond
/// this are dropped.
pub const MAX_COUNTERS: usize = 128;

/// Maximum value a counter can accumulate to.
pub const MAX_COUNTER_VALUE: u32 = 1_000_000;

/// Hard deadline for one background telemetry flush. Telemetry must never
/// slow a command down noticeably, so this is deliberately short.
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// Version of the consent prompt message. Bumping it re-prompts installs
/// that previously said yes (never installs that said no). Version 2:
/// reports moved from weekly to daily aggregate windows.
pub const CONSENT_MESSAGE_VERSION: u32 = 2;

/// Universal opt-out (<https://consoledonottrack.com>); overrides opt-in.
pub const DO_NOT_TRACK_ENV: &str = "DO_NOT_TRACK";

/// Husk-specific kill switch; overrides opt-in.
pub const TELEMETRY_DISABLED_ENV: &str = "HUSK_TELEMETRY_DISABLED";

/// Standard CI marker; telemetry is suppressed in CI by default.
pub const CI_ENV: &str = "CI";

/// Explicit re-enable for CI environments (`HUSK_TELEMETRY=1`).
pub const TELEMETRY_OVERRIDE_ENV: &str = "HUSK_TELEMETRY";

/// The v1 anonymous install id file. The current schema sends no identifier
/// at all; the file is only ever deleted (on `husk telemetry off`), never
/// created or read.
const LEGACY_ID_FILE: &str = "telemetry_id";
const TELEMETRY_SUBDIR: &str = "telemetry";
const PENDING_SUBDIR: &str = "pending";
const CURRENT_FILE: &str = "current.json";
const META_FILE: &str = "meta.json";
const REPORTS_PATH: &str = "/api/v1/telemetry/reports";

/// The closed set of counter names. Every key the client can ever bump is
/// defined here; nothing else may reach the wire.
pub mod counters {
    use std::time::Duration;

    /// `cli.run.<command>`: one bump per CLI invocation. `<command>` is the
    /// top-level subcommand word only (`scan`, `tui`, ...), never
    /// arguments.
    pub fn cli_run(command: &str) -> String {
        format!("cli.run.{command}")
    }

    /// Bumped when the interactive terminal UI starts.
    pub const TUI_SESSION: &str = "tui.session";

    /// Bumped when `husk web` starts serving.
    pub const WEB_SESSION: &str = "web.session";

    /// Bumped when the MCP server starts.
    pub const MCP_SESSION: &str = "mcp.session";

    /// `mcp.tool.<tool_name>`: one bump per dispatched MCP tool call. Callers
    /// pass only names the MCP server actually dispatches, never a
    /// client-supplied string; the charset check is a second line of defense
    /// (an invalid name yields `None` and is never transmitted).
    pub fn mcp_tool(tool_name: &str) -> Option<String> {
        let key = format!("mcp.tool.{tool_name}");
        super::valid_counter_key(&key).then_some(key)
    }

    /// `mcp.tool.<tool_name>.err`: one bump when a known MCP tool's dispatch
    /// returns an error result, so failing tools are visible per tool. Only
    /// the tool name is recorded, never the error text.
    pub fn mcp_tool_err(tool_name: &str) -> Option<String> {
        let key = format!("mcp.tool.{tool_name}.err");
        super::valid_counter_key(&key).then_some(key)
    }

    /// Bumped when an MCP client calls a tool name the server does not have,
    /// so hallucinated names are measured without ever transmitting them.
    pub const MCP_TOOL_UNKNOWN: &str = "mcp.tool.unknown";

    /// Bumped once per completed scan.
    pub const SCAN_COMPLETED: &str = "scan.completed";

    /// `scan.duration.<under-1s|1-5s|5-30s|over-30s>`: one bump per completed
    /// scan, bucketed wall time.
    pub fn scan_duration(duration: Duration) -> &'static str {
        let millis = duration.as_millis();
        if millis < 1_000 {
            "scan.duration.under-1s"
        } else if millis < 5_000 {
            "scan.duration.1-5s"
        } else if millis < 30_000 {
            "scan.duration.5-30s"
        } else {
            "scan.duration.over-30s"
        }
    }

    /// `scan.packages.<under-100|100-1k|over-1k>`: one bump per completed
    /// scan, bucketed package count.
    pub fn scan_packages(count: usize) -> &'static str {
        if count < 100 {
            "scan.packages.under-100"
        } else if count < 1_000 {
            "scan.packages.100-1k"
        } else {
            "scan.packages.over-1k"
        }
    }

    /// `scan.findings.<critical|high|medium|low|info>`: bumped by each
    /// completed scan's per-severity finding counts (the daily aggregate is
    /// the sum across scans). Counts only; the findings never leave the
    /// machine.
    pub fn scan_findings(severity: &str) -> String {
        format!("scan.findings.{severity}")
    }

    /// `scan.scanner.<id>`: one bump per scan per scanner that ran, using the
    /// closed id map in [`super::scanner_telemetry_id`].
    pub fn scan_scanner(id: &str) -> String {
        format!("scan.scanner.{id}")
    }
}

/// The full report-upload URL for a backend base URL.
pub fn reports_url(base_url: &str) -> String {
    api_url(base_url, REPORTS_PATH)
}

/// True when `key` matches the wire charset `^[a-z0-9._+:-]{1,64}$`.
pub fn valid_counter_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 64
        && key
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b':' | b'-'))
}

/// The in-progress UTC day: counters accumulated so far. Lives at
/// `~/.husk/telemetry/current.json`.
#[derive(Debug, Deserialize, Serialize)]
struct CurrentDay {
    day: NaiveDate,
    counters: BTreeMap<String, u32>,
}

impl CurrentDay {
    fn new(day: NaiveDate) -> Self {
        Self {
            day,
            counters: BTreeMap::new(),
        }
    }
}

/// Durable install-level bookkeeping at `~/.husk/telemetry/meta.json`. The
/// install day leaves the machine only as the coarse `days_since_install`
/// bucket.
#[derive(Debug, Deserialize, Serialize)]
struct Meta {
    install_day: NaiveDate,
    first_report_sent: bool,
    consent_message_version_acknowledged: u32,
}

/// One daily report, exactly as uploaded: a single flat JSON object with no
/// identifier of any kind.
#[derive(Debug, Deserialize, Serialize)]
struct Report {
    schema: u32,
    day: NaiveDate,
    first_report: bool,
    days_since_install: String,
    husk_version: String,
    os: String,
    arch: String,
    ci: bool,
    counters: BTreeMap<String, u32>,
}

/// True when no environment kill switch suppresses telemetry: not
/// `DO_NOT_TRACK=1`, not `HUSK_TELEMETRY_DISABLED=1`, and not in CI
/// (`CI=true`) unless `HUSK_TELEMETRY=1` re-enables it explicitly.
pub fn env_allows_telemetry() -> bool {
    if env_truthy(DO_NOT_TRACK_ENV) || env_truthy(TELEMETRY_DISABLED_ENV) {
        return false;
    }
    !env_truthy(CI_ENV) || env_truthy(TELEMETRY_OVERRIDE_ENV)
}

/// Coarse install-age bucket carried in each report: `0`, `1-6`, `7-29`, or
/// `30+` whole days between the install day and the reported day. Four
/// buckets on purpose: they bound the server's metrics label cardinality and
/// stay too coarse to fingerprint.
pub fn days_since_install_bucket(install_day: NaiveDate, report_day: NaiveDate) -> &'static str {
    match (report_day - install_day).num_days().max(0) {
        0 => "0",
        1..=6 => "1-6",
        7..=29 => "7-29",
        _ => "30+",
    }
}

/// The one-time consent ask, shared by all three interactive surfaces (the
/// CLI prompt, the TUI pane, and the web card) so the user reads the same
/// promise everywhere. Three short lines: the question, what is (and is not)
/// collected, and the off switch.
pub const CONSENT_QUESTION: &str = "Share anonymous usage data with Husk?";
pub const CONSENT_DETAIL: &str = "No account, no identifier: just daily aggregate counts, \
never file paths or package names.";
pub const CONSENT_OFF_HINT: &str = "Turn off anytime: husk telemetry off";

/// Whether the consent prompt should run. Pure over its inputs so the
/// decision is unit-testable without a TTY: prompt only in an interactive
/// terminal, never under CI or an environment kill switch, and only when the
/// user has never decided (or previously said yes to an older message
/// version; a recorded no is final).
pub fn consent_prompt_due(
    consent: TelemetryConsent,
    acknowledged_version: u32,
    stdin_is_tty: bool,
    stderr_is_tty: bool,
    ci: bool,
    do_not_track: bool,
    disabled_env: bool,
) -> bool {
    if !stdin_is_tty || !stderr_is_tty || ci || do_not_track || disabled_env {
        return false;
    }
    match consent {
        TelemetryConsent::Unset => true,
        TelemetryConsent::Enabled => acknowledged_version < CONSENT_MESSAGE_VERSION,
        TelemetryConsent::Disabled => false,
    }
}

/// [`consent_prompt_due`] against this state directory and the live
/// environment. The caller asserts the surface's interactivity: the CLI and
/// TUI pass real TTY checks; the web card passes `true` because a browser
/// session is interactive by construction.
pub fn consent_due_now(telemetry: &Telemetry, stdin_is_tty: bool, output_is_tty: bool) -> bool {
    consent_prompt_due(
        telemetry.consent(),
        telemetry.acknowledged_consent_version(),
        stdin_is_tty,
        output_is_tty,
        env_truthy(CI_ENV),
        env_truthy(DO_NOT_TRACK_ENV),
        env_truthy(TELEMETRY_DISABLED_ENV),
    )
}

/// Map one prompt answer line to a consent decision: only `y`/`yes`
/// (case-insensitive) enables; anything else, including an empty Enter,
/// declines.
pub fn consent_from_answer(answer: &str) -> TelemetryConsent {
    let answer = answer.trim();
    if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
        TelemetryConsent::Enabled
    } else {
        TelemetryConsent::Disabled
    }
}

/// In-flight background flush tasks, awaited by [`settle_flushes`] before
/// the process exits.
fn flush_tasks() -> &'static Mutex<Vec<tokio::task::JoinHandle<()>>> {
    static TASKS: OnceLock<Mutex<Vec<tokio::task::JoinHandle<()>>>> = OnceLock::new();
    TASKS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Await every background flush spawned this run. Each task is internally
/// bounded by [`FLUSH_TIMEOUT`], so this adds at most roughly that much to a
/// command's exit. Without this settle point, runtime teardown cancels the
/// upload mid-request and the spooled report never leaves the machine on
/// short-lived commands.
pub async fn settle_flushes() {
    let tasks: Vec<_> = std::mem::take(
        &mut *flush_tasks()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    for task in tasks {
        let _ = task.await;
    }
}

/// Serializes in-process read-modify-write cycles on the telemetry state
/// files (the MCP server bumps from concurrent tool tasks).
fn state_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Telemetry client bound to a husk state directory (`~/.husk` in
/// production, a temporary directory in tests).
#[derive(Clone, Debug)]
pub struct Telemetry {
    state_dir: PathBuf,
}

impl Telemetry {
    /// Client for the default state directory, `~/.husk`.
    pub fn from_default_dir() -> Result<Self> {
        Ok(Self::at(crate::paths::husk_home()?))
    }

    pub fn at(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
        }
    }

    /// Stored consent. Any unreadable config counts as not consented.
    pub fn consent(&self) -> TelemetryConsent {
        HuskCloudConfig::load_from(&self.state_dir)
            .unwrap_or_default()
            .telemetry
    }

    /// True only when the user opted in *and* no environment kill switch is
    /// active (see [`env_allows_telemetry`]). Gates accumulation and upload.
    pub fn is_enabled(&self) -> bool {
        self.consent().is_enabled() && env_allows_telemetry()
    }

    /// Opt in: persist consent, record the acknowledged consent message
    /// version, and pin the install day if this is the first opt-in.
    /// Idempotent; never rewinds `first_report_sent` or the install day.
    pub fn enable(&self) -> Result<()> {
        self.enable_at(Utc::now())
    }

    pub fn enable_at(&self, now: DateTime<Utc>) -> Result<()> {
        let _lock = state_lock();
        let mut config = HuskCloudConfig::load_from(&self.state_dir)?;
        config.telemetry = TelemetryConsent::Enabled;
        config.store_in(&self.state_dir)?;
        let mut meta = self.load_meta().unwrap_or_else(|| Meta {
            install_day: now.date_naive(),
            first_report_sent: false,
            consent_message_version_acknowledged: CONSENT_MESSAGE_VERSION,
        });
        meta.consent_message_version_acknowledged = CONSENT_MESSAGE_VERSION;
        self.store_meta(&meta)
    }

    /// Opt out: delete every piece of local telemetry state (the current
    /// day, the install metadata, all pending reports, and any leftover v1
    /// `telemetry_id` file), then persist the disabled consent. Deletion
    /// happens first so opting out removes data even if rewriting the config
    /// fails.
    pub fn disable(&self) -> Result<()> {
        let _lock = state_lock();
        let dir = self.telemetry_dir();
        if dir.is_dir() {
            fs::remove_dir_all(&dir).with_context(|| format!("delete {}", dir.display()))?;
        }
        // Best-effort: a v1 install may still carry the old id file.
        let _ = fs::remove_file(self.state_dir.join(LEGACY_ID_FILE));
        let mut config = HuskCloudConfig::load_from(&self.state_dir)?;
        config.telemetry = TelemetryConsent::Disabled;
        config.store_in(&self.state_dir)?;
        Ok(())
    }

    /// The consent message version the user last acknowledged (0 when never
    /// asked).
    pub fn acknowledged_consent_version(&self) -> u32 {
        self.load_meta()
            .map(|meta| meta.consent_message_version_acknowledged)
            .unwrap_or(0)
    }

    /// The install day, if telemetry has ever been enabled here.
    pub fn install_day(&self) -> Option<NaiveDate> {
        self.load_meta().map(|meta| meta.install_day)
    }

    /// Bump counters into the current day. A no-op unless telemetry
    /// [`is_enabled`](Self::is_enabled); never touches the network. If the
    /// stored day has ended, it is first finalized into a pending report and
    /// a fresh day starts, so bumps always land in the day containing now.
    pub fn bump(&self, counters: &[(String, u32)]) -> Result<()> {
        self.bump_at(counters, Utc::now())
    }

    pub fn bump_at(&self, counters: &[(String, u32)], now: DateTime<Utc>) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        let _lock = state_lock();
        let today = now.date_naive();
        let meta = self.load_or_repin_meta(today)?;
        let mut current = match self.load_current() {
            // The stored day has ended: finalize it, start fresh.
            Some(stored) if stored.day < today => {
                self.finalize_day(stored, &meta)?;
                CurrentDay::new(today)
            }
            Some(stored) => stored,
            None => CurrentDay::new(today),
        };
        for (key, amount) in counters {
            if !valid_counter_key(key) {
                // A bad key is a husk bug (the set is closed); say so, keep going.
                eprintln!("husk: telemetry: dropping counter with invalid key {key:?}");
                continue;
            }
            if let Some(value) = current.counters.get_mut(key) {
                *value = value.saturating_add(*amount).min(MAX_COUNTER_VALUE);
            } else if current.counters.len() < MAX_COUNTERS {
                current
                    .counters
                    .insert(key.clone(), (*amount).min(MAX_COUNTER_VALUE));
            }
        }
        self.store_current(&current)
    }

    /// Roll a completed day into the pending spool without bumping anything:
    /// the startup and daemon-midnight delivery path, so a report ships even
    /// when the new day has no activity yet. A no-op unless telemetry is
    /// enabled or when the stored day is still today.
    pub fn roll_over(&self) -> Result<()> {
        self.roll_over_at(Utc::now())
    }

    pub fn roll_over_at(&self, now: DateTime<Utc>) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        let _lock = state_lock();
        let today = now.date_naive();
        if let Some(stored) = self.load_current()
            && stored.day < today
        {
            let meta = self.load_or_repin_meta(today)?;
            self.finalize_day(stored, &meta)?;
            self.store_current(&CurrentDay::new(today))?;
        }
        Ok(())
    }

    /// Stored metadata, or fresh metadata pinned to `today` when it is
    /// missing (state partially deleted by hand): re-pin rather than fail
    /// every command.
    fn load_or_repin_meta(&self, today: NaiveDate) -> Result<Meta> {
        match self.load_meta() {
            Some(meta) => Ok(meta),
            None => {
                let meta = Meta {
                    install_day: today,
                    first_report_sent: false,
                    consent_message_version_acknowledged: CONSENT_MESSAGE_VERSION,
                };
                self.store_meta(&meta)?;
                Ok(meta)
            }
        }
    }

    /// Turn a completed day into one pending report file, then enforce the
    /// pending cap (oldest days are dropped first). A day with no counters
    /// produces no report: the report's existence is the activity signal.
    fn finalize_day(&self, day: CurrentDay, meta: &Meta) -> Result<()> {
        if day.counters.is_empty() {
            return Ok(());
        }
        let report = Report {
            schema: SCHEMA_VERSION,
            day: day.day,
            first_report: !meta.first_report_sent,
            days_since_install: days_since_install_bucket(meta.install_day, day.day).to_string(),
            husk_version: env!("CARGO_PKG_VERSION").to_string(),
            os: os_family().to_string(),
            arch: arch_label().to_string(),
            ci: env_truthy(CI_ENV),
            counters: day.counters,
        };
        let dir = self.pending_dir();
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let path = dir.join(format!("{}.json", report.day));
        write_atomic(&path, &serde_json::to_vec(&report)?)?;
        self.enforce_pending_cap()
    }

    /// Upload every pending report, oldest first, one POST per report. A
    /// report file is deleted only after the backend acknowledges it with
    /// exactly `202`; any other status or transport failure stops the flush
    /// and leaves the remaining spool intact for a later attempt. Returns the
    /// number of reports accepted. A no-op unless telemetry is enabled.
    pub async fn flush(&self, base_url: &str, client: &reqwest::Client) -> Result<usize> {
        if !self.is_enabled() || is_offline() {
            return Ok(0);
        }
        let mut sent = 0;
        for path in self.pending_files()? {
            let body = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            // A spool entry that is not valid JSON could never be accepted;
            // drop it so it cannot block newer reports forever.
            if serde_json::from_slice::<Value>(&body).is_err() {
                eprintln!(
                    "husk: telemetry: deleting unparseable pending report {}",
                    path.display()
                );
                let _ = fs::remove_file(&path);
                continue;
            }
            let response = client
                .post(api_url(base_url, REPORTS_PATH))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .context("send telemetry report")?;
            if response.status() != reqwest::StatusCode::ACCEPTED {
                bail!(
                    "telemetry endpoint returned {} (report stays spooled)",
                    response.status()
                );
            }
            let _ = fs::remove_file(&path);
            sent += 1;
            self.mark_first_report_sent()?;
        }
        Ok(sent)
    }

    /// [`flush`](Self::flush) against the configured backend, resolved
    /// through the standard chain: `HUSK_BACKEND_URL` beats this state
    /// directory's `config.json`, which beats the built-in default.
    pub async fn flush_configured(&self, client: &reqwest::Client) -> Result<usize> {
        let config = HuskCloudConfig::load_from(&self.state_dir).unwrap_or_default();
        self.flush(&super::effective_backend_url(&config), client)
            .await
    }

    /// After the first `202`, future reports stop claiming `first_report`.
    fn mark_first_report_sent(&self) -> Result<()> {
        let _lock = state_lock();
        if let Some(mut meta) = self.load_meta()
            && !meta.first_report_sent
        {
            meta.first_report_sent = true;
            self.store_meta(&meta)?;
        }
        Ok(())
    }

    /// [`flush`](Self::flush) on a detached tokio task, bounded by
    /// [`FLUSH_TIMEOUT`]. Failures are logged to stderr; the spool stays
    /// intact for the next run. A no-op when telemetry is disabled, offline
    /// is set, nothing is pending, or no runtime is active.
    ///
    /// The handle is registered so [`settle_flushes`] can await it before the
    /// process exits: dropping the runtime cancels detached tasks, and a short
    /// command (`husk telemetry status`) otherwise exits before the request
    /// even resolves DNS.
    pub fn spawn_flush(&self, base_url: impl Into<String>, client: reqwest::Client) {
        if !self.is_enabled() || is_offline() || self.pending_count() == 0 {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let telemetry = self.clone();
        let base_url = base_url.into();
        let handle = runtime.spawn(async move {
            match tokio::time::timeout(FLUSH_TIMEOUT, telemetry.flush(&base_url, &client)).await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => eprintln!("husk: telemetry upload failed: {err:#}"),
                Err(_) => eprintln!("husk: telemetry upload timed out"),
            }
        });
        flush_tasks()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(handle);
    }

    /// Render the current day's counters plus every pending report verbatim:
    /// everything telemetry holds, and exactly what upload would send.
    pub fn payload(&self) -> Result<String> {
        let mut out = String::new();
        match self.load_current() {
            Some(current) => {
                out.push_str(
                    "Current day (still accumulating, becomes a report when the day ends):\n",
                );
                out.push_str(&serde_json::to_string_pretty(&current)?);
                out.push('\n');
            }
            None => out.push_str("No counters recorded yet today.\n"),
        }
        let pending = self.pending_reports()?;
        if pending.is_empty() {
            out.push_str("No pending reports.\n");
        } else {
            for (path, report) in &pending {
                out.push_str(&format!(
                    "\nPending report {} (sent verbatim on the next flush):\n",
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("?")
                ));
                out.push_str(&serde_json::to_string_pretty(report)?);
                out.push('\n');
            }
        }
        Ok(out)
    }

    /// Every pending report, oldest day first, parsed verbatim.
    pub fn pending_reports(&self) -> Result<Vec<(PathBuf, Value)>> {
        let mut reports = Vec::new();
        for path in self.pending_files()? {
            let contents =
                fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            let report = serde_json::from_str(&contents)
                .with_context(|| format!("parse {}", path.display()))?;
            reports.push((path, report));
        }
        Ok(reports)
    }

    pub fn pending_count(&self) -> usize {
        self.pending_files().map(|files| files.len()).unwrap_or(0)
    }

    fn telemetry_dir(&self) -> PathBuf {
        self.state_dir.join(TELEMETRY_SUBDIR)
    }

    pub fn pending_dir(&self) -> PathBuf {
        self.telemetry_dir().join(PENDING_SUBDIR)
    }

    fn current_path(&self) -> PathBuf {
        self.telemetry_dir().join(CURRENT_FILE)
    }

    fn meta_path(&self) -> PathBuf {
        self.telemetry_dir().join(META_FILE)
    }

    fn load_current(&self) -> Option<CurrentDay> {
        load_state(&self.current_path())
    }

    fn store_current(&self, current: &CurrentDay) -> Result<()> {
        self.store_json(&self.current_path(), current)
    }

    fn load_meta(&self) -> Option<Meta> {
        load_state(&self.meta_path())
    }

    fn store_meta(&self, meta: &Meta) -> Result<()> {
        self.store_json(&self.meta_path(), meta)
    }

    fn store_json<T: Serialize>(&self, path: &std::path::Path, value: &T) -> Result<()> {
        ensure_dir_private(&self.state_dir)?;
        let dir = self.telemetry_dir();
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        write_atomic(path, &serde_json::to_vec_pretty(value)?)
    }

    /// Pending report files, oldest day first. Filenames are the reported
    /// day's ISO date, so lexicographic order is chronological order.
    fn pending_files(&self) -> Result<Vec<PathBuf>> {
        let dir = self.pending_dir();
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                files.push(path);
            }
        }
        files.sort();
        Ok(files)
    }

    /// Drop the oldest pending reports until at most [`MAX_PENDING_REPORTS`]
    /// remain.
    fn enforce_pending_cap(&self) -> Result<()> {
        let mut files = self.pending_files()?;
        if files.len() > MAX_PENDING_REPORTS {
            let excess = files.len() - MAX_PENDING_REPORTS;
            for path in files.drain(..excess) {
                let _ = fs::remove_file(path);
            }
        }
        Ok(())
    }
}

/// Load a telemetry state file, treating anything unreadable or unparseable
/// (including a leftover pre-v3 weekly state file) as absent. Telemetry
/// state is disposable by design: a bad file must re-initialize, never wedge
/// accumulation on every future command.
fn load_state<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Option<T> {
    let contents = fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Process-wide "offline" flag, set by the `--offline` scan flag. When on,
/// telemetry keeps accumulating locally but the network flush is suppressed:
/// the flag promises "fully offline", so it must not phone home even for an
/// opted-in user.
static OFFLINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_offline(offline: bool) {
    OFFLINE.store(offline, std::sync::atomic::Ordering::Relaxed);
}

/// Whether `--offline` suppressed telemetry network sends this run.
pub fn is_offline() -> bool {
    OFFLINE.load(std::sync::atomic::Ordering::Relaxed)
}

/// True when telemetry accumulates and would send: the user opted in (state
/// in `~/.husk`) and no environment kill switch is active.
pub fn is_enabled() -> bool {
    Telemetry::from_default_dir().is_ok_and(|telemetry| telemetry.is_enabled())
}

/// Bump counters against the default state directory. Failures are logged to
/// stderr and never fail or slow the command.
pub fn bump(counters: &[(String, u32)]) {
    let Ok(telemetry) = Telemetry::from_default_dir() else {
        return;
    };
    if let Err(err) = telemetry.bump(counters) {
        eprintln!("husk: telemetry: could not record counters: {err:#}");
    }
}

/// [`bump`] one counter by one.
pub fn bump_one(counter: impl Into<String>) {
    bump(&[(counter.into(), 1)]);
}

/// Fire-and-forget upload of pending reports against the configured backend.
/// See [`Telemetry::spawn_flush`].
pub fn flush_in_background() {
    if is_offline() {
        return;
    }
    let Ok(telemetry) = Telemetry::from_default_dir() else {
        return;
    };
    let config = HuskCloudConfig::load().unwrap_or_default();
    let Ok(client) = super::http_client() else {
        return;
    };
    telemetry.spawn_flush(super::effective_backend_url(&config), client);
}

/// Roll any completed day into the pending spool and start the background
/// flush: the delivery step every husk invocation runs at startup, and the
/// daemon repeats after each UTC midnight. Failures are logged, never fatal.
pub fn deliver_in_background() {
    let Ok(telemetry) = Telemetry::from_default_dir() else {
        return;
    };
    if let Err(err) = telemetry.roll_over() {
        eprintln!("husk: telemetry: could not roll the day over: {err:#}");
    }
    flush_in_background();
}

/// Record a completed scan into the daily counters (bucketed duration and
/// package count, per-severity finding counts, canonical scanner ids) and
/// opportunistically flush pending reports. A no-op unless the user opted in.
pub fn record_scan(report: &crate::model::ScanReport, duration: Duration) {
    if !is_enabled() {
        return;
    }
    let mut bumps: Vec<(String, u32)> = vec![
        (counters::SCAN_COMPLETED.to_string(), 1),
        (counters::scan_duration(duration).to_string(), 1),
        (
            counters::scan_packages(report.stats.packages).to_string(),
            1,
        ),
    ];
    for (severity, count) in [
        ("critical", report.stats.critical),
        ("high", report.stats.high),
        ("medium", report.stats.medium),
        ("low", report.stats.low),
        ("info", report.stats.info),
    ] {
        if count > 0 {
            bumps.push((
                counters::scan_findings(severity),
                u32::try_from(count).unwrap_or(u32::MAX),
            ));
        }
    }
    for provider in &report.providers {
        if let Some(id) = scanner_telemetry_id(&provider.name) {
            bumps.push((counters::scan_scanner(id), 1));
        }
    }
    bump(&bumps);
    flush_in_background();
}

/// Ask for telemetry consent once, at the end of a successful interactive
/// scan: only when the decision is due (see [`consent_prompt_due`]), only on
/// a real terminal, and never more than the message version warrants. The
/// answer is recorded either way, so a no is never asked again.
pub fn prompt_for_consent_if_due() {
    use std::io::IsTerminal;
    let Ok(telemetry) = Telemetry::from_default_dir() else {
        return;
    };
    if !consent_due_now(
        &telemetry,
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    ) {
        return;
    }
    eprintln!();
    eprintln!("{CONSENT_QUESTION}");
    eprintln!("{CONSENT_DETAIL}");
    eprintln!("{CONSENT_OFF_HINT}. Inspect the exact payload: husk telemetry status --payload");
    eprint!("Enable anonymous telemetry? [y/N] ");
    let mut answer = String::new();
    // No answer (EOF, read error) is not a decision; ask again another time.
    if std::io::stdin().read_line(&mut answer).is_err() {
        return;
    }
    let outcome = match consent_from_answer(&answer) {
        TelemetryConsent::Enabled => telemetry.enable().map(|()| {
            eprintln!("Telemetry is on. Turn it off any time with `husk telemetry off`.");
        }),
        _ => telemetry.disable().map(|()| {
            eprintln!("Telemetry stays off.");
        }),
    };
    if let Err(err) = outcome {
        eprintln!("husk: telemetry: could not record the consent decision: {err:#}");
    }
}

/// Coarse OS family: `linux`, `macos`, or `windows` (anything else reports
/// as `other`, never a finer-grained platform string).
fn os_family() -> &'static str {
    match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        "windows" => "windows",
        _ => "other",
    }
}

/// `std::env::consts::ARCH`, collapsed to `other` if implausibly long for
/// the wire.
fn arch_label() -> &'static str {
    let arch = std::env::consts::ARCH;
    if arch.len() > 16 { "other" } else { arch }
}

/// Map a human-facing provider display name to a stable, space-free scanner
/// id for telemetry. The wire stays a closed, anonymous set (matching the
/// documented telemetry policy); human display names (which contain spaces and
/// would be rejected by the counter-key charset) never leak. Unrecognized
/// names are dropped so the set can never silently drift.
pub(crate) fn scanner_telemetry_id(name: &str) -> Option<&'static str> {
    match name {
        "OSV.dev" => Some("osv"),
        "npm audit" => Some("npm_audit"),
        "PyPI JSON" => Some("pypi"),
        "GitHub Advisory Database" => Some("github_advisory"),
        "Arch Security" => Some("arch_security"),
        "online providers" => Some("online_providers"),
        "provider client" | "provider worker" => Some("provider_client"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_telemetry_ids_are_valid_counter_suffixes_and_closed() {
        // The real provider display names must map to ids that survive the
        // counter-key charset, so `scan.scanner.<id>` is always sendable.
        for (display, id) in [
            ("OSV.dev", "osv"),
            ("npm audit", "npm_audit"),
            ("PyPI JSON", "pypi"),
            ("GitHub Advisory Database", "github_advisory"),
            ("Arch Security", "arch_security"),
            ("online providers", "online_providers"),
            ("provider client", "provider_client"),
            ("provider worker", "provider_client"),
        ] {
            let mapped = scanner_telemetry_id(display).expect("known provider name maps");
            assert_eq!(mapped, id, "{display}");
            assert!(
                valid_counter_key(&counters::scan_scanner(mapped)),
                "scanner counter key must match the wire charset"
            );
        }
        // Unknown names are dropped, never leaked verbatim.
        assert_eq!(scanner_telemetry_id("something else"), None);
    }

    #[test]
    fn mcp_tool_counters_stay_inside_the_charset() {
        assert_eq!(
            counters::mcp_tool("husk_scan").as_deref(),
            Some("mcp.tool.husk_scan")
        );
        assert_eq!(
            counters::mcp_tool_err("husk_scan").as_deref(),
            Some("mcp.tool.husk_scan.err")
        );
        assert!(valid_counter_key(counters::MCP_TOOL_UNKNOWN));
        // A hostile tool name never becomes a counter key.
        assert_eq!(counters::mcp_tool("Weird Name"), None);
        assert_eq!(counters::mcp_tool_err("Weird Name"), None);
    }

    #[test]
    fn days_since_install_buckets_match_the_contract() {
        let install = NaiveDate::from_ymd_opt(2026, 8, 1).expect("valid date");
        let day = |offset: u64| install + chrono::Days::new(offset);
        assert_eq!(days_since_install_bucket(install, day(0)), "0");
        assert_eq!(days_since_install_bucket(install, day(1)), "1-6");
        assert_eq!(days_since_install_bucket(install, day(6)), "1-6");
        assert_eq!(days_since_install_bucket(install, day(7)), "7-29");
        assert_eq!(days_since_install_bucket(install, day(29)), "7-29");
        assert_eq!(days_since_install_bucket(install, day(30)), "30+");
        assert_eq!(days_since_install_bucket(install, day(4000)), "30+");
        // A clock that went backwards must not panic or invent a bucket.
        assert_eq!(
            days_since_install_bucket(install, install - chrono::Days::new(3)),
            "0"
        );
    }
}
