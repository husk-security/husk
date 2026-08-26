//! Integration tests for the opt-in daily-aggregate telemetry client.
//!
//! Telemetry behavior depends on process environment variables
//! (`DO_NOT_TRACK`, `HUSK_TELEMETRY_DISABLED`, `CI`, `HUSK_TELEMETRY`,
//! `HUSK_BACKEND_URL`), so every test that bumps, flushes, or checks
//! enablement serializes on [`env_guard`], which resets those variables to a
//! known-clean state and restores their prior values on drop (even on panic)
//! via the shared [`common::EnvVarGuard`]. Time never comes from the clock:
//! the `*_at` client methods take an injected now, so day rollovers are
//! driven by dates, not sleeps. No test touches the real `~/.husk` or the
//! network; flush tests talk only to loopback sockets owned by the test.

use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use husk::cloud::telemetry::{
    CONSENT_MESSAGE_VERSION, MAX_COUNTER_VALUE, MAX_COUNTERS, MAX_PENDING_REPORTS, Telemetry,
    consent_due_now, consent_from_answer, consent_prompt_due, counters, env_allows_telemetry,
    valid_counter_key,
};
use husk::cloud::{HuskCloudConfig, TelemetryConsent};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

mod common;

const TRACKED_ENV_VARS: [&str; 5] = [
    "DO_NOT_TRACK",
    "HUSK_TELEMETRY_DISABLED",
    "CI",
    "HUSK_TELEMETRY",
    "HUSK_BACKEND_URL",
];

/// Serialize environment-dependent tests and start each from a clean slate.
/// The returned guard restores every touched variable's prior value on drop.
fn env_guard() -> common::EnvVarGuard {
    let mut guard = common::EnvVarGuard::acquire();
    for name in TRACKED_ENV_VARS {
        guard.remove(name);
    }
    guard
}

fn date(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("valid date")
}

/// Noon UTC on the given date: a time squarely inside that day.
fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 12, 0, 0)
        .single()
        .expect("valid time")
}

/// Three consecutive test days.
const DAY1: (i32, u32, u32) = (2026, 8, 10);
const DAY2: (i32, u32, u32) = (2026, 8, 11);
const DAY3: (i32, u32, u32) = (2026, 8, 12);

fn bump_key(telemetry: &Telemetry, key: &str, amount: u32, now: DateTime<Utc>) {
    telemetry
        .bump_at(&[(key.to_string(), amount)], now)
        .expect("bump");
}

/// A telemetry client in a fresh state directory, opted in during DAY1.
fn enabled_telemetry() -> (TempDir, Telemetry) {
    let dir = TempDir::new().expect("create temp state dir");
    let telemetry = Telemetry::at(dir.path());
    let (y, m, d) = DAY1;
    telemetry.enable_at(at(y, m, d)).expect("enable telemetry");
    (dir, telemetry)
}

fn current_day_json(dir: &Path) -> Value {
    let contents =
        fs::read_to_string(dir.join("telemetry/current.json")).expect("read current.json");
    serde_json::from_str(&contents).expect("parse current.json")
}

/// The coarse OS family the wire contract allows, as the client must report
/// it on this platform.
fn expected_os() -> &'static str {
    match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        "windows" => "windows",
        _ => "other",
    }
}

#[test]
fn env_gate_truth_table() {
    let mut guard = env_guard();

    // Clean environment: nothing suppresses telemetry.
    assert!(env_allows_telemetry());

    // DO_NOT_TRACK beats everything, including the explicit CI override.
    guard.set("DO_NOT_TRACK", "1");
    assert!(!env_allows_telemetry());
    guard.set("HUSK_TELEMETRY", "1");
    assert!(!env_allows_telemetry());
    guard.remove("HUSK_TELEMETRY");
    guard.set("DO_NOT_TRACK", "true");
    assert!(!env_allows_telemetry());
    guard.set("DO_NOT_TRACK", "0");
    assert!(env_allows_telemetry());
    guard.remove("DO_NOT_TRACK");

    // The husk-specific kill switch behaves the same way.
    guard.set("HUSK_TELEMETRY_DISABLED", "1");
    assert!(!env_allows_telemetry());
    guard.remove("HUSK_TELEMETRY_DISABLED");

    // CI suppresses telemetry unless HUSK_TELEMETRY=1 re-enables it.
    guard.set("CI", "true");
    assert!(!env_allows_telemetry());
    guard.set("HUSK_TELEMETRY", "1");
    assert!(env_allows_telemetry());
    guard.remove("CI");
    guard.remove("HUSK_TELEMETRY");
}

#[test]
fn is_enabled_requires_consent_and_environment() {
    let mut guard = env_guard();
    let dir = TempDir::new().expect("create temp state dir");
    let telemetry = Telemetry::at(dir.path());

    // Default is unset (never asked) and off, even with a permissive env.
    assert_eq!(telemetry.consent(), TelemetryConsent::Unset);
    assert!(!telemetry.is_enabled());

    telemetry.enable().expect("enable telemetry");
    assert_eq!(telemetry.consent(), TelemetryConsent::Enabled);
    assert!(telemetry.is_enabled());

    // Kill switches override the stored opt-in.
    guard.set("DO_NOT_TRACK", "1");
    assert!(!telemetry.is_enabled());
    guard.remove("DO_NOT_TRACK");

    guard.set("CI", "true");
    assert!(!telemetry.is_enabled());
    guard.set("HUSK_TELEMETRY", "1");
    assert!(telemetry.is_enabled());
}

#[test]
fn nothing_is_written_before_opt_in() {
    let mut guard = env_guard();
    let dir = TempDir::new().expect("create temp state dir");
    let telemetry = Telemetry::at(dir.path());
    let (y, m, d) = DAY1;

    bump_key(&telemetry, counters::SCAN_COMPLETED, 1, at(y, m, d));
    assert!(
        !dir.path().join("telemetry").exists(),
        "no telemetry file or directory may exist before opt-in"
    );
    assert_eq!(telemetry.pending_count(), 0);

    // Opted in but suppressed by environment: counters must not accumulate.
    telemetry.enable_at(at(y, m, d)).expect("enable telemetry");
    guard.set("DO_NOT_TRACK", "1");
    bump_key(&telemetry, counters::SCAN_COMPLETED, 1, at(y, m, d));
    assert!(
        !dir.path().join("telemetry/current.json").exists(),
        "a kill switch stops accumulation, not just upload"
    );
}

#[test]
fn counters_accumulate_and_enforce_the_key_charset_and_caps() {
    let _guard = env_guard();
    let (dir, telemetry) = enabled_telemetry();

    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    telemetry
        .bump_at(
            &[
                ("Not A Valid Key".to_string(), 1),
                (counters::SCAN_COMPLETED.to_string(), 1),
            ],
            at(2026, 8, 10),
        )
        .expect("bump");
    // Values cap at MAX_COUNTER_VALUE.
    bump_key(&telemetry, "cli.run.status", u32::MAX, at(2026, 8, 10));

    let current = current_day_json(dir.path());
    assert_eq!(current["day"], "2026-08-10");
    assert_eq!(current["counters"]["cli.run.scan"], 2);
    assert_eq!(current["counters"]["scan.completed"], 1);
    assert_eq!(
        current["counters"]["cli.run.status"], MAX_COUNTER_VALUE,
        "values cap when bumping"
    );
    assert!(
        current["counters"].get("Not A Valid Key").is_none(),
        "keys outside the charset are dropped"
    );

    // At most MAX_COUNTERS distinct keys; bumps of new keys beyond that drop.
    for index in 0..(MAX_COUNTERS + 10) {
        bump_key(&telemetry, &format!("cli.run.k{index}"), 1, at(2026, 8, 10));
    }
    let counters = current_day_json(dir.path());
    let map = counters["counters"].as_object().expect("counters object");
    assert_eq!(map.len(), MAX_COUNTERS);
}

#[test]
fn counter_key_charset_is_enforced_exactly() {
    for valid in [
        "a",
        "cli.run.scan",
        "scan.duration.under-1s",
        "mcp.tool.husk_scan",
        "mcp.tool.husk_scan.err",
        "a+b:c-d_e.f0",
        &"x".repeat(64),
    ] {
        assert!(valid_counter_key(valid), "{valid:?} should be valid");
    }
    for invalid in [
        "",
        "Upper",
        "has space",
        "naïve",
        "semi;colon",
        &"x".repeat(65),
    ] {
        assert!(!valid_counter_key(invalid), "{invalid:?} should be invalid");
    }
}

#[test]
fn day_rollover_finalizes_exactly_one_pending_report() {
    let _guard = env_guard();
    let (dir, telemetry) = enabled_telemetry();

    // Several bumps within day 1.
    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    bump_key(&telemetry, counters::SCAN_COMPLETED, 1, at(2026, 8, 10));
    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    assert_eq!(telemetry.pending_count(), 0, "the day is still open");

    // The first bump of day 2 finalizes day 1.
    let (y2, m2, d2) = DAY2;
    bump_key(&telemetry, "cli.run.status", 1, at(y2, m2, d2));
    assert_eq!(telemetry.pending_count(), 1);

    let pending = telemetry.pending_reports().expect("read pending");
    let (_, report) = &pending[0];
    assert_eq!(
        report,
        &json!({
            "schema": 3,
            "day": "2026-08-10",
            "first_report": true,
            "days_since_install": "0",
            "husk_version": env!("CARGO_PKG_VERSION"),
            "os": expected_os(),
            "arch": std::env::consts::ARCH,
            "ci": false,
            "counters": { "cli.run.scan": 2, "scan.completed": 1 },
        }),
        "exactly the wire fields, nothing extra, no identifier"
    );

    // Day 2's bump landed in a fresh current day, not the report.
    let current = current_day_json(dir.path());
    assert_eq!(current["day"], "2026-08-11");
    assert_eq!(current["counters"], json!({ "cli.run.status": 1 }));
}

#[test]
fn startup_roll_over_delivers_without_a_bump_and_skips_empty_days() {
    let _guard = env_guard();
    let (dir, telemetry) = enabled_telemetry();

    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    // The startup path: no counter bump, just the rollover check.
    let (y2, m2, d2) = DAY2;
    telemetry.roll_over_at(at(y2, m2, d2)).expect("roll over");
    assert_eq!(
        telemetry.pending_count(),
        1,
        "a completed day becomes a report at startup, no scan or bump needed"
    );
    let pending = telemetry.pending_reports().expect("read pending");
    assert_eq!(pending[0].1["day"], "2026-08-10");

    // The rollover reset the current day; rolling again is a no-op.
    let current = current_day_json(dir.path());
    assert_eq!(current["day"], "2026-08-11");
    assert_eq!(current["counters"], json!({}));
    telemetry.roll_over_at(at(y2, m2, d2)).expect("roll over");
    assert_eq!(telemetry.pending_count(), 1);

    // A day that ends with zero counters produces no report at all.
    let (y3, m3, d3) = DAY3;
    telemetry.roll_over_at(at(y3, m3, d3)).expect("roll over");
    assert_eq!(
        telemetry.pending_count(),
        1,
        "an empty day sends nothing: the report's existence is the signal"
    );
}

#[test]
fn leftover_weekly_state_is_reset_not_fatal() {
    let _guard = env_guard();
    let (dir, telemetry) = enabled_telemetry();

    // A pre-v3 install left weekly-shaped state files behind. They must be
    // treated as absent (fresh start), never as an error on every command.
    let telemetry_dir = dir.path().join("telemetry");
    fs::create_dir_all(&telemetry_dir).expect("create telemetry dir");
    fs::write(
        telemetry_dir.join("current.json"),
        r#"{"week_start":"2026-08-03","counters":{"cli.run.scan":4},"active_dates":["2026-08-04"]}"#,
    )
    .expect("plant weekly current");
    fs::write(
        telemetry_dir.join("meta.json"),
        r#"{"install_week":"2026-08-03","first_report_sent":true,"consent_message_version_acknowledged":1}"#,
    )
    .expect("plant weekly meta");

    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    let current = current_day_json(dir.path());
    assert_eq!(current["day"], "2026-08-10");
    assert_eq!(current["counters"], json!({ "cli.run.scan": 1 }));
    assert_eq!(
        telemetry.pending_count(),
        0,
        "old weekly data is never sent"
    );
}

// The env guard must intentionally span the awaits: flush behavior depends
// on process environment variables, and the runtime is single-threaded here.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn flush_posts_the_exact_report_and_first_report_flips_after_202() {
    let _guard = env_guard();
    let (_dir, telemetry) = enabled_telemetry();
    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    let (y2, m2, d2) = DAY2;
    bump_key(&telemetry, "cli.run.scan", 1, at(y2, m2, d2));
    assert_eq!(telemetry.pending_count(), 1);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(accept_one_request(listener, "202 Accepted"));

    let client = husk::cloud::http_client().expect("build client");
    let sent = telemetry
        .flush(&format!("http://{address}"), &client)
        .await
        .expect("flush succeeds");
    assert_eq!(sent, 1);
    assert_eq!(
        telemetry.pending_count(),
        0,
        "a 202 deletes the spooled report"
    );

    let (head, body) = server.await.expect("server task");
    let request_line = head.lines().next().expect("request line");
    assert!(
        request_line.starts_with("POST /api/v1/telemetry/reports"),
        "unexpected request line: {request_line}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/json"),
        "missing JSON content type: {head}"
    );
    let payload: Value = serde_json::from_str(&body).expect("request body is JSON");
    assert_eq!(
        payload,
        json!({
            "schema": 3,
            "day": "2026-08-10",
            "first_report": true,
            "days_since_install": "0",
            "husk_version": env!("CARGO_PKG_VERSION"),
            "os": expected_os(),
            "arch": std::env::consts::ARCH,
            "ci": false,
            "counters": { "cli.run.scan": 1 },
        }),
        "the upload body is exactly the documented report, no identifier"
    );

    // The install's first report was accepted: the next finalized day must
    // no longer claim first_report.
    let (y3, m3, d3) = DAY3;
    bump_key(&telemetry, "cli.run.scan", 1, at(y3, m3, d3));
    let pending = telemetry.pending_reports().expect("read pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1["day"], "2026-08-11");
    assert_eq!(pending[0].1["first_report"], false);
}

// The env guard must intentionally span the awaits; see above.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn settle_flushes_delivers_the_spawned_upload_before_exit() {
    let _guard = env_guard();
    let (_dir, telemetry) = enabled_telemetry();
    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    let (y2, m2, d2) = DAY2;
    bump_key(&telemetry, "cli.run.scan", 1, at(y2, m2, d2));
    assert_eq!(telemetry.pending_count(), 1);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(accept_one_request(listener, "202 Accepted"));

    // The production path: a detached spawn followed by the pre-exit settle.
    // Without settle_flushes the runtime would tear the task down mid-request
    // (observed live as "dns error: task was cancelled").
    let client = husk::cloud::http_client().expect("build client");
    telemetry.spawn_flush(format!("http://{address}"), client);
    husk::cloud::telemetry::settle_flushes().await;

    assert_eq!(
        telemetry.pending_count(),
        0,
        "the settled flush must have delivered and cleared the spool"
    );
    let (head, _body) = server.await.expect("server task");
    assert!(
        head.starts_with("POST /api/v1/telemetry/reports"),
        "unexpected request: {head}"
    );
}

// The env guard must intentionally span the awaits; see above.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn non_202_keeps_the_report_spooled_and_first_report_pending() {
    let mut guard = env_guard();
    let (_dir, telemetry) = enabled_telemetry();
    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    let (y2, m2, d2) = DAY2;
    bump_key(&telemetry, "cli.run.scan", 1, at(y2, m2, d2));

    // 200 is not the contract; only exactly 202 acknowledges a report.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(accept_one_request(listener, "200 OK"));

    let client = husk::cloud::http_client().expect("build client");
    let result = telemetry.flush(&format!("http://{address}"), &client).await;
    assert!(result.is_err(), "a non-202 status must fail the flush");
    assert_eq!(telemetry.pending_count(), 1, "the report stays spooled");
    server.await.expect("server task");

    // No 202 yet, so a later day still carries first_report.
    let (y3, m3, d3) = DAY3;
    bump_key(&telemetry, "cli.run.scan", 1, at(y3, m3, d3));
    let pending = telemetry.pending_reports().expect("read pending");
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[1].1["first_report"], true);

    // Environment kill switches stop flushes outright: no request, no error.
    guard.set("DO_NOT_TRACK", "1");
    let sent = telemetry
        .flush(&format!("http://{address}"), &client)
        .await
        .expect("suppressed flush is a silent no-op");
    assert_eq!(sent, 0);
    assert_eq!(telemetry.pending_count(), 2);
}

// The env guard serializes flush-affecting tests; see above. `--offline` must
// suppress the network flush entirely while local accumulation continues.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn offline_suppresses_flush_but_accumulation_continues() {
    let _guard = env_guard();
    let (dir, telemetry) = enabled_telemetry();
    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    let (y2, m2, d2) = DAY2;
    bump_key(&telemetry, "cli.run.scan", 1, at(y2, m2, d2));
    assert_eq!(telemetry.pending_count(), 1);

    // A loopback port nothing listens on: a real send would error, so a clean
    // `Ok(0)` proves no request was attempted.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
        let port = listener.local_addr().expect("probe address").port();
        drop(listener);
        port
    };

    // RAII reset so a panic in the assertions below can't leave the
    // process-wide OFFLINE flag stuck `true` for later tests in this binary.
    struct OfflineGuard;
    impl Drop for OfflineGuard {
        fn drop(&mut self) {
            husk::cloud::telemetry::set_offline(false);
        }
    }

    husk::cloud::telemetry::set_offline(true);
    let _offline_guard = OfflineGuard;
    let client = husk::cloud::http_client().expect("build client");
    let sent = telemetry
        .flush(&format!("http://127.0.0.1:{port}"), &client)
        .await
        .expect("offline flush is a silent no-op");
    assert_eq!(sent, 0, "no send attempted while offline");
    assert_eq!(
        telemetry.pending_count(),
        1,
        "the report stays for a later run"
    );

    // Local accumulation is not suppressed by offline.
    bump_key(&telemetry, "cli.run.scan", 1, at(y2, m2, d2));
    let current = current_day_json(dir.path());
    assert_eq!(current["counters"]["cli.run.scan"], 2);
}

// The env guard must intentionally span the awaits; see above.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn backend_url_env_override_routes_the_upload() {
    let mut guard = env_guard();
    let (_dir, telemetry) = enabled_telemetry();
    bump_key(&telemetry, "cli.run.scan", 1, at(2026, 8, 10));
    let (y2, m2, d2) = DAY2;
    bump_key(&telemetry, "cli.run.scan", 1, at(y2, m2, d2));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(accept_one_request(listener, "202 Accepted"));

    // The uploader resolves its target through the standard chain; the env
    // override must beat the default (and the config file, which is empty).
    guard.set("HUSK_BACKEND_URL", format!("http://{address}"));
    let client = husk::cloud::http_client().expect("build client");
    let sent = telemetry
        .flush_configured(&client)
        .await
        .expect("flush against the overridden backend");
    assert_eq!(sent, 1);

    let (head, _) = server.await.expect("server task");
    assert!(
        head.lines()
            .next()
            .expect("request line")
            .starts_with("POST /api/v1/telemetry/reports"),
        "unexpected request line: {head}"
    );
}

#[test]
fn disable_deletes_all_state_including_the_legacy_id_but_keeps_other_config() {
    let _guard = env_guard();
    let dir = TempDir::new().expect("create temp state dir");

    // Pre-existing configuration written by other cloud features.
    let config = HuskCloudConfig {
        backend_url: Some("http://localhost:8787".to_string()),
        ..HuskCloudConfig::default()
    };
    config.store_in(dir.path()).expect("store config");

    let telemetry = Telemetry::at(dir.path());
    let (y, m, d) = DAY1;
    telemetry.enable_at(at(y, m, d)).expect("enable telemetry");
    bump_key(&telemetry, "cli.run.scan", 1, at(y, m, d));
    let (y2, m2, d2) = DAY2;
    bump_key(&telemetry, "cli.run.scan", 1, at(y2, m2, d2));
    assert_eq!(telemetry.pending_count(), 1);
    // A leftover v1 install id must go too.
    let legacy_id = dir.path().join("telemetry_id");
    fs::write(&legacy_id, "0decafba-dbad-4dea-89ab-000000000000\n").expect("plant legacy id");

    telemetry.disable().expect("disable telemetry");

    assert_eq!(telemetry.consent(), TelemetryConsent::Disabled);
    assert!(!telemetry.is_enabled());
    assert!(
        !dir.path().join("telemetry").exists(),
        "current day, metadata, and pending reports are all deleted"
    );
    assert!(!legacy_id.exists(), "the v1 telemetry_id file is deleted");
    assert_eq!(telemetry.pending_count(), 0);
    assert_eq!(telemetry.install_day(), None);

    // The rest of the config survives the opt-out.
    let config = HuskCloudConfig::load_from(dir.path()).expect("reload config");
    assert_eq!(config.backend_url.as_deref(), Some("http://localhost:8787"));
    assert_eq!(config.telemetry, TelemetryConsent::Disabled);
}

#[test]
fn pending_reports_cap_dropping_the_oldest_days() {
    let _guard = env_guard();
    let (_dir, telemetry) = enabled_telemetry();

    // One bump on each of MAX + 4 consecutive days: each new day finalizes
    // the one before it, producing MAX + 3 finalized reports along the way.
    let (y, m, d) = DAY1;
    let first_day = date(y, m, d);
    let total = MAX_PENDING_REPORTS as u64 + 4;
    for day in 0..total {
        let current = first_day + chrono::Days::new(day);
        let now = Utc.from_utc_datetime(&current.and_hms_opt(12, 0, 0).expect("valid time"));
        bump_key(&telemetry, "cli.run.scan", 1, now);
    }

    assert_eq!(telemetry.pending_count(), MAX_PENDING_REPORTS);
    let pending = telemetry.pending_reports().expect("read pending");
    // The oldest days were dropped; the newest finalized day is yesterday
    // relative to the last bump.
    let expected_oldest =
        (first_day + chrono::Days::new(total - 1)) - chrono::Days::new(MAX_PENDING_REPORTS as u64);
    assert_eq!(
        pending[0].1["day"],
        Value::String(expected_oldest.to_string())
    );
    assert_eq!(
        pending.last().expect("newest").1["day"],
        Value::String((first_day + chrono::Days::new(total - 2)).to_string())
    );
}

#[test]
fn consent_prompt_runs_only_when_due_in_an_interactive_terminal() {
    use TelemetryConsent::{Disabled, Enabled, Unset};
    let due = |consent, acknowledged| {
        consent_prompt_due(consent, acknowledged, true, true, false, false, false)
    };

    // Never decided, interactive, clean env: ask.
    assert!(due(Unset, 0));
    // A recorded decision is final at the current message version.
    assert!(!due(Disabled, 0));
    assert!(!due(Enabled, CONSENT_MESSAGE_VERSION));
    // A message-version bump re-asks only installs that previously said yes.
    assert!(due(Enabled, CONSENT_MESSAGE_VERSION - 1));
    assert!(!due(Disabled, CONSENT_MESSAGE_VERSION - 1));

    // Any non-interactive stream suppresses the prompt.
    assert!(!consent_prompt_due(
        Unset, 0, false, true, false, false, false
    ));
    assert!(!consent_prompt_due(
        Unset, 0, true, false, false, false, false
    ));
    // CI and the kill switches suppress it.
    assert!(!consent_prompt_due(
        Unset, 0, true, true, true, false, false
    ));
    assert!(!consent_prompt_due(
        Unset, 0, true, true, false, true, false
    ));
    assert!(!consent_prompt_due(
        Unset, 0, true, true, false, false, true
    ));
}

/// The CLI prompt, the TUI pane, and the web card all resolve "should I ask?"
/// through [`consent_due_now`] over one on-disk state: a decision recorded by
/// any surface (including the TUI pane's persist-on-render decline and the web
/// card's dismiss) stops every other surface from asking, and the TTY and
/// environment short-circuits hold for all of them.
#[test]
fn consent_ask_is_shared_across_surfaces_and_short_circuits() {
    let mut guard = env_guard();
    let dir = TempDir::new().expect("tempdir");
    let telemetry = Telemetry::at(dir.path());

    // Never asked, interactive, clean env: the ask is due.
    assert!(consent_due_now(&telemetry, true, true));
    // A non-TTY stream on either side suppresses it.
    assert!(!consent_due_now(&telemetry, false, true));
    assert!(!consent_due_now(&telemetry, true, false));
    // CI and the kill switches suppress it.
    for (name, value) in [
        ("CI", "true"),
        ("DO_NOT_TRACK", "1"),
        ("HUSK_TELEMETRY_DISABLED", "1"),
    ] {
        guard.set(name, value);
        assert!(!consent_due_now(&telemetry, true, true), "{name} must gate");
        guard.remove(name);
    }

    // One surface declines (the TUI pane persisting on render, or the web
    // card's dismiss): no surface ever asks again.
    telemetry.disable().expect("record decline");
    assert!(!consent_due_now(&telemetry, true, true));

    // An explicit yes is not due either, at the current message version.
    telemetry.enable().expect("record yes");
    assert!(!consent_due_now(&telemetry, true, true));
}

#[test]
fn only_an_explicit_yes_enables() {
    use TelemetryConsent::{Disabled, Enabled};
    for yes in ["y", "Y", "yes", "YES", "Yes", "  y  ", "yes\n"] {
        assert_eq!(consent_from_answer(yes), Enabled, "{yes:?}");
    }
    for no in ["", "\n", "n", "no", "sure", "ok", "true", "1", "y e s"] {
        assert_eq!(consent_from_answer(no), Disabled, "{no:?}");
    }
}

/// Accept exactly one HTTP request on `listener`, answer it with `status`,
/// and return its head and body.
async fn accept_one_request(
    listener: tokio::net::TcpListener,
    status: &'static str,
) -> (String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut socket, _) = listener.accept().await.expect("accept connection");
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    let request = loop {
        let read = socket.read(&mut chunk).await.expect("read request");
        raw.extend_from_slice(&chunk[..read]);
        if let Some(request) = split_request(&raw) {
            break request;
        }
        assert!(read > 0, "connection closed before request completed");
    };
    let response = format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    socket
        .write_all(response.as_bytes())
        .await
        .expect("write response");
    socket.shutdown().await.ok();
    request
}

/// Split a raw HTTP/1.1 request into head and body once it has fully
/// arrived (per its `content-length`); `None` while still incomplete.
fn split_request(raw: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(raw).ok()?;
    let (head, body) = text.split_once("\r\n\r\n")?;
    let content_length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    })?;
    if body.len() < content_length {
        return None;
    }
    Some((head.to_string(), body[..content_length].to_string()))
}
