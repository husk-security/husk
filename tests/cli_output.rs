//! The CLI output contract, end to end against the real binary:
//! `husk status` serves the FULL findings listing from the cache with zero
//! scanning, and piped output is plain text (no ANSI) and never truncated.

use chrono::Utc;
use std::process::Command;

mod common;
use common::{run_husk, seed_cache};

#[test]
fn status_pipes_the_full_plain_findings_listing_without_scanning() {
    let state = seed_cache(75, Utc::now());
    let out = run_husk(&state, &["status"]);
    assert!(out.status.success(), "husk status failed: {out:?}");

    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    for i in 0..75 {
        assert!(
            stdout.contains(&format!("Synthetic finding number {i}")),
            "finding {i} missing from piped status output"
        );
    }
    assert!(
        !stdout.contains("more findings"),
        "piped output must never truncate"
    );
    assert!(
        !stdout.contains('\x1b'),
        "piped output must be plain text (no ANSI escapes)"
    );
    // Greppable: one findings line per finding, stable shape.
    assert_eq!(
        stdout
            .lines()
            .filter(|l| l.contains("Synthetic finding number"))
            .count(),
        75
    );
}

#[test]
fn status_no_pager_flag_is_accepted() {
    let state = seed_cache(3, Utc::now());
    let out = run_husk(&state, &["status", "--no-pager"]);
    assert!(out.status.success(), "husk status --no-pager failed");
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Synthetic finding number 2"));
}

#[test]
fn status_json_is_the_raw_report() {
    let state = seed_cache(2, Utc::now());
    let out = run_husk(&state, &["status", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("status --json emits valid JSON");
    assert_eq!(parsed["findings"].as_array().map(Vec::len), Some(2));
}

#[test]
fn bare_husk_prints_help_and_exits_zero() {
    let state = seed_cache(1, Utc::now());
    let out = run_husk(&state, &[]);
    assert!(
        out.status.success(),
        "bare husk must exit 0, not run an action: {out:?}"
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    // The grouped top-level help, not a scan or a server.
    assert!(stdout.contains("Usage: husk"), "help usage line missing");
    assert!(stdout.contains("Scan & view:"), "grouped commands missing");
    assert!(
        !stdout.contains("Web UI ready") && !stdout.contains("Synthetic finding"),
        "bare husk must not scan or start the web UI"
    );
}

#[test]
fn scan_of_an_empty_dir_pipes_plain_coverage_line() {
    let state = tempfile::tempdir().expect("tempdir");
    let target = state.path().join("empty-project");
    std::fs::create_dir_all(&target).expect("create scan target");
    let out = Command::new(env!("CARGO_BIN_EXE_husk"))
        .args([
            "scan",
            "--offline",
            "--no-home-inventory",
            target.to_str().expect("utf8 path"),
        ])
        .env("HUSK_CACHE_DIR", state.path().join("cache"))
        .env("HUSK_HOME", state.path().join("home"))
        .output()
        .expect("run husk scan");
    assert!(out.status.success(), "husk scan failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Husk scan complete"));
    assert!(!stdout.contains('\x1b'), "piped scan output must be plain");
}

/// A scan whose stdio is piped never asks for telemetry consent and records
/// no decision: the one-time ask is strictly for interactive terminals, so
/// scripts, CI wrappers, and agents can never answer it by accident.
#[test]
fn a_piped_scan_never_asks_for_telemetry_consent() {
    let state = tempfile::tempdir().expect("tempdir");
    let target = state.path().join("empty-project");
    std::fs::create_dir_all(&target).expect("create scan target");
    let out = Command::new(env!("CARGO_BIN_EXE_husk"))
        .args([
            "scan",
            "--offline",
            "--no-home-inventory",
            target.to_str().expect("utf8 path"),
        ])
        .env("HUSK_CACHE_DIR", state.path().join("cache"))
        .env("HUSK_HOME", state.path().join("home"))
        .output()
        .expect("run husk scan");
    assert!(out.status.success(), "husk scan failed: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Share anonymous usage data"),
        "piped scan must not prompt: {stderr}"
    );
    let config = husk::cloud::HuskCloudConfig::load_from(&state.path().join("home"))
        .expect("readable config state");
    assert!(
        config.telemetry.is_unset(),
        "no consent decision may be recorded without an interactive answer"
    );
}
