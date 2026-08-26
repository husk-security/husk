//! The stale-scan warning, end to end: commands serving a cached report older
//! than 24h flag it on stderr, while stdout stays greppable and a fresh
//! report stays silent.

use chrono::{Duration, Utc};

mod common;
use common::{run_husk, seed_cache};

#[test]
fn stale_cached_report_warns_on_stderr_and_keeps_stdout_greppable() {
    let state = seed_cache(1, Utc::now() - Duration::days(3));
    let out = run_husk(&state, &["status"]);
    assert!(out.status.success());

    let stderr = String::from_utf8(out.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("last scan: 3 days ago"),
        "expected stale-scan warning on stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("husk scan"),
        "warning names the refresh command"
    );

    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert!(
        !stdout.contains("last scan:"),
        "the stale warning must not pollute greppable stdout"
    );
}

#[test]
fn fresh_cached_report_does_not_warn() {
    let state = seed_cache(1, Utc::now());
    let out = run_husk(&state, &["status"]);
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("utf8 stderr");
    assert!(
        !stderr.contains("last scan:"),
        "no stale warning for a fresh report: {stderr}"
    );
}

#[test]
fn status_json_never_carries_the_warning_in_stdout() {
    let state = seed_cache(1, Utc::now() - Duration::days(5));
    let out = run_husk(&state, &["status", "--json"]);
    assert!(out.status.success());
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must stay pure JSON");
    assert!(parsed["findings"].is_array());
}
