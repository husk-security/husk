//! CLI-level tests for the opt-in cloud subcommands, exercising the compiled
//! binary end to end without any network access: every invocation runs
//! against a temporary `HOME` (so no real `~/.husk` state is read or
//! written) and an unroutable backend URL, and asserts only on paths that
//! return before any request would be sent. Argument-parsing coverage lives
//! in the unit tests inside `src/cli.rs`.

use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

/// Run the husk binary with isolated state: `HOME` points at a temporary
/// directory, the backend URL points at a closed local port, and every
/// cloud-related environment override is cleared.
fn husk_command(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_husk"));
    command
        .args(args)
        .env("HOME", home)
        .env("HUSK_HOME", home.join(".husk"))
        .env("HUSK_CACHE_DIR", home.join("cache"))
        .env("HUSK_BACKEND_URL", "http://127.0.0.1:9")
        .env_remove("HUSK_TOKEN")
        .env_remove("HUSK_OIDC_ISSUER")
        .env_remove("HUSK_OIDC_CLIENT_ID")
        .env_remove("HUSK_LOGIN_DEVICE")
        .env_remove("HUSK_INTEL_ROOT_KEY")
        .env_remove("DO_NOT_TRACK")
        .env_remove("HUSK_TELEMETRY_DISABLED")
        .env_remove("HUSK_TELEMETRY")
        .env_remove("CI");
    command
}

fn run_husk(home: &Path, args: &[&str]) -> Output {
    husk_command(home, args).output().expect("run husk binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn login_reports_coming_soon_without_starting_auth() {
    let home = TempDir::new().expect("temp home");
    let output = run_husk(home.path(), &["login"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "Account sign-in is coming soon.");
    assert!(stderr(&output).is_empty());
    assert!(!home.path().join(".husk/credentials.json").exists());
}

#[test]
fn login_stays_network_silent_when_telemetry_is_enabled() {
    let home = TempDir::new().expect("temp home");
    let husk_home = home.path().join(".husk");
    std::fs::create_dir_all(&husk_home).expect("create husk home");
    std::fs::write(husk_home.join("config.json"), r#"{"telemetry":"enabled"}"#)
        .expect("enable telemetry");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
    listener.set_nonblocking(true).expect("nonblocking probe");

    let output = husk_command(home.path(), &["login"])
        .env(
            "HUSK_BACKEND_URL",
            format!("http://{}", listener.local_addr().unwrap()),
        )
        .output()
        .expect("run husk login");

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "Account sign-in is coming soon.");
    let accept = listener.accept();
    assert!(
        accept.is_err_and(|err| err.kind() == std::io::ErrorKind::WouldBlock),
        "login must not connect to the backend"
    );
    let current = std::fs::read_to_string(husk_home.join("telemetry/current.json"))
        .expect("current day counters");
    let current: serde_json::Value = serde_json::from_str(&current).expect("parse current day");
    assert_eq!(
        current["counters"]["cli.run.login"], 1,
        "the anonymous command counter should accumulate locally for a later day"
    );
}

#[test]
fn logout_explains_that_an_environment_token_remains_active() {
    let home = TempDir::new().expect("temp home");
    let output = husk_command(home.path(), &["logout"])
        .env("HUSK_TOKEN", "test-token")
        .output()
        .expect("run husk logout");

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let printed = stdout(&output);
    assert!(printed.contains("No stored credentials."), "{printed}");
    assert!(printed.contains("HUSK_TOKEN is active"), "{printed}");
    assert!(printed.contains("unset it"), "{printed}");
    assert!(!printed.contains("test-token"), "must not print the token");
}

#[test]
fn logout_deletes_stored_credentials_but_preserves_environment_session() {
    let home = TempDir::new().expect("temp home");
    let credentials = home.path().join(".husk/credentials.json");
    std::fs::create_dir_all(credentials.parent().expect("credentials parent"))
        .expect("create husk home");
    std::fs::write(&credentials, "invalid but removable").expect("write credentials");

    let output = husk_command(home.path(), &["logout"])
        .env("HUSK_TOKEN", "test-token")
        .output()
        .expect("run husk logout");

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let printed = stdout(&output);
    assert!(printed.contains("Stored credentials deleted."), "{printed}");
    assert!(printed.contains("HUSK_TOKEN is still active"), "{printed}");
    assert!(!credentials.exists());
}

#[cfg(unix)]
#[test]
fn logout_unlinks_rejected_credential_symlink_without_touching_target() {
    let home = TempDir::new().expect("temp home");
    let husk_home = home.path().join(".husk");
    std::fs::create_dir_all(&husk_home).expect("create husk home");
    let target = home.path().join("credential-target");
    std::fs::write(&target, "keep me").expect("write target");
    let credentials = husk_home.join("credentials.json");
    std::os::unix::fs::symlink(&target, &credentials).expect("create credential symlink");

    let output = run_husk(home.path(), &["logout"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("Stored credentials deleted."));
    assert!(std::fs::symlink_metadata(&credentials).is_err());
    assert_eq!(std::fs::read_to_string(target).unwrap(), "keep me");
}

#[test]
fn telemetry_status_is_off_by_default() {
    let home = TempDir::new().expect("temp home");
    let output = run_husk(home.path(), &["telemetry", "status"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let printed = stdout(&output);
    assert!(
        printed.contains("telemetry: off (default)"),
        "unexpected status output: {printed}"
    );
    assert!(
        printed.contains("Nothing is ever recorded or sent"),
        "status must state the default-off promise: {printed}"
    );
    // The harness sets HUSK_BACKEND_URL, so status must surface both the
    // resolved reports endpoint and where the override came from.
    assert!(
        printed.contains("endpoint: http://127.0.0.1:9/api/v1/telemetry/reports"),
        "status must show the effective telemetry endpoint: {printed}"
    );
    assert!(
        printed.contains("(from HUSK_BACKEND_URL)"),
        "status must name the backend URL override source: {printed}"
    );
}

#[test]
fn telemetry_status_payload_reports_the_empty_state() {
    let home = TempDir::new().expect("temp home");
    let output = run_husk(home.path(), &["telemetry", "status", "--payload"]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let printed = stdout(&output);
    assert!(
        printed.contains("No counters recorded yet today."),
        "nothing may be accumulated before opt-in: {printed}"
    );
    assert!(
        printed.contains("No pending reports."),
        "nothing may be pending before opt-in: {printed}"
    );
}

#[test]
fn telemetry_reset_id_no_longer_exists() {
    let home = TempDir::new().expect("temp home");
    let output = run_husk(home.path(), &["telemetry", "reset-id"]);

    assert!(!output.status.success(), "v2 has no install id to rotate");
    assert!(
        stderr(&output).contains("unrecognized subcommand"),
        "unexpected stderr: {}",
        stderr(&output)
    );
}

#[test]
fn alerts_without_login_is_a_friendly_error() {
    let home = TempDir::new().expect("temp home");
    let output = run_husk(home.path(), &["alerts"]);

    assert!(!output.status.success(), "alerts must fail when logged out");
    let printed = stderr(&output);
    assert!(
        printed.contains("not logged in"),
        "unexpected stderr: {printed}"
    );
    assert!(
        printed.contains("sign-in is coming soon"),
        "the error must explain sign-in availability: {printed}"
    );
}

#[test]
fn sync_without_login_is_a_friendly_error() {
    let home = TempDir::new().expect("temp home");
    let output = run_husk(home.path(), &["sync"]);

    assert!(!output.status.success(), "sync must fail when logged out");
    let printed = stderr(&output);
    assert!(
        printed.contains("not logged in"),
        "unexpected stderr: {printed}"
    );
    assert!(
        printed.contains("sign-in is coming soon"),
        "unexpected stderr: {printed}"
    );
}

#[test]
fn account_without_login_reports_logged_out_state() {
    let home = TempDir::new().expect("temp home");
    let output = run_husk(home.path(), &["account"]);

    assert!(
        output.status.success(),
        "account is informational and must succeed when logged out; stderr: {}",
        stderr(&output)
    );
    let printed = stdout(&output);
    assert!(
        printed.contains("not logged in"),
        "unexpected account output: {printed}"
    );
    assert!(
        printed.contains("sign-in is coming soon"),
        "unexpected account output: {printed}"
    );
    assert!(
        printed.contains("telemetry: off (default)"),
        "account must show the telemetry default: {printed}"
    );
    assert!(
        printed.contains("http://127.0.0.1:9"),
        "account must show the effective backend URL: {printed}"
    );
}

#[test]
fn feedback_rejects_an_empty_message_before_any_request() {
    let home = TempDir::new().expect("temp home");
    let output = run_husk(home.path(), &["feedback", "   "]);

    assert!(!output.status.success(), "empty feedback must fail");
    assert!(
        stderr(&output).contains("feedback message is empty"),
        "unexpected error: {}",
        stderr(&output)
    );
}

#[test]
fn feedback_reports_an_unreachable_backend() {
    let home = TempDir::new().expect("temp home");
    let output = run_husk(
        home.path(),
        &["feedback", "--contact", "dev@example.com", "great scanner"],
    );

    assert!(
        !output.status.success(),
        "send must fail against a closed port"
    );
    assert!(
        stderr(&output).contains("could not reach the Husk backend"),
        "unexpected error: {}",
        stderr(&output)
    );
}

#[test]
fn feedback_reads_the_message_from_stdin_when_no_argument_is_given() {
    use std::io::Write;
    let home = TempDir::new().expect("temp home");
    let mut child = husk_command(home.path(), &["feedback"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn husk feedback");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(b"typed into a pipe\n")
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait for husk feedback");

    // The piped message passes validation (so the run proceeds to the send),
    // and the closed-port backend is what fails; stdin was therefore read.
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("could not reach the Husk backend"),
        "unexpected error: {}",
        stderr(&output)
    );
}
