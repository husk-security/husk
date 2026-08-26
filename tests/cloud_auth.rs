//! Pure-logic tests for the cloud config, credential storage, and device
//! flow helpers. No network access: everything operates on temporary
//! directories and in-process values.

use chrono::{Duration, Utc};
use husk::cloud;
use husk::cloud::auth::{TOKEN_ENV, env_token, format_user_code};
use husk::cloud::{
    BACKEND_URL_ENV, Credentials, DEFAULT_BACKEND_URL, HuskCloudConfig, TelemetryConsent, api_url,
    resolve_backend_url,
};
use std::fs;
use tempfile::TempDir;

mod common;

fn sample_credentials() -> Credentials {
    Credentials {
        access_token: "husk_at_test_access".to_string(),
        refresh_token: "husk_rt_test_refresh".to_string(),
        expires_at: Utc::now() + Duration::hours(1),
    }
}

#[cfg(unix)]
fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).expect("metadata").permissions().mode() & 0o777
}

#[test]
fn config_round_trips_as_pretty_json() {
    let temp = TempDir::new().expect("temp dir");
    let state_dir = temp.path().join("home").join(".husk");

    let config = HuskCloudConfig {
        backend_url: Some("http://localhost:8787".to_string()),
        telemetry: TelemetryConsent::Enabled,
    };
    let path = config.store_in(&state_dir).expect("store config");
    assert!(path.ends_with("config.json"));

    let loaded = HuskCloudConfig::load_from(&state_dir).expect("load config");
    assert_eq!(loaded, config);

    let raw = fs::read_to_string(&path).expect("read config");
    assert!(raw.lines().count() > 1, "config should be pretty-printed");
    assert!(raw.contains("\"backend_url\""));
    assert!(raw.contains("\"telemetry\""));
}

#[test]
fn missing_config_defaults_to_offline() {
    let temp = TempDir::new().expect("temp dir");
    let loaded = HuskCloudConfig::load_from(temp.path()).expect("load default config");
    assert_eq!(loaded, HuskCloudConfig::default());
    assert!(loaded.backend_url.is_none());
    assert!(!loaded.telemetry.is_enabled());
}

#[test]
fn config_tolerates_unknown_and_missing_fields() {
    let temp = TempDir::new().expect("temp dir");
    fs::write(
        temp.path().join("config.json"),
        r#"{"backend_url":"https://api.example.test","future_field":true}"#,
    )
    .expect("write config");

    let loaded = HuskCloudConfig::load_from(temp.path()).expect("load config");
    assert_eq!(
        loaded.backend_url.as_deref(),
        Some("https://api.example.test")
    );
    // A missing telemetry field means the user was never asked: Unset, off.
    assert_eq!(loaded.telemetry, TelemetryConsent::Unset);
    assert!(!loaded.telemetry.is_enabled());
}

#[cfg(unix)]
#[test]
fn state_dir_is_created_owner_only() {
    let temp = TempDir::new().expect("temp dir");
    let state_dir = temp.path().join(".husk");
    HuskCloudConfig::default()
        .store_in(&state_dir)
        .expect("store config");
    assert_eq!(mode_of(&state_dir), 0o700);
}

#[test]
fn backend_url_precedence_is_env_then_config_then_default() {
    let mut config = HuskCloudConfig::default();
    assert_eq!(resolve_backend_url(None, &config), DEFAULT_BACKEND_URL);

    config.backend_url = Some("http://localhost:8787/".to_string());
    assert_eq!(
        resolve_backend_url(None, &config),
        "http://localhost:8787",
        "config overrides default and trailing slashes are trimmed"
    );

    assert_eq!(
        resolve_backend_url(Some("http://127.0.0.1:9999"), &config),
        "http://127.0.0.1:9999",
        "env beats config"
    );
    assert_eq!(
        resolve_backend_url(Some("   "), &config),
        "http://localhost:8787",
        "blank env values are ignored"
    );

    config.backend_url = Some("  ".to_string());
    assert_eq!(
        resolve_backend_url(None, &config),
        DEFAULT_BACKEND_URL,
        "blank config values are ignored"
    );
}

/// Assertions that read the process environment. The shared [`EnvVarGuard`]
/// serializes against every other env-mutating test in this binary and restores
/// `HUSK_BACKEND_URL`/`HUSK_TOKEN` on drop, even if an assertion below panics.
#[test]
fn environment_overrides_are_honored() {
    let config = HuskCloudConfig {
        backend_url: Some("https://config.example.test".to_string()),
        telemetry: TelemetryConsent::Disabled,
    };

    let mut env = common::EnvVarGuard::acquire();

    env.set(BACKEND_URL_ENV, "http://localhost:8787");
    assert_eq!(
        cloud::effective_backend_url(&config),
        "http://localhost:8787"
    );
    env.remove(BACKEND_URL_ENV);
    assert_eq!(
        cloud::effective_backend_url(&config),
        "https://config.example.test"
    );

    env.set(TOKEN_ENV, "husk_pat_from_env");
    assert_eq!(env_token().as_deref(), Some("husk_pat_from_env"));
    env.set(TOKEN_ENV, "   ");
    assert_eq!(env_token(), None, "blank HUSK_TOKEN is ignored");
    env.remove(TOKEN_ENV);
    assert_eq!(env_token(), None);
}

#[test]
fn credentials_store_load_delete_round_trip() {
    let temp = TempDir::new().expect("temp dir");
    let state_dir = temp.path().join(".husk");

    assert!(
        Credentials::load_from(&state_dir)
            .expect("load missing credentials")
            .is_none()
    );

    let credentials = sample_credentials();
    let path = credentials.store_in(&state_dir).expect("store credentials");
    assert!(path.ends_with("credentials.json"));

    let loaded = Credentials::load_from(&state_dir)
        .expect("load credentials")
        .expect("credentials present");
    assert_eq!(loaded, credentials);

    Credentials::delete_in(&state_dir).expect("delete credentials");
    assert!(
        Credentials::load_from(&state_dir)
            .expect("load after delete")
            .is_none()
    );
    Credentials::delete_in(&state_dir).expect("delete is idempotent");
}

#[test]
fn legacy_credentials_with_retired_kind_field_still_load() {
    // credentials.json files written by older binaries carried a `kind`
    // marker ("device"/"static") and may lack a refresh token. Both must keep
    // loading: unknown fields are ignored, and a missing/empty refresh token
    // simply means the bearer is used as-is until it expires.
    let temp = TempDir::new().expect("temp dir");
    let path = temp.path().join("credentials.json");
    fs::write(
        &path,
        r#"{"access_token":"husk_at_old","expires_at":"2099-01-01T00:00:00Z","kind":"static"}"#,
    )
    .expect("write legacy credentials");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("perms");
    }
    let loaded = Credentials::load_from(temp.path())
        .expect("load legacy")
        .expect("present");
    assert_eq!(loaded.access_token, "husk_at_old");
    assert!(loaded.refresh_token.is_empty(), "no refresh token recorded");
}

#[cfg(unix)]
#[test]
fn credentials_file_is_owner_only() {
    let temp = TempDir::new().expect("temp dir");
    let state_dir = temp.path().join(".husk");

    let path = sample_credentials()
        .store_in(&state_dir)
        .expect("store credentials");
    assert_eq!(mode_of(&path), 0o600);

    // Overwriting keeps the restrictive mode.
    let path = sample_credentials()
        .store_in(&state_dir)
        .expect("overwrite credentials");
    assert_eq!(mode_of(&path), 0o600);
}

#[test]
fn credential_expiry_window_detects_imminent_expiry() {
    let mut credentials = sample_credentials();
    assert!(!credentials.expires_within(Duration::minutes(5)));

    credentials.expires_at = Utc::now() + Duration::minutes(2);
    assert!(credentials.expires_within(Duration::minutes(5)));

    credentials.expires_at = Utc::now() - Duration::minutes(2);
    assert!(
        credentials.expires_within(Duration::minutes(5)),
        "already-expired tokens are inside every window"
    );
}

#[test]
fn user_code_displays_as_grouped_uppercase() {
    assert_eq!(format_user_code("BCDF-GHJK"), "BCDF-GHJK");
    assert_eq!(format_user_code("bcdfghjk"), "BCDF-GHJK");
    assert_eq!(format_user_code(" bcdf ghjk "), "BCDF-GHJK");
    assert_eq!(format_user_code("bcd-fgh-jk"), "BCDF-GHJK");
    assert_eq!(
        format_user_code("short"),
        "short",
        "codes that are not eight characters pass through trimmed"
    );
}

#[test]
fn api_url_joins_base_and_path() {
    assert_eq!(
        api_url("http://localhost:8787/", "/api/v1/account"),
        "http://localhost:8787/api/v1/account"
    );
    assert_eq!(
        api_url("https://husk-security.dev", "/api/v1/account/machines"),
        "https://husk-security.dev/api/v1/account/machines"
    );
}
