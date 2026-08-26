//! Opt-in cloud features.
//!
//! The husk scanner is complete without a backend: everything under this
//! module is an optional addition that the user explicitly enables by
//! logging in, turning on telemetry, or running a sync command. Network
//! paths use short timeouts and degrade silently to offline behavior.
//!
//! Durable cloud state lives in `~/.husk/`: `config.json` (backend URL
//! override, telemetry consent) and `credentials.json` (device-flow tokens,
//! written with owner-only permissions). Re-fetchable data belongs in the
//! XDG cache directory instead.

pub mod auth;
pub mod feedback;
pub mod sync;
pub mod telemetry;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Backend used when neither `HUSK_BACKEND_URL` nor the config file
/// overrides it.
pub const DEFAULT_BACKEND_URL: &str = "https://husk-security.dev";

/// Environment variable that overrides every other backend URL source.
pub const BACKEND_URL_ENV: &str = "HUSK_BACKEND_URL";

/// New account sessions stay disabled until the hosted sign-in flow is ready.
pub const LOGIN_AVAILABLE: bool = false;

const CONFIG_FILE: &str = "config.json";
const CREDENTIALS_FILE: &str = "credentials.json";
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether the user has decided about anonymous telemetry.
///
/// `Unset` (the default, and what a missing config field deserializes to)
/// means the user was never asked; it behaves as off, but is what makes the
/// one-time consent prompt eligible to run. Nothing is ever recorded or sent
/// without an explicit `Enabled`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TelemetryConsent {
    #[default]
    Unset,
    Disabled,
    Enabled,
}

impl TelemetryConsent {
    pub fn is_enabled(self) -> bool {
        self == Self::Enabled
    }

    pub fn is_unset(&self) -> bool {
        *self == Self::Unset
    }
}

/// Persistent cloud configuration stored at `~/.husk/config.json`.
///
/// Unknown fields are tolerated on load so older binaries keep working
/// after newer ones extend the file.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct HuskCloudConfig {
    /// Backend base URL override. `None` means the built-in default.
    pub backend_url: Option<String>,
    /// Telemetry consent. Unset (and off) by default; only an explicit user
    /// decision sets it. Skipped while unset so older binaries, which know
    /// only `enabled`/`disabled`, can still parse the file.
    #[serde(skip_serializing_if = "TelemetryConsent::is_unset")]
    pub telemetry: TelemetryConsent,
}

impl HuskCloudConfig {
    /// Load the config from `~/.husk/config.json`. A missing file is not an
    /// error: it yields the all-offline default.
    pub fn load() -> Result<Self> {
        Self::load_from(&crate::paths::husk_home()?)
    }

    /// Load the config from `<dir>/config.json`.
    pub fn load_from(dir: &Path) -> Result<Self> {
        let path = dir.join(CONFIG_FILE);
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&contents).with_context(|| format!("parse {}", path.display()))
    }

    /// Persist the config to `<dir>/config.json` as pretty JSON.
    pub fn store_in(&self, dir: &Path) -> Result<PathBuf> {
        crate::paths::ensure_dir_private(dir)?;
        let path = dir.join(CONFIG_FILE);
        crate::paths::write_atomic(&path, &serde_json::to_vec_pretty(self)?)?;
        Ok(path)
    }
}

/// Stored credentials at `~/.husk/credentials.json` (0600).
///
/// Normally an OIDC access+refresh pair rotated near expiry. An empty
/// `refresh_token` means the token cannot be renewed: it is used as-is until
/// it expires, after which the machine is simply logged out. Unknown fields
/// are ignored on load.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Credentials {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

impl Credentials {
    pub fn load() -> Result<Option<Self>> {
        Self::load_from(&crate::paths::husk_home()?)
    }

    /// Load credentials from `<dir>/credentials.json`, if present.
    ///
    /// The file holds long-lived tokens, so it is validated before it is
    /// trusted: a missing file is not an error, but the path must be a regular
    /// file (never a symlink) and, on Unix, must not be readable or writable by
    /// group or other. This blocks a same-UID attacker from swapping in a
    /// symlink or loosening permissions to capture or forge tokens.
    pub fn load_from(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(CREDENTIALS_FILE);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
        };
        if !metadata.file_type().is_file() {
            anyhow::bail!(
                "{} is not a regular file; refusing to read credentials. \
                 Remove it with `husk logout`; account sign-in is coming soon.",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "{} is accessible by group or other (mode {:o}); \
                     refusing to read credentials. Remove it with `husk logout`; \
                     account sign-in is coming soon.",
                    path.display(),
                    mode & 0o7777
                );
            }
        }
        let contents =
            fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let credentials =
            serde_json::from_str(&contents).with_context(|| format!("parse {}", path.display()))?;
        Ok(Some(credentials))
    }

    /// Persist credentials to `<dir>/credentials.json` with owner-only file
    /// permissions.
    pub fn store_in(&self, dir: &Path) -> Result<PathBuf> {
        crate::paths::ensure_dir_private(dir)?;
        let path = dir.join(CREDENTIALS_FILE);
        crate::paths::write_private(&path, &serde_json::to_vec_pretty(self)?)?;
        Ok(path)
    }

    /// Whether any filesystem entry occupies the credentials path. This does
    /// not trust or follow the entry, so logout can remove an invalid file or
    /// symlink that credential loading correctly rejects.
    pub fn exists_in(dir: &Path) -> Result<bool> {
        let path = dir.join(CREDENTIALS_FILE);
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
        }
    }

    /// Delete `<dir>/credentials.json` if present. Deleting credentials that
    /// do not exist is not an error.
    pub fn delete_in(dir: &Path) -> Result<()> {
        let path = dir.join(CREDENTIALS_FILE);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("delete {}", path.display())),
        }
    }

    /// True when the access token expires within `window` (or has already
    /// expired).
    pub fn expires_within(&self, window: chrono::Duration) -> bool {
        self.expires_at - window <= Utc::now()
    }
}

/// Resolve the backend base URL: `HUSK_BACKEND_URL` beats the config file,
/// which beats [`DEFAULT_BACKEND_URL`]. Trailing slashes are trimmed.
pub fn effective_backend_url(config: &HuskCloudConfig) -> String {
    resolve_backend_url(std::env::var(BACKEND_URL_ENV).ok().as_deref(), config)
}

/// Pure resolution logic behind [`effective_backend_url`]: `env_override`
/// (when non-blank) beats the config value, which beats the default.
pub fn resolve_backend_url(env_override: Option<&str>, config: &HuskCloudConfig) -> String {
    let candidate = non_blank(env_override)
        .or_else(|| non_blank(config.backend_url.as_deref()))
        .unwrap_or_else(|| DEFAULT_BACKEND_URL.to_string());
    candidate.trim_end_matches('/').to_string()
}

/// Join an API path onto a backend base URL.
pub fn api_url(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

/// HTTP client for all cloud calls: 5 second timeout so offline machines
/// never hang, and a `husk/<version>` user agent.
pub fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(concat!("husk/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build cloud HTTP client")
}

fn non_blank(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// True when the environment variable is set to a truthy value:
/// `1`/`true`/`yes`/`on`, case-insensitive, trimmed. Shared by every cloud
/// module so switches (and especially the telemetry kill switches, which
/// should err toward triggering) all accept the same spellings.
pub(crate) fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            let value = value.trim().to_ascii_lowercase();
            matches!(value.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

/// Deserialize JSON `null` as the type's default, for backend fields that
/// are nullable server-side but conceptually "empty" here.
pub(crate) fn null_to_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Serializes the env-mutating unit tests in this crate's test binary so no
    /// two threads call `setenv`/`getenv` concurrently (a data race even for
    /// distinct variable names). The integration tests use
    /// `tests/common::EnvVarGuard`, but that module is not visible here, so this
    /// binary keeps its own lock.
    fn env_lock() -> MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn sample_credentials() -> Credentials {
        Credentials {
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: Utc::now(),
        }
    }

    #[test]
    fn env_truthy_recognizes_common_affirmatives() {
        const VAR: &str = "HUSK_TEST_ENV_TRUTHY";
        // Held across both loops and the final cleanup so no other env-mutating
        // test in this binary can race on the process environment.
        let _lock = env_lock();
        for value in ["1", "true", "TRUE", "yes", "On", "  on  "] {
            // SAFETY: _lock serializes all env access in this test binary, so no
            // other thread reads or writes the environment concurrently.
            unsafe { std::env::set_var(VAR, value) };
            assert!(env_truthy(VAR), "{value:?} should be truthy");
        }
        for value in ["0", "false", "no", ""] {
            // SAFETY: see above; the env lock is held for the whole test.
            unsafe { std::env::set_var(VAR, value) };
            assert!(!env_truthy(VAR), "{value:?} should be falsy");
        }
        // SAFETY: see above; the env lock is held through cleanup.
        unsafe { std::env::remove_var(VAR) };
        assert!(!env_truthy(VAR), "unset should be falsy");
    }

    #[test]
    fn load_missing_credentials_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(Credentials::load_from(dir.path()).expect("load"), None);
    }

    #[test]
    fn round_trips_owner_only_credentials() {
        let dir = tempfile::tempdir().expect("tempdir");
        let creds = sample_credentials();
        creds.store_in(dir.path()).expect("store");
        let loaded = Credentials::load_from(dir.path())
            .expect("load")
            .expect("present");
        assert_eq!(loaded, creds);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_other_readable_credentials() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        sample_credentials().store_in(dir.path()).expect("store");
        let path = dir.path().join(CREDENTIALS_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen perms");
        let err = Credentials::load_from(dir.path()).expect_err("should reject loose perms");
        assert!(err.to_string().contains("group or other"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_credentials() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real-credentials.json");
        crate::paths::write_private(
            &target,
            &serde_json::to_vec_pretty(&sample_credentials()).unwrap(),
        )
        .expect("write target");
        let link = dir.path().join(CREDENTIALS_FILE);
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let err = Credentials::load_from(dir.path()).expect_err("should reject symlink");
        assert!(err.to_string().contains("not a regular file"));
    }
}
