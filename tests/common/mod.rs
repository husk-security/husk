//! Shared helpers for the integration-test binaries.
//!
//! Each test binary compiles this module independently (`mod common;`), so not
//! every binary uses every helper.
#![allow(dead_code)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Process-wide lock serializing every test that mutates or reads environment
/// variables. Each integration-test binary compiles `common` independently, so
/// this is one lock per binary, which is exactly right, since each test binary
/// is its own process and cannot race another.
static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// RAII guard that serializes process-environment mutation across parallel test
/// threads and restores every variable it touched to its prior value on drop,
/// including if the test panics mid-way. Hold it for the whole span of any test
/// that reads or writes environment variables.
///
/// ```ignore
/// let mut env = common::EnvVarGuard::acquire();
/// env.set("HUSK_TOKEN", "…");   // remembers + restores the previous value
/// env.remove("HUSK_BACKEND_URL");
/// // … assertions …
/// // guard drops here: prior values are restored, lock released.
/// ```
pub struct EnvVarGuard {
    _lock: MutexGuard<'static, ()>,
    saved: Vec<(String, Option<OsString>)>,
}

impl EnvVarGuard {
    /// Acquire the process-wide environment lock. A poisoned lock is recovered
    /// (a prior panic already restored its own vars on drop), so tests never
    /// wedge on each other.
    pub fn acquire() -> Self {
        let lock = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self {
            _lock: lock,
            saved: Vec::new(),
        }
    }

    /// Set `name=value`, remembering the prior value for restoration on drop.
    pub fn set(&mut self, name: &str, value: impl AsRef<std::ffi::OsStr>) {
        self.remember(name);
        // SAFETY: this guard holds ENV_LOCK for its whole lifetime, so no other
        // test thread reads or writes the process environment concurrently.
        unsafe { std::env::set_var(name, value) };
    }

    /// Remove `name`, remembering the prior value for restoration on drop.
    pub fn remove(&mut self, name: &str) {
        self.remember(name);
        // SAFETY: see `set`.
        unsafe { std::env::remove_var(name) };
    }

    fn remember(&mut self, name: &str) {
        if !self.saved.iter().any(|(existing, _)| existing == name) {
            self.saved.push((name.to_string(), std::env::var_os(name)));
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // `remember` captures each variable exactly once (on first touch), so
        // every name here is unique and is simply restored to that one prior
        // value; iteration order does not matter.
        for (name, value) in self.saved.drain(..) {
            // SAFETY: still holding ENV_LOCK here, so restoration cannot race.
            unsafe {
                match value {
                    Some(previous) => std::env::set_var(&name, previous),
                    None => std::env::remove_var(&name),
                }
            }
        }
    }
}

/// The crate root, resolved at run time. `CARGO_MANIFEST_DIR` is baked in at
/// compile time and is not part of Cargo's fingerprint, so a `CARGO_TARGET_DIR`
/// shared across sibling worktrees serves a binary carrying another worktree's
/// path, which may since have moved or been deleted. Cargo runs test binaries
/// with the package root as the working directory, and no test changes it.
pub fn crate_root() -> PathBuf {
    std::env::current_dir().expect("test working directory is the crate root")
}

/// The intentionally-unsafe fixture corpus checked into `tst/`.
pub fn fixture_root() -> PathBuf {
    crate_root().join("tst")
}

/// Write a synthetic cached report (the same envelope `husk scan` saves) with
/// `findings` medium-severity findings into a fresh state dir; the returned
/// tempdir holds `cache/` and `home/` for [`run_husk`].
pub fn seed_cache(
    findings: usize,
    generated_at: chrono::DateTime<chrono::Utc>,
) -> tempfile::TempDir {
    use husk::model::{Finding, ScanReport, Severity};

    let state = tempfile::tempdir().expect("tempdir");
    let mut report = ScanReport::empty(vec![PathBuf::from("/tmp/husk-test-project")]);
    for i in 0..findings {
        report.findings.push(Finding::new(
            format!("finding-{i}"),
            format!("Synthetic finding number {i}"),
            Severity::Medium,
            husk::rule::Category::Secret,
            "test",
            Some(PathBuf::from(format!("/tmp/husk-test-project/file{i}.env"))),
            Some(1),
            format!("synthetic summary {i}"),
            None,
            "rotate it",
        ));
    }
    report.refresh_stats();
    report.generated_at = generated_at;

    let envelope = serde_json::json!({
        "version": format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        "saved_at": chrono::Utc::now(),
        "report": report,
    });
    let cache = state.path().join("cache");
    std::fs::create_dir_all(&cache).expect("create cache dir");
    std::fs::write(
        cache.join(husk::cache::report_name(&report)),
        serde_json::to_vec_pretty(&envelope).expect("serialize envelope"),
    )
    .expect("write cached report");
    state
}

/// Run `husk <args>` against a [`seed_cache`] state with stdout piped (never a
/// terminal), a hostile `PAGER` (must be irrelevant off-terminal), and all
/// durable state confined to the tempdir.
pub fn run_husk(state: &tempfile::TempDir, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_husk"))
        .args(args)
        .env("HUSK_CACHE_DIR", state.path().join("cache"))
        .env("HUSK_HOME", state.path().join("home"))
        .env("PAGER", "/definitely/not/a/pager")
        .output()
        .expect("run husk")
}

/// Make this test binary hermetic: point durable state (`HUSK_HOME`) and the
/// scan cache (`HUSK_CACHE_DIR`) at a fresh per-process directory under the
/// cargo target dir, so `cargo test` can never read from (or write test
/// fingerprints into) the developer's real `~/.husk` / `~/.cache/husk`.
///
/// The overrides are honored on every OS (unlike `XDG_CACHE_HOME`, which
/// macOS ignores) and are inherited by any `husk` subprocess a test spawns.
/// Environment variables are process state, so the isolation is necessarily
/// process-wide: every test that scans or touches state must call `isolate()`
/// FIRST, which makes the one-time `set_var` happen-before any parallel test
/// thread reads the environment.
pub fn isolate() {
    static ISOLATED: OnceLock<()> = OnceLock::new();
    ISOLATED.get_or_init(|| {
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("husk-isolated-{}", std::process::id()));
        // Start clean: stale state from a previous run (pid reuse) must not
        // feed this one; a poisoned cache is exactly what we're isolating from.
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create isolation dir");
        // SAFETY: runs exactly once inside this OnceLock initializer, which
        // happens-before any parallel test thread reads the environment.
        unsafe { std::env::set_var("HUSK_HOME", base.join("home")) };
        // SAFETY: runs exactly once inside this OnceLock initializer, which
        // happens-before any parallel test thread reads the environment.
        unsafe { std::env::set_var("HUSK_CACHE_DIR", base.join("cache")) };
    });
}
