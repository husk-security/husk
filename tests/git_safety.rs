//! Husk must be strictly READ-ONLY toward a scanned repository's git state.
//!
//! A security scanner that rewrites `.git/config` (e.g. flipping `core.bare` to
//! true) on scan is a launch-killer. These tests scan a real git repo, one that
//! uses a **linked worktree** (worktrees share a single `.git/config`), and
//! assert the config is byte-for-byte unchanged, including under a **hostile
//! inherited `GIT_DIR`** (the environment a git hook or agent/MCP harness leaks),
//! which must never redirect husk onto (or mutate) another repository.

use std::fs;
use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        // Clear inherited repo-redirection env so setup always acts on `dir`
        // (a git hook run in a linked worktree exports an absolute GIT_DIR).
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

fn init_repo(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    git(dir, &["init", "-q"]);
    git(dir, &["config", "user.email", "t@example.com"]);
    git(dir, &["config", "user.name", "Test"]);
    fs::write(dir.join("README.md"), "hello\n").unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-qm", "init"]);
}

fn config_bytes(git_dir: &Path) -> Vec<u8> {
    fs::read(git_dir.join("config")).expect("read .git/config")
}

/// Run `husk scan --json` against `target`, asserting the scan itself succeeds
/// so a regression can't hide behind a swallowed error, and return its stdout
/// (the JSON report) for inspection.
fn husk_scan(target: &Path, home: &Path, extra_env: &[(&str, &str)]) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_husk"));
    command
        .arg("scan")
        .arg("--offline")
        .arg("--json")
        .arg(target)
        .env("HOME", home)
        .env("HUSK_TELEMETRY_DISABLED", "1");
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let output = command.output().expect("run husk scan");
    assert!(
        output.status.success(),
        "husk scan must exit 0, got {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn scan_never_mutates_the_scanned_repo_git_config() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let repo = tmp.path().join("repo");
    init_repo(&repo);
    // A linked worktree: its `.git` is a file, and it shares `repo/.git/config`.
    let worktree = tmp.path().join("wt");
    git(
        &repo,
        &["worktree", "add", "-q", worktree.to_str().unwrap()],
    );

    let before = config_bytes(&repo.join(".git"));
    assert!(
        String::from_utf8_lossy(&before).contains("bare = false"),
        "sanity: repo starts non-bare"
    );

    husk_scan(&worktree, &home, &[]);
    husk_scan(&repo, &home, &[]);

    let after = config_bytes(&repo.join(".git"));
    assert_eq!(
        before, after,
        ".git/config must be byte-identical after a scan"
    );
}

#[test]
fn scan_is_immune_to_a_hostile_inherited_git_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    // The repo we intend to scan, plus an unrelated "hostile" repo whose `.git`
    // we leak into the environment as GIT_DIR: the exact condition under a git
    // hook (`GIT_DIR` is set) that could redirect husk's git access.
    let scanned = tmp.path().join("scanned");
    init_repo(&scanned);
    let hostile = tmp.path().join("hostile");
    init_repo(&hostile);

    let scanned_before = config_bytes(&scanned.join(".git"));
    let hostile_before = config_bytes(&hostile.join(".git"));

    husk_scan(
        &scanned,
        &home,
        &[("GIT_DIR", hostile.join(".git").to_str().unwrap())],
    );

    assert_eq!(
        scanned_before,
        config_bytes(&scanned.join(".git")),
        "scanned repo config must be untouched"
    );
    assert_eq!(
        hostile_before,
        config_bytes(&hostile.join(".git")),
        "an inherited GIT_DIR must never let husk mutate that repo's config"
    );
}

#[test]
fn scan_ignores_inherited_git_config_overrides() {
    // A git hook / agent harness can leak the `GIT_CONFIG_*` family, which
    // otherwise injects attacker-chosen config into every `git` invocation.
    // Husk reads `git config --global --get user.name`; if it honored these,
    // an attacker could feed husk a bogus identity (and, more dangerously,
    // safe-directory / signing settings). The hardened builder scrubs the
    // family, so the injected value must NOT surface in the scan report.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let scanned = tmp.path().join("scanned");
    init_repo(&scanned);

    // A hostile "global" config file the env tries to redirect git onto.
    let hostile_config = tmp.path().join("hostile.gitconfig");
    fs::write(&hostile_config, "[user]\n\tname = INJECTED_HOSTILE_NAME\n").unwrap();

    let report = husk_scan(
        &scanned,
        &home,
        &[
            ("GIT_CONFIG_GLOBAL", hostile_config.to_str().unwrap()),
            // Indexed-override mechanism: neutralized by clearing the count.
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "user.name"),
            ("GIT_CONFIG_VALUE_0", "INJECTED_HOSTILE_NAME"),
        ],
    );

    assert!(
        !report.contains("INJECTED_HOSTILE_NAME"),
        "inherited GIT_CONFIG_* overrides must never reach husk's git reads:\n{report}"
    );
}
