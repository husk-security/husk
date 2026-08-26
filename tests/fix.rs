//! `husk fix` end-to-end: scan a real temp git repo containing an untracked
//! `.env`, then plan → dry-run → apply → re-apply (idempotent) → rollback,
//! asserting husk only ever appends to `.gitignore`, backs up, and is reversible.

use husk::model::ScanOptions;
use husk::remediation::{self, ActionStatus, ApplyOptions, ExecutionClass, RemediationOperation};
use husk::scan::run_scan;
use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

fn git(repo: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        // Clear inherited repo-redirection env (a git hook run in a linked
        // worktree exports an absolute GIT_DIR) so this helper acts on `repo`.
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

struct TempRepo {
    /// Owns the directory; auto-removed on drop (even on assert failure).
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl TempRepo {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // Canonicalize for macOS, where /var symlinks to /private/var and the
        // scanner reports canonical paths.
        let root = dir.path().canonicalize().expect("canonicalize tempdir");
        assert!(git(&root, &["init", "-q"]), "git init");
        Self { _dir: dir, root }
    }
}

#[tokio::test]
async fn fix_gitignores_untracked_dotenv_and_rolls_back() {
    common::isolate();
    let repo = TempRepo::new();
    let env_path = repo.root.join(".env");
    std::fs::write(&env_path, "SECRET_TOKEN=abc123def456\nAPI_KEY=zzz\n").unwrap();

    // 1. Scan finds the plaintext .env as a secret finding.
    let mut options = ScanOptions::new(vec![repo.root.clone()]);
    options.online = false;
    options.include_home_inventory = false;
    let report = run_scan(options).await.expect("scan temp repo");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.category == husk::rule::Category::Secret
                && f.path.as_deref() == Some(env_path.as_path())),
        "expected a secret finding for the .env file"
    );

    // 2. The plan offers an AUTO-SAFE gitignore append for the dotenv file.
    let plan = remediation::plan(&report);
    assert!(
        plan.proposals.iter().any(|f| f.class == ExecutionClass::AutoSafe
            && matches!(&f.action, RemediationOperation::GitignoreAppend { secret_path } if secret_path == &env_path)),
        "plan should contain an auto-safe gitignore append for .env"
    );

    let husk_dir = repo.root.join(".husk");
    let gitignore = repo.root.join(".gitignore");

    // 3. Dry run writes nothing.
    let dry = ApplyOptions {
        dry_run: true,
        husk_dir: husk_dir.clone(),
        only: None,
        deps: false,
        on_dep_run: None,
    };
    let out = remediation::apply(&plan, &dry).expect("dry run");
    assert!(
        out.results
            .iter()
            .any(|r| r.status == ActionStatus::WouldApply)
    );
    assert!(!gitignore.exists(), "dry run must not create .gitignore");
    assert!(!husk_dir.exists(), "dry run must not create .husk");

    // 4. Apply: .gitignore now ignores .env, and a backup snapshot exists.
    let live = ApplyOptions {
        dry_run: false,
        husk_dir: husk_dir.clone(),
        only: None,
        deps: false,
        on_dep_run: None,
    };
    let out = remediation::apply(&plan, &live).expect("apply");
    assert!(
        out.results
            .iter()
            .any(|r| r.status == ActionStatus::Applied)
    );
    let ignore_body = std::fs::read_to_string(&gitignore).expect("gitignore written");
    assert!(
        ignore_body.lines().any(|l| l.trim() == ".env"),
        "gitignore should now contain .env, got: {ignore_body:?}"
    );
    assert!(out.backup_dir.is_some(), "apply records a backup dir");
    assert!(
        git(&repo.root, &["check-ignore", "-q", "--", ".env"]),
        ".env now ignored"
    );
    // The backups dir is itself kept out of git.
    assert!(
        husk_dir.join(".gitignore").exists(),
        ".husk/.gitignore written"
    );

    // 5. Idempotent: re-planning + applying does nothing (already ignored).
    let report2 = {
        let mut o = ScanOptions::new(vec![repo.root.clone()]);
        o.online = false;
        o.include_home_inventory = false;
        run_scan(o).await.expect("rescan")
    };
    let plan2 = remediation::plan(&report2);
    let out2 = remediation::apply(&plan2, &live).expect("re-apply");
    assert!(
        out2.results
            .iter()
            .filter(|r| r.id.starts_with("gitignore:"))
            .all(|r| r.status == ActionStatus::Skipped),
        "second apply must be a clean no-op for the gitignore action"
    );

    // 6. Rollback restores .gitignore to its pre-fix (absent → empty) state.
    let restored = remediation::rollback(&husk_dir, None).expect("rollback");
    assert!(!restored.is_empty(), "rollback restored at least one file");
    let after = std::fs::read_to_string(&gitignore).unwrap_or_default();
    assert!(
        !after.lines().any(|l| l.trim() == ".env"),
        "rollback should remove the .env line, got: {after:?}"
    );
}
