//! The check side of the scan walk: per-file detection routing (the
//! [`Check`](crate::scan::checks::Check) registry) backed by the SQLite scan
//! index so unchanged files are skipped on a rescan, the git-hook scan, and
//! the known home-inventory locations. The filesystem traversal itself lives
//! in [`crate::scan::walk`].

use crate::cache::ScanCache;
use crate::model::{Finding, ScanOptions, Severity};
use crate::rule::{Category, Rule, RuleId};
use crate::scan::checks::util::dangerous_command_reason;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Rules for the walk-scope detectors that live in this module (the git-hook
/// scan runs on `.git` dirs collected during the walk, not per file), collected
/// into the global catalog by `crate::rule`.
pub(crate) static RULES: &[Rule] = &[Rule {
    id: RuleId::lit("git-hook"),
    title: Cow::Borrowed("Git hook can run local automation"),
    category: Category::LifecycleScript,
    default_severity: Severity::Medium,
    rationale: Cow::Borrowed(
        "A git hook executes automatically during normal git commands; a malicious or \
         unexpected hook is arbitrary local code execution on every commit or checkout.",
    ),
}];

pub fn home_inventory_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let Some(home) = dirs::home_dir() else {
        return roots;
    };

    for path in [
        home.join(".vscode/extensions"),
        home.join(".cursor/extensions"),
        home.join(".windsurf/extensions"),
        home.join(".vscode-oss/extensions"),
        home.join(".claude"),
        home.join(".cursor/mcp.json"),
        home.join(".config/Claude/claude_desktop_config.json"),
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
    ] {
        if path.exists() {
            roots.push(path);
        }
    }

    roots
}

pub(super) struct ScanFileOutcome {
    pub(super) bytes_scanned: u64,
    pub(super) cache_hit: bool,
}

const SKIPPED: ScanFileOutcome = ScanFileOutcome {
    bytes_scanned: 0,
    cache_hit: false,
};

/// Run every applicable [`Check`](crate::scan::checks::Check) over one file. The
/// detector routing lives in each check's `applies` gate; this function only
/// handles I/O, size limits, the binary-skip, and the durable scan cache.
/// Infallible: an unreadable file is simply skipped.
pub(super) fn scan_file(
    path: &Path,
    options: &ScanOptions,
    scan_index: Option<&ScanCache>,
    findings: &mut Vec<Finding>,
) -> ScanFileOutcome {
    let Ok(metadata) = fs::metadata(path) else {
        return SKIPPED;
    };
    if metadata.len() > options.max_file_bytes {
        return SKIPPED;
    }

    let fingerprint = crate::cache::fingerprint(&metadata);
    if let Some(scan_index) = scan_index
        && let Some((cached_findings, bytes_scanned)) = scan_index.lookup(path, fingerprint)
    {
        findings.extend(cached_findings);
        return ScanFileOutcome {
            bytes_scanned,
            cache_hit: true,
        };
    }

    let Ok(bytes) = fs::read(path) else {
        return SKIPPED;
    };
    if looks_binary(&bytes) {
        if let Some(scan_index) = scan_index {
            scan_index.record(path, fingerprint, 0, &[]);
        }
        return SKIPPED;
    }
    let scanned = bytes.len() as u64;
    let contents = String::from_utf8_lossy(&bytes);

    crate::scan::checks::run_per_file(path, &contents, findings);

    if let Some(scan_index) = scan_index {
        scan_index.record(path, fingerprint, scanned, findings);
    }

    ScanFileOutcome {
        bytes_scanned: scanned,
        cache_hit: false,
    }
}

/// Scan every directory git may run this repository's hooks from. Infallible:
/// unreadable hook dirs and entries are skipped.
pub(super) fn scan_git_hooks(git_dir: &Path, options: &ScanOptions, findings: &mut Vec<Finding>) {
    for hooks_dir in hook_dirs(git_dir) {
        scan_hook_dir(&hooks_dir, options, findings);
    }
}

/// Every directory the repository at `git_dir` can execute hooks from.
///
/// `.git/hooks` is only the default. `core.hooksPath` relocates hooks entirely,
/// and `.githooks/` and `.husky/` are in-repo conventions that a clone installs
/// through a `prepare`/`postinstall` script, so they can already hold live hook
/// scripts. Scanning only the default location misses the setups most projects
/// actually use. Deduplicated by canonical path so a `core.hooksPath` pointing
/// at one of the conventions is not reported twice.
fn hook_dirs(git_dir: &Path) -> Vec<PathBuf> {
    let worktree = git_dir.parent().unwrap_or(git_dir);
    let mut candidates = vec![git_dir.join("hooks")];
    candidates.extend(configured_hooks_path(worktree));
    candidates.push(worktree.join(".githooks"));
    candidates.push(worktree.join(".husky"));

    let mut seen = HashSet::new();
    candidates.retain(|dir| seen.insert(dir.canonicalize().unwrap_or_else(|_| dir.clone())));
    candidates
}

/// The repository's effective `core.hooksPath`, resolved to a directory.
///
/// Read through the hardened read-only git builder so an inherited `GIT_DIR` /
/// `GIT_CONFIG_*` environment cannot redirect the lookup at a different repo.
/// The value itself comes from `.git/config`, which is attacker-controlled in a
/// cloned repository, so it is only ever used as a directory to *read*.
fn configured_hooks_path(worktree: &Path) -> Option<PathBuf> {
    let output = crate::gitcmd::git_command()
        .arg("-C")
        .arg(worktree)
        .args(["config", "--get", "core.hooksPath"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        return None;
    }
    // git expands a leading `~` for path-typed config and resolves a relative
    // hooks path against the working tree.
    let path = match value.strip_prefix("~/") {
        Some(rest) => dirs::home_dir()?.join(rest),
        None => PathBuf::from(&value),
    };
    Some(if path.is_absolute() {
        path
    } else {
        worktree.join(path)
    })
}

fn scan_hook_dir(hooks_dir: &Path, options: &ScanOptions, findings: &mut Vec<Finding>) {
    let Ok(entries) = fs::read_dir(hooks_dir) else {
        return;
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("sample") || !path.is_file() {
            continue;
        }
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.len() > options.max_file_bytes {
            continue;
        }
        let contents = fs::read_to_string(&path).unwrap_or_default();
        let dangerous = dangerous_command_reason(&contents);
        let severity = dangerous
            .map(|_| Severity::High)
            .unwrap_or(Severity::Medium);
        let mut finding = Finding::from_rule("git-hook")
            .id("git-hook")
            .severity(severity)
            .source("Husk git hook scanner")
            .at(path, None)
            .summary(
                "A non-sample Git hook exists in this repository and can run during normal git commands.",
            )
            .recommend("Review the hook source and remove it if it was not intentionally installed.");
        if let Some(reason) = dangerous {
            finding = finding.evidence(reason);
        }
        findings.push(finding);
    }
}

fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(4096).any(|byte| *byte == 0)
}
