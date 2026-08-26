//! Project discovery, metadata, and finding attachment: the heart of the
//! project-posture model: every finding belongs to exactly one project.
//!
//! `discover_projects` runs after the scan, classifies the filesystem into
//! [`Project`]s in strict order (git repos → submodules/nested clones →
//! meaningful directories → one synthetic config/host project), reads cheap git
//! metadata, and builds a deepest-match attachment table so every finding gets a
//! `project_id`.
//!
//! Git metadata is read by a small **hand-rolled `.git` reader** (no subprocess,
//! no `gix` dependency, no zlib): branch/sha from `HEAD`, `owner_repo` from
//! `config`, and last-activity from the `logs/HEAD` reflog timestamp.

use crate::model::{Activity, GitInfo, Project, ProjectId, ProjectKind, ProjectRollup};
use chrono::{DateTime, TimeZone, Utc};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Content directories that are never project boundaries and are pruned from the
/// `.git`-marker walk for performance (we still descend through real `.git`).
const PRUNE_DIRS: &[&str] = &[
    "node_modules",
    "target",
    ".venv",
    "venv",
    "vendor",
    "dist",
    "build",
    ".next",
    "site-packages",
    ".cargo",
    ".rustup",
];

/// The discovered projects plus a deepest-match attachment table.
pub struct ProjectIndex {
    pub projects: Vec<Project>,
    /// (canonical root, id), sorted by descending path length; first
    /// `starts_with` match wins (deepest → a submodule finding attaches to the
    /// submodule, a config finding to the config project).
    attach: Vec<(PathBuf, ProjectId)>,
    /// The synthetic config/host project id (fallback owner for unowned findings).
    config_id: ProjectId,
}

impl ProjectIndex {
    /// The project a path belongs to (deepest match), or the config project.
    pub fn attach_path(&self, path: &Path) -> ProjectId {
        let canonical = canonicalize(path);
        self.attach
            .iter()
            .find(|(root, _)| canonical.starts_with(root))
            .map(|(_, id)| id.clone())
            .unwrap_or_else(|| self.config_id.clone())
    }

    pub fn config_id(&self) -> &ProjectId {
        &self.config_id
    }
}

/// Best-effort canonicalize; falls back to the input path so a vanished file
/// still attaches deterministically.
fn canonicalize(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

/// Discover all projects under `roots`. `home` is used for the synthetic
/// config/host project (and dotfiles-collision handling).
pub fn discover_projects(roots: &[PathBuf], home: Option<&Path>) -> ProjectIndex {
    // 1. Collect ALL .git markers (never prune at a .git boundary).
    let mut repo_roots: Vec<PathBuf> = Vec::new();
    let mut submodule_markers: Vec<PathBuf> = Vec::new(); // repo roots whose .git is a file
    for root in roots {
        collect_git_markers(root, &mut repo_roots, &mut submodule_markers);
    }
    // A scan root that sits *inside* a repo (`husk scan tst` from a repo
    // subfolder) discovers no `.git` below it; without its enclosing repo as a
    // project, every scanned finding would fall into the config bucket.
    for root in roots {
        let canonical = canonicalize(root);
        if !repo_roots.iter().any(|r| canonical.starts_with(r))
            && let Some(enclosing) = enclosing_git_root(&canonical)
        {
            repo_roots.push(enclosing);
        }
    }
    repo_roots.sort();
    repo_roots.dedup();

    // 2. Classify: GitRepo vs Submodule/nested.
    // A repo is a Submodule if its .git is a file (gitdir: pointer) OR its root
    // is a strict descendant of another repo root (plain nested clone).
    let submodule_set: std::collections::HashSet<&PathBuf> = submodule_markers.iter().collect();
    let mut projects: Vec<Project> = Vec::new();
    let mut attach: Vec<(PathBuf, ProjectId)> = Vec::new();

    // For submodule parent linkage.
    let id_by_root: HashMap<PathBuf, ProjectId> = repo_roots
        .iter()
        .map(|r| (r.clone(), ProjectId::from_root(r)))
        .collect();

    for root in &repo_roots {
        let id = id_by_root[root].clone();
        let nested_of = repo_roots
            .iter()
            .filter(|other| *other != root && root.starts_with(other))
            // deepest enclosing repo is the parent
            .max_by_key(|p| p.as_os_str().len());
        let is_submodule = submodule_set.contains(root) || nested_of.is_some();
        let kind = if is_submodule {
            ProjectKind::Submodule
        } else {
            ProjectKind::GitRepo
        };
        let submodule_of = if is_submodule {
            nested_of.map(|p| id_by_root[p].clone())
        } else {
            None
        };
        let git = read_git_info(root);
        let last_modified = git
            .as_ref()
            .and_then(|g| g.head_date)
            .or_else(|| dir_mtime(root));
        let activity = if kind == ProjectKind::Submodule {
            // Submodules are forced Dormant ("user doesn't maintain them").
            Activity::Dormant
        } else {
            classify_activity(last_modified)
        };
        let name = project_name(root, git.as_ref());
        projects.push(Project {
            id: id.clone(),
            root: root.clone(),
            name,
            kind,
            submodule_of,
            git,
            last_modified,
            activity,
            ecosystems: Vec::new(),
            package_count: 0,
            rollup: ProjectRollup::default(),
            posture: None,
        });
        attach.push((root.clone(), id));
    }

    // 3. The synthetic config/host project (last).
    // Rooted at a sentinel distinct from any home-as-repo so its id never
    // collides with a `~/.git` dotfiles repo.
    let home_path = home.map(canonicalize).unwrap_or_else(|| PathBuf::from("/"));
    let config_root = {
        let mut p = home_path.clone();
        p.push("#husk-config");
        p
    };
    let config_id = ProjectId::from_root(&config_root);
    projects.push(Project {
        id: config_id.clone(),
        root: config_root,
        name: "System & user config".to_string(),
        kind: ProjectKind::ConfigLocation,
        submodule_of: None,
        git: None,
        last_modified: None,
        // Config/host posture is always relevant; neutral activity.
        activity: Activity::Recent,
        ecosystems: Vec::new(),
        package_count: 0,
        rollup: ProjectRollup::default(),
        posture: None,
    });

    // Deepest-match first.
    attach.sort_by_key(|a| std::cmp::Reverse(a.0.as_os_str().len()));

    ProjectIndex {
        projects,
        attach,
        config_id,
    }
}

/// Attach every finding to its deepest-matching project (config project as
/// fallback). Part of [`apply_projects`].
pub fn attach_findings(findings: &mut [crate::model::Finding], index: &ProjectIndex) {
    for f in findings {
        let path = f
            .path
            .clone()
            .or_else(|| f.package.as_ref().map(|p| p.manifest_path.clone()));
        let id = path
            .map(|p| index.attach_path(&p))
            .unwrap_or_else(|| index.config_id().clone());
        f.project_id = Some(id);
    }
}

/// Project-posture assembly from an already-built index: attach a `project_id`
/// to every finding, roll up per-project severity/ecosystem counts, and set
/// `report.projects`. Clean repos (no findings) are dropped so the Scan list
/// stays signal, and that now includes the synthetic config/host project: a
/// folder scan never reads host config, so its row was an empty one on every
/// project scan. The live scan reuses one index across every incremental
/// publish and finalize, so mid-scan grouping matches the final report.
pub fn apply_projects(report: &mut crate::model::ScanReport, index: &ProjectIndex) {
    use std::collections::HashSet;

    attach_findings(&mut report.findings, index);

    // Per-project finding rollups.
    let mut roll: HashMap<ProjectId, ProjectRollup> = HashMap::new();
    for f in &report.findings {
        let Some(id) = &f.project_id else { continue };
        let r = roll.entry(id.clone()).or_default();
        r.by_severity.add(f.severity);
        r.worst_severity = r.worst_severity.max(Some(f.severity));
    }

    // Per-project ecosystem / package counts.
    let mut eco: HashMap<ProjectId, (HashSet<String>, usize)> = HashMap::new();
    for pkg in &report.packages {
        let id = index.attach_path(&pkg.manifest_path);
        let e = eco.entry(id).or_default();
        e.0.insert(pkg.ecosystem.clone());
        e.1 += 1;
    }

    let mut projects = index.projects.clone();
    for p in &mut projects {
        if let Some(r) = roll.remove(&p.id) {
            p.rollup = r;
        }
        if let Some((set, count)) = eco.remove(&p.id) {
            let mut v: Vec<String> = set.into_iter().collect();
            v.sort();
            p.ecosystems = v;
            p.package_count = count;
        }
    }
    projects.retain(|p| p.rollup.by_severity.findings > 0);
    report.projects = projects;
}

/// The nearest ancestor (or the path itself) that is a git worktree root:
/// a `.git` dir, or a `.git` file (`gitdir:` pointer) for linked worktrees.
fn enclosing_git_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|a| {
            let marker = a.join(".git");
            (marker.is_dir() && marker.join("HEAD").is_file())
                || std::fs::read_to_string(&marker)
                    .map(|c| c.starts_with("gitdir:"))
                    .unwrap_or(false)
        })
        .map(Path::to_path_buf)
}

/// Walk `root` collecting `.git` markers. Descends through `.git` boundaries
/// (so nested repos are reached) but prunes heavy content dirs for speed.
fn collect_git_markers(root: &Path, repos: &mut Vec<PathBuf>, file_markers: &mut Vec<PathBuf>) {
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(false) // we need to see .git
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .follow_links(false)
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            // prune heavy content dirs, but never a `.git` itself
            !(entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
                && PRUNE_DIRS.contains(&name.as_ref()))
        });
    for entry in builder.build().flatten() {
        if entry.file_name() != ".git" {
            continue;
        }
        let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if !is_file && !entry.path().join("HEAD").is_file() {
            continue;
        }
        let Some(repo_root) = entry.path().parent() else {
            continue;
        };
        let repo_root = canonicalize(repo_root);
        // Linked worktrees / submodule .git files both use the file form; both
        // are reported as their own project (submodule). Skip git internal dirs
        // (`.git/modules/...`) which would otherwise look like repos.
        if repo_root.components().any(|c| c.as_os_str() == ".git") {
            continue;
        }
        if is_file {
            file_markers.push(repo_root.clone());
        }
        repos.push(repo_root);
    }
}

/// Hand-rolled `.git` reader (no subprocess, no zlib). Returns `None` if the
/// repo can't be read at all.
fn read_git_info(root: &Path) -> Option<GitInfo> {
    let dot_git = root.join(".git");
    // Resolve the real git dir: a `.git` *file* points elsewhere ("gitdir: …").
    let git_dir = if dot_git.is_file() {
        let contents = std::fs::read_to_string(&dot_git).ok()?;
        let rel = contents.strip_prefix("gitdir:")?.trim();
        let p = PathBuf::from(rel);
        if p.is_absolute() {
            p
        } else {
            canonicalize(&root.join(p))
        }
    } else if dot_git.is_dir() {
        dot_git
    } else {
        return None;
    };

    let mut info = GitInfo::default();

    // HEAD → branch + sha.
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
        let head = head.trim();
        if let Some(reference) = head.strip_prefix("ref: ") {
            info.branch = reference.rsplit('/').next().map(|s| s.to_string());
            // resolve the ref to a sha
            let ref_path = git_dir.join(reference);
            if let Ok(sha) = std::fs::read_to_string(&ref_path) {
                info.head_sha = Some(sha.trim().to_string());
            } else if let Ok(packed) = std::fs::read_to_string(git_dir.join("packed-refs")) {
                for line in packed.lines() {
                    if let Some((sha, name)) = line.split_once(' ')
                        && name.trim() == reference
                    {
                        info.head_sha = Some(sha.trim().to_string());
                        break;
                    }
                }
            }
        } else {
            // detached HEAD: the sha directly
            info.head_sha = Some(head.to_string());
        }
    }

    // logs/HEAD → last activity (reflog timestamp on the final line).
    info.head_date = read_reflog_date(&git_dir);

    // config → remote origin url → owner_repo / host.
    if let Ok(config) = std::fs::read_to_string(git_dir.join("config"))
        && let Some(url) = parse_origin_url(&config)
    {
        let (host, owner_repo) = normalize_remote(&url);
        info.remote_host = host;
        info.owner_repo = owner_repo;
        info.remote_url = Some(url);
    }

    info.shallow = git_dir.join("shallow").exists();
    Some(info)
}

/// The committer/checkout timestamp from the last `logs/HEAD` reflog entry.
fn read_reflog_date(git_dir: &Path) -> Option<DateTime<Utc>> {
    let log = std::fs::read_to_string(git_dir.join("logs/HEAD")).ok()?;
    let last = log.lines().rfind(|l| !l.trim().is_empty())?;
    // Format: "<old> <new> <name> <email> <unix-ts> <tz>\t<message>"
    let before_tab = last.split('\t').next().unwrap_or(last);
    let mut parts = before_tab.split_whitespace().collect::<Vec<_>>();
    // timezone is last, unix-ts is second-to-last
    let _tz = parts.pop()?;
    let ts: i64 = parts.pop()?.parse().ok()?;
    Utc.timestamp_opt(ts, 0).single()
}

/// Extract the `origin` remote url from a git config file (best-effort INI).
fn parse_origin_url(config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_origin = t == "[remote \"origin\"]";
            continue;
        }
        if in_origin && let Some(url) = t.strip_prefix("url = ").or_else(|| t.strip_prefix("url="))
        {
            return Some(url.trim().to_string());
        }
    }
    None
}

/// Normalize a git remote url to `(host, owner/repo)`. Handles https and
/// scp-like (`git@host:owner/repo`); strips `.git`, `git+`, and userinfo.
/// `owner_repo` is populated only for github.com (the cloud correlation key).
fn normalize_remote(url: &str) -> (Option<String>, Option<String>) {
    let url = url.trim().trim_start_matches("git+");
    let (host, path) = if let Some(rest) = url.strip_prefix("git@") {
        // git@github.com:owner/repo.git
        match rest.split_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => return (None, None),
        }
    } else if let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("ssh://"))
    {
        // strip userinfo
        let rest = rest.rsplit('@').next().unwrap_or(rest);
        match rest.split_once('/') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => return (None, None),
        }
    } else {
        return (None, None);
    };
    let path = path.trim_start_matches('/').trim_end_matches('/');
    let owner_repo = path.strip_suffix(".git").unwrap_or(path).to_string();
    // Only correlate github.com (configurable enterprise hosts later).
    let correlate = host == "github.com";
    (
        Some(host),
        if correlate && owner_repo.matches('/').count() == 1 {
            Some(owner_repo)
        } else {
            None
        },
    )
}

/// `Active ≤30d · Recent ≤180d · Dormant ≤365d · Abandoned >365d`. Unknown date
/// → `Recent` (neutral; never demotes config/dirs).
fn classify_activity(last: Option<DateTime<Utc>>) -> Activity {
    let Some(last) = last else {
        return Activity::Recent;
    };
    let days = (Utc::now() - last).num_days();
    match days {
        d if d <= 30 => Activity::Active,
        d if d <= 180 => Activity::Recent,
        d if d <= 365 => Activity::Dormant,
        _ => Activity::Abandoned,
    }
}

/// The directory's own mtime, for non-git activity.
fn dir_mtime(dir: &Path) -> Option<DateTime<Utc>> {
    let meta = std::fs::metadata(dir).ok()?;
    let modified = meta.modified().ok()?;
    Some(DateTime::<Utc>::from(modified))
}

/// Project display name: the `owner/repo` basename when known, else the root's
/// directory basename.
fn project_name(root: &Path, git: Option<&GitInfo>) -> String {
    if let Some(owner_repo) = git.and_then(|g| g.owner_repo.as_deref())
        && let Some(repo) = owner_repo.rsplit('/').next()
    {
        return repo.to_string();
    }
    root.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_remote_https_and_scp() {
        assert_eq!(
            normalize_remote("https://github.com/ErikFrankling/husk.git"),
            (Some("github.com".into()), Some("ErikFrankling/husk".into()))
        );
        assert_eq!(
            normalize_remote("git@github.com:owner/repo.git"),
            (Some("github.com".into()), Some("owner/repo".into()))
        );
        // non-github → host known, no owner_repo correlation
        let (host, owner) = normalize_remote("git@gitlab.com:o/r.git");
        assert_eq!(host.as_deref(), Some("gitlab.com"));
        assert_eq!(owner, None);
    }

    #[test]
    fn parse_origin_url_picks_origin() {
        let cfg = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:o/r.git\n\tfetch = +refs/heads/*\n";
        assert_eq!(
            parse_origin_url(cfg).as_deref(),
            Some("git@github.com:o/r.git")
        );
    }

    /// A self-hosted remote gets no `owner_repo`, so the raw url is the only
    /// record of where the project actually came from.
    #[test]
    fn git_info_keeps_the_raw_remote_url() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("repo");
        std::fs::create_dir_all(root.join(".git")).expect("git dir");
        std::fs::write(
            root.join(".git/config"),
            "[remote \"origin\"]\n\turl = git@git.example.com:team/thing.git\n",
        )
        .expect("config");
        let git = read_git_info(&root).expect("git info");
        assert_eq!(
            git.remote_url.as_deref(),
            Some("git@git.example.com:team/thing.git")
        );
        assert_eq!(git.remote_host.as_deref(), Some("git.example.com"));
        assert_eq!(git.owner_repo, None);
    }

    #[test]
    fn activity_buckets() {
        assert_eq!(classify_activity(None), Activity::Recent);
        assert_eq!(classify_activity(Some(Utc::now())), Activity::Active);
        assert_eq!(
            classify_activity(Some(Utc::now() - chrono::Duration::days(400))),
            Activity::Abandoned
        );
    }

    /// A folder scan reads nothing outside the folder, so the synthetic
    /// config/host project has nothing to report and must not take a row in
    /// the project list next to the folder the user actually scanned.
    #[test]
    fn clean_config_project_is_dropped_from_a_folder_scan() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("repo");
        std::fs::create_dir_all(root.join(".git")).expect("git dir");
        std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").expect("head");
        let index = discover_projects(std::slice::from_ref(&root), Some(temp.path()));

        let mut report = crate::model::ScanReport::empty(vec![root.clone()]);
        report.findings = vec![
            crate::model::Finding::from_rule("t")
                .severity(crate::model::Severity::High)
                .at(root.join("app.js"), Some(1)),
        ];
        apply_projects(&mut report, &index);
        assert!(
            !report
                .projects
                .iter()
                .any(|p| p.kind == ProjectKind::ConfigLocation),
            "a clean config project must not show up: {:?}",
            report.projects.iter().map(|p| &p.name).collect::<Vec<_>>()
        );

        // A finding with no path still attaches to the config project, which
        // then has something to say and keeps its row.
        report.findings =
            vec![crate::model::Finding::from_rule("t").severity(crate::model::Severity::High)];
        apply_projects(&mut report, &index);
        assert!(
            report
                .projects
                .iter()
                .any(|p| p.kind == ProjectKind::ConfigLocation)
        );
    }

    #[test]
    fn empty_dot_git_directory_is_not_a_project_boundary() {
        let temp = tempfile::tempdir().expect("tempdir");
        let nested = temp.path().join("fixture");
        std::fs::create_dir_all(nested.join(".git/hooks")).expect("empty .git fixture");
        let index = discover_projects(std::slice::from_ref(&nested), None);
        assert!(!index.projects.iter().any(|project| project.root == nested));
    }
}
