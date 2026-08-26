//! Dependency-domain controls: cooldown, install-script suppression, lockfile
//! presence and commit state, frozen installs, advisory findings, registry
//! scoping, and update automation.

use super::{
    ControlAssessment, ControlContext, ControlStatus, Evidence, assessment, evidence,
    finding_evidence, git_root, home, manifest_dirs, matching_rules, project_roots, read_text,
    rule_control,
};
use crate::remediation::RemediationProposal;
use crate::rule::Category;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Small config readers shared by the probes in this module
// ---------------------------------------------------------------------------

/// `key=value` lookup in npm-style ini (`.npmrc`, `go/env`); last write wins.
fn ini_value(contents: &str, key: &str) -> Option<String> {
    let mut found = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            found = Some(v.trim().trim_matches('"').to_string());
        }
    }
    found
}

fn ini_truthy(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

/// Top-level (unindented) `key: value` in a small YAML config.
fn yaml_top_value(contents: &str, key: &str) -> Option<String> {
    let mut found = None;
    for line in contents.lines() {
        if line.starts_with(' ') || line.starts_with('\t') || line.trim_start().starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.trim() == key
        {
            found = Some(v.trim().trim_matches(|c| c == '"' || c == '\'').to_string());
        }
    }
    found
}

/// Value of `key` in a small TOML file. `section: None` matches only keys
/// before the first `[header]`; `Some(name)` only keys inside `[name]`.
fn toml_value(contents: &str, section: Option<&str>, key: &str) -> Option<String> {
    let mut current: Option<String> = None;
    let mut found = None;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            current = Some(
                line.trim_matches(|c| c == '[' || c == ']')
                    .trim()
                    .to_string(),
            );
            continue;
        }
        let in_scope = match section {
            None => current.is_none(),
            Some(name) => current.as_deref() == Some(name),
        };
        if in_scope
            && let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            found = Some(v.trim().trim_matches('"').to_string());
        }
    }
    found
}

fn snippet(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() > 80 {
        let cut: String = text.chars().take(77).collect();
        format!("{cut}...")
    } else {
        text.to_string()
    }
}

fn display_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

fn npm_surface(root: &Path) -> bool {
    [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "bun.lockb",
    ]
    .iter()
    .any(|name| root.join(name).is_file())
}

fn python_surface(root: &Path) -> bool {
    ["pyproject.toml", "uv.toml", "uv.lock", "poetry.lock"]
        .iter()
        .any(|name| root.join(name).is_file())
}

fn deno_manifest(root: &Path) -> Option<PathBuf> {
    ["deno.json", "deno.jsonc"]
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.is_file())
}

// ---------------------------------------------------------------------------
// dependency-cooldown
// ---------------------------------------------------------------------------

/// A cooldown value of `0`/`false` is the feature switched off, not a config.
fn cooldown_on(value: &str) -> bool {
    !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
}

type CooldownSource = (PathBuf, &'static str);

/// The npm-family cooldown configured in `dir`, if any. Works for a project
/// root and for the user home (`~/.npmrc` / `~/.yarnrc.yml` share the names).
fn npm_cooldown_source(dir: &Path) -> Option<CooldownSource> {
    let npmrc = dir.join(".npmrc");
    if read_text(&npmrc)
        .and_then(|c| ini_value(&c, "min-release-age"))
        .is_some_and(|v| cooldown_on(&v))
    {
        return Some((npmrc, ".npmrc min-release-age"));
    }
    let pnpm = dir.join("pnpm-workspace.yaml");
    if read_text(&pnpm)
        .and_then(|c| yaml_top_value(&c, "minimumReleaseAge"))
        .is_some_and(|v| cooldown_on(&v))
    {
        return Some((pnpm, "pnpm-workspace.yaml minimumReleaseAge"));
    }
    let yarn = dir.join(".yarnrc.yml");
    if read_text(&yarn)
        .and_then(|c| yaml_top_value(&c, "npmMinimalAgeGate"))
        .is_some_and(|v| cooldown_on(&v))
    {
        return Some((yarn, ".yarnrc.yml npmMinimalAgeGate"));
    }
    let bun = dir.join("bunfig.toml");
    if read_text(&bun)
        .and_then(|c| toml_value(&c, Some("install"), "minimumReleaseAge"))
        .is_some_and(|v| cooldown_on(&v))
    {
        return Some((bun, "bunfig.toml [install] minimumReleaseAge"));
    }
    None
}

fn python_cooldown_source(dir: &Path) -> Option<CooldownSource> {
    let uv = dir.join("uv.toml");
    if read_text(&uv)
        .and_then(|c| toml_value(&c, None, "exclude-newer"))
        .is_some_and(|v| cooldown_on(&v))
    {
        return Some((uv, "uv.toml exclude-newer"));
    }
    let pyproject = dir.join("pyproject.toml");
    if read_text(&pyproject)
        .and_then(|c| toml_value(&c, Some("tool.uv"), "exclude-newer"))
        .is_some_and(|v| cooldown_on(&v))
    {
        return Some((pyproject, "pyproject.toml [tool.uv] exclude-newer"));
    }
    None
}

pub(super) fn cooldown(ctx: &ControlContext<'_>) -> ControlAssessment {
    let id = "dependency-cooldown";
    let home_dir = home(ctx);
    let home_npm = home_dir.and_then(|h| {
        npm_cooldown_source(h).or_else(|| {
            let bun = h.join(".bunfig.toml");
            read_text(&bun)
                .and_then(|c| toml_value(&c, Some("install"), "minimumReleaseAge"))
                .is_some_and(|v| cooldown_on(&v))
                .then_some((bun, ".bunfig.toml [install] minimumReleaseAge"))
        })
    });
    let home_python = home_dir.and_then(|h| {
        let uv = h.join(".config/uv/uv.toml");
        read_text(&uv)
            .and_then(|c| toml_value(&c, None, "exclude-newer"))
            .is_some_and(|v| cooldown_on(&v))
            .then_some((uv, "uv.toml exclude-newer"))
    });

    let mut rows = Vec::new();
    let mut applicable = 0usize;
    let mut covered = 0usize;
    for root in project_roots(ctx) {
        let mut needs: Vec<(&str, Option<CooldownSource>)> = Vec::new();
        if npm_surface(&root) {
            needs.push((
                "npm",
                npm_cooldown_source(&root).or_else(|| home_npm.clone()),
            ));
        }
        if python_surface(&root) {
            needs.push((
                "Python",
                python_cooldown_source(&root).or_else(|| home_python.clone()),
            ));
        }
        if let Some(deno) = deno_manifest(&root) {
            let source = read_text(&deno)
                .is_some_and(|c| c.contains("\"minimumDependencyAge\""))
                .then_some((deno, "deno.json minimumDependencyAge"));
            needs.push(("Deno", source));
        }
        if needs.is_empty() {
            continue;
        }
        applicable += 1;
        if needs.iter().all(|(_, source)| source.is_some()) {
            covered += 1;
        }
        for (eco, source) in needs {
            match source {
                Some((path, label)) => rows.push(evidence(
                    format!("{eco} cooldown configured ({label})"),
                    Some(path),
                )),
                None => rows.push(evidence(
                    format!("No {eco} dependency cooldown is configured"),
                    Some(root.clone()),
                )),
            }
        }
    }

    if applicable == 0 {
        let npm_pkgs = ctx.report.packages.iter().any(|p| p.ecosystem == "npm");
        let py_pkgs = ctx.report.packages.iter().any(|p| p.ecosystem == "pypi");
        if !npm_pkgs && !py_pkgs {
            return assessment(
                id,
                ControlStatus::NotApplicable,
                vec![evidence(
                    "No npm, Python, or Deno package surface was found",
                    None,
                )],
                Vec::new(),
            );
        }
        let mut ok = true;
        for (label, present, source) in [
            ("npm", npm_pkgs, &home_npm),
            ("Python", py_pkgs, &home_python),
        ] {
            if !present {
                continue;
            }
            match source {
                Some((path, key)) => rows.push(evidence(
                    format!("{label} cooldown configured ({key})"),
                    Some(path.clone()),
                )),
                None => {
                    ok = false;
                    rows.push(evidence(
                        format!("No {label} dependency cooldown is configured in your user config"),
                        None,
                    ));
                }
            }
        }
        let status = if ok {
            ControlStatus::Passed
        } else {
            ControlStatus::Failed
        };
        return assessment(id, status, rows, Vec::new());
    }

    let status = if covered == applicable {
        ControlStatus::Passed
    } else if covered > 0 {
        ControlStatus::Partial
    } else {
        ControlStatus::Failed
    };
    assessment(id, status, rows, Vec::new())
}

// ---------------------------------------------------------------------------
// install-scripts-disabled
// ---------------------------------------------------------------------------

fn install_script_guard(root: &Path) -> Option<(PathBuf, &'static str)> {
    let npmrc = root.join(".npmrc");
    if read_text(&npmrc)
        .and_then(|c| ini_value(&c, "ignore-scripts"))
        .is_some_and(|v| ini_truthy(&v))
    {
        return Some((npmrc, ".npmrc ignore-scripts=true"));
    }
    let pnpm = root.join("pnpm-workspace.yaml");
    if read_text(&pnpm).is_some_and(|c| yaml_top_value(&c, "onlyBuiltDependencies").is_some()) {
        return Some((pnpm, "pnpm onlyBuiltDependencies allowlist"));
    }
    let package = root.join("package.json");
    if read_text(&package).is_some_and(|c| c.contains("\"allowScripts\"")) {
        return Some((package, "npm allowScripts allowlist"));
    }
    None
}

pub(super) fn install_scripts(ctx: &ControlContext<'_>) -> ControlAssessment {
    let id = "install-scripts-disabled";
    let roots: Vec<PathBuf> = project_roots(ctx)
        .into_iter()
        .filter(|root| npm_surface(root))
        .collect();
    let npm_packages = ctx.report.packages.iter().any(|p| p.ecosystem == "npm");
    if roots.is_empty() && !npm_packages {
        return assessment(
            id,
            ControlStatus::NotApplicable,
            vec![evidence(
                "No npm, pnpm, yarn, or bun projects were found",
                None,
            )],
            Vec::new(),
        );
    }

    let findings = matching_rules(ctx.report, &["npmrc-ignore-scripts"]);
    let home_npmrc = home(ctx).map(|h| h.join(".npmrc"));
    let home_covered = home_npmrc
        .as_ref()
        .and_then(|path| read_text(path))
        .and_then(|c| ini_value(&c, "ignore-scripts"))
        .is_some_and(|v| ini_truthy(&v));

    let mut rows = Vec::new();
    if home_covered {
        rows.push(evidence(
            "User .npmrc sets ignore-scripts=true",
            home_npmrc.clone(),
        ));
    }

    if roots.is_empty() {
        let status = if home_covered {
            ControlStatus::Passed
        } else {
            rows.push(evidence(
                "Your user .npmrc does not set ignore-scripts=true",
                home_npmrc,
            ));
            ControlStatus::Failed
        };
        let attach = if status == ControlStatus::Passed {
            Vec::new()
        } else {
            findings
        };
        return assessment(id, status, rows, attach);
    }

    let mut covered = 0usize;
    for root in &roots {
        if home_covered {
            covered += 1;
            continue;
        }
        match install_script_guard(root) {
            Some((path, label)) => {
                covered += 1;
                rows.push(evidence(
                    format!("Install scripts restricted ({label})"),
                    Some(path),
                ));
            }
            None => rows.push(evidence(
                "Dependency install scripts run unrestricted for this project",
                Some(root.clone()),
            )),
        }
    }
    let status = if covered == roots.len() {
        ControlStatus::Passed
    } else if covered > 0 {
        ControlStatus::Partial
    } else {
        ControlStatus::Failed
    };
    let attach = if status == ControlStatus::Passed {
        Vec::new()
    } else {
        findings
    };
    assessment(id, status, rows, attach)
}

// ---------------------------------------------------------------------------
// lifecycle-scripts
// ---------------------------------------------------------------------------

pub(super) fn lifecycle_scripts(ctx: &ControlContext<'_>) -> ControlAssessment {
    let applicable = ctx.report.packages.iter().any(|p| p.ecosystem == "npm");
    rule_control(
        "lifecycle-scripts",
        ctx.report,
        &["npm-lifecycle-script"],
        applicable,
    )
}

// ---------------------------------------------------------------------------
// lockfile-present
// ---------------------------------------------------------------------------

const NPM_LOCKS: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
];
const PY_LOCKS: &[&str] = &["uv.lock", "poetry.lock", "pdm.lock"];

/// Manifests in `root` that should have a lockfile, with the lock names that
/// satisfy each. `Cargo.toml` counts only for binaries: libraries deliberately
/// omit `Cargo.lock`. A `pyproject.toml` counts only when it declares a
/// project, not when it is pure tool config.
fn manifests_needing_locks(root: &Path) -> Vec<(PathBuf, &'static [&'static str])> {
    let mut out: Vec<(PathBuf, &'static [&'static str])> = Vec::new();
    let package = root.join("package.json");
    if package.is_file() {
        out.push((package, NPM_LOCKS));
    }
    let pyproject = root.join("pyproject.toml");
    if pyproject.is_file()
        && read_text(&pyproject).is_some_and(|c| {
            c.lines()
                .any(|line| matches!(line.trim(), "[project]" | "[tool.poetry]" | "[tool.pdm]"))
        })
    {
        out.push((pyproject, PY_LOCKS));
    }
    for (manifest, locks) in [
        ("Gemfile", &["Gemfile.lock"] as &'static [&'static str]),
        ("composer.json", &["composer.lock"]),
        ("go.mod", &["go.sum"]),
    ] {
        let path = root.join(manifest);
        if path.is_file() {
            out.push((path, locks));
        }
    }
    let cargo = root.join("Cargo.toml");
    if cargo.is_file()
        && (root.join("src/main.rs").is_file()
            || read_text(&cargo).is_some_and(|c| c.lines().any(|l| l.trim() == "[[bin]]")))
    {
        out.push((cargo, &["Cargo.lock"]));
    }
    out
}

/// A matching lockfile in `root` or, for workspace layouts, in an ancestor up
/// to the enclosing git root (pnpm/uv/cargo workspaces lock at the top).
fn lock_near(root: &Path, names: &[&str]) -> Option<PathBuf> {
    for name in names {
        let path = root.join(name);
        if path.is_file() {
            return Some(path);
        }
    }
    let stop = git_root(root)?;
    let mut dir = root.parent();
    while let Some(current) = dir {
        if !current.starts_with(&stop) {
            break;
        }
        for name in names {
            let path = current.join(name);
            if path.is_file() {
                return Some(path);
            }
        }
        dir = current.parent();
    }
    None
}

/// A lockfile only protects the machines that receive it, so this asks both
/// halves of the question: does each manifest have a lock, and is that lock
/// committed. A lock Git cannot be asked about is left uncounted rather than
/// failed.
pub(super) fn lockfile_present(ctx: &ControlContext<'_>) -> ControlAssessment {
    let id = "lockfile-present";
    let mut found: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut rows = Vec::new();
    let mut missing = 0usize;
    for root in manifest_dirs(ctx) {
        for (manifest, locks) in manifests_needing_locks(&root) {
            match lock_near(&root, locks) {
                Some(lock) => found.push((manifest, lock)),
                None => {
                    missing += 1;
                    rows.push(evidence(
                        format!("{} has no lockfile", display_name(&manifest)),
                        Some(manifest),
                    ));
                }
            }
        }
    }
    if found.is_empty() && missing == 0 {
        return assessment(
            id,
            ControlStatus::NotApplicable,
            vec![evidence("No dependency manifests were discovered", None)],
            Vec::new(),
        );
    }

    let tracked = git_tracks_all(&found.iter().map(|(_, lock)| lock).collect());
    let mut uncommitted = 0usize;
    for (manifest, lock) in found {
        let summary = match tracked.get(&lock).copied().flatten() {
            Some(false) => {
                uncommitted += 1;
                format!(
                    "{} is covered by {}, which is not committed to Git",
                    display_name(&manifest),
                    display_name(&lock)
                )
            }
            _ => format!(
                "{} is covered by {}",
                display_name(&manifest),
                display_name(&lock)
            ),
        };
        rows.push(evidence(summary, Some(lock)));
    }

    let status = if missing > 0 || uncommitted > 0 {
        ControlStatus::Failed
    } else {
        ControlStatus::Passed
    };
    assessment(id, status, rows, Vec::new())
}

/// Which of `paths` Git tracks: `Some(true)` tracked, `Some(false)` untracked,
/// `None` outside a readable repository.
///
/// This runs inside every scan's finalize, so it is grouped rather than
/// per-file: asking `rev-parse` + `ls-files` about one lockfile at a time meant
/// two process spawns per lockfile, which dominated finalize on a repo-heavy
/// tree. Lockfiles cluster into a few repositories, so the repo root is
/// resolved once per directory and each repository is then asked once about all
/// of its candidates.
fn git_tracks_all(paths: &BTreeSet<&PathBuf>) -> std::collections::HashMap<PathBuf, Option<bool>> {
    let mut roots: std::collections::HashMap<PathBuf, Option<PathBuf>> =
        std::collections::HashMap::new();
    let mut by_root: std::collections::HashMap<PathBuf, Vec<&PathBuf>> =
        std::collections::HashMap::new();
    let mut result: std::collections::HashMap<PathBuf, Option<bool>> =
        std::collections::HashMap::new();

    for path in paths {
        let Some(parent) = path.parent() else {
            result.insert((*path).clone(), None);
            continue;
        };
        let root = roots
            .entry(parent.to_path_buf())
            .or_insert_with(|| git_root(parent))
            .clone();
        match root {
            Some(root) => by_root.entry(root).or_default().push(path),
            None => {
                result.insert((*path).clone(), None);
            }
        }
    }

    for (root, candidates) in by_root {
        // `ls-files` echoes back only the paths it tracks, so an absent entry
        // is an untracked file. `-z` keeps newline-bearing paths parseable.
        let mut command = crate::gitcmd::git_command();
        command.args(["-C", &root.to_string_lossy(), "ls-files", "-z", "--"]);
        let mut relatives = Vec::with_capacity(candidates.len());
        for path in &candidates {
            match path.strip_prefix(&root) {
                Ok(relative) => {
                    command.arg(relative.as_os_str());
                    relatives.push((*path, relative.to_path_buf()));
                }
                Err(_) => {
                    result.insert((*path).clone(), None);
                }
            }
        }
        if relatives.is_empty() {
            continue;
        }
        let Some(output) = command.output().ok().filter(|out| out.status.success()) else {
            for (path, _) in relatives {
                result.insert(path.clone(), None);
            }
            continue;
        };
        let listed = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| PathBuf::from(String::from_utf8_lossy(entry).into_owned()))
            .collect::<BTreeSet<_>>();
        for (path, relative) in relatives {
            result.insert(path.clone(), Some(listed.contains(&relative)));
        }
    }

    result
}

// ---------------------------------------------------------------------------
// frozen-install
// ---------------------------------------------------------------------------

/// Package managers that can be told to freeze by configuration rather than by
/// a flag on every invocation. When the key is set, a bare `yarn install` in
/// that project is already immutable, so the command alone does not say whether
/// the lockfile is authoritative.
const CONFIGURED_FREEZE: &[(&str, &str, &str)] = &[
    ("yarn", ".yarnrc.yml", "enableImmutableInstalls"),
    ("bun", "bunfig.toml", "frozenLockfile"),
    ("bundler", ".bundle/config", "BUNDLE_FROZEN"),
    ("bundler", ".bundle/config", "BUNDLE_DEPLOYMENT"),
];

/// Which package managers this project has configured to freeze by default,
/// with the file that says so.
fn configured_freeze(root: &Path) -> Vec<(&'static str, PathBuf)> {
    let mut found: Vec<(&'static str, PathBuf)> = Vec::new();
    for (tool, file, key) in CONFIGURED_FREEZE {
        let path = root.join(file);
        let Some(text) = read_text(&path) else {
            continue;
        };
        let enabled = text.lines().any(|line| {
            let line = line.trim();
            line.starts_with(key)
                && line
                    .split_once(':')
                    .or_else(|| line.split_once('='))
                    .is_some_and(|(_, value)| {
                        matches!(value.trim().trim_matches('"'), "true" | "1" | "yes")
                    })
        });
        if enabled && !found.iter().any(|(name, _)| name == tool) {
            found.push((tool, path));
        }
    }
    found
}

/// Which package manager an install command belongs to, and whether that
/// invocation is frozen. `None` means the line is not an install command, one
/// whose default is already safe (pnpm freezes on CI), or one that does not
/// touch a lockfile (global tool installs, `pip install <pkg>`).
fn classify_install(line: &str) -> Option<(&'static str, bool)> {
    let line = line.trim();
    if line.starts_with('#') {
        return None;
    }
    // pnpm first: "pnpm install" contains "npm install" as a substring.
    if line.contains("pnpm install") {
        return line.contains("--frozen-lockfile").then_some(("pnpm", true));
    }
    if line.contains("npm ci") {
        return Some(("npm", true));
    }
    if line.contains("npm install") {
        if line.contains("--global") || has_flag(line, "-g") {
            return None;
        }
        return Some(("npm", false));
    }
    if line.contains("yarn install") {
        return Some((
            "yarn",
            line.contains("--immutable") || line.contains("--frozen-lockfile"),
        ));
    }
    if line.contains("bun install") {
        return Some(("bun", line.contains("--frozen-lockfile")));
    }
    if line.contains("pip install") || line.contains("pip3 install") {
        if line.contains("--require-hashes") {
            return Some(("pip", true));
        }
        if line.contains("--requirement") || has_flag(line, "-r") {
            return Some(("pip", false));
        }
        return None;
    }
    if line.contains("uv sync") {
        return (line.contains("--frozen") || line.contains("--locked")).then_some(("uv", true));
    }
    if line.contains("poetry install") {
        return line.contains("--sync").then_some(("poetry", true));
    }
    if line.contains("bundle install") {
        return Some((
            "bundler",
            line.contains("--deployment") || line.contains("--frozen"),
        ));
    }
    if line.contains("go mod download") || line.contains("-mod=readonly") {
        return Some(("go", true));
    }
    if line.contains("cargo ") && line.contains("--locked") {
        return Some(("cargo", true));
    }
    None
}

fn has_flag(line: &str, flag: &str) -> bool {
    line.split_whitespace().any(|word| word == flag)
}

fn ci_files(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![
        root.join(".gitlab-ci.yml"),
        root.join("Makefile"),
        root.join("Dockerfile"),
    ];
    if let Ok(entries) = std::fs::read_dir(root.join(".github/workflows")) {
        files.extend(
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|ext| ext == "yml" || ext == "yaml")
                }),
        );
    }
    files.retain(|path| path.is_file());
    files.sort();
    files
}

pub(super) fn frozen_install(ctx: &ControlContext<'_>) -> ControlAssessment {
    let id = "frozen-install";
    let mut frozen: Vec<Evidence> = Vec::new();
    let mut loose: Vec<Evidence> = Vec::new();
    for root in project_roots(ctx) {
        let configured = configured_freeze(&root);
        if let Some(text) = read_text(&root.join("package.json"))
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(scripts) = json.get("scripts").and_then(serde_json::Value::as_object)
        {
            for (name, command) in scripts {
                if let Some(cmd) = command.as_str()
                    && let Some((tool, is_frozen)) = classify_install(cmd)
                {
                    let row = evidence(
                        format!("scripts.{name}: {}", snippet(cmd)),
                        Some(root.join("package.json")),
                    );
                    if is_frozen || configured.iter().any(|(name, _)| *name == tool) {
                        frozen.push(row);
                    } else {
                        loose.push(row);
                    }
                }
            }
        }
        for path in ci_files(&root) {
            let Some(text) = read_text(&path) else {
                continue;
            };
            for line in text.lines() {
                if let Some((tool, is_frozen)) = classify_install(line) {
                    let row = evidence(snippet(line), Some(path.clone()));
                    if is_frozen || configured.iter().any(|(name, _)| *name == tool) {
                        frozen.push(row);
                    } else {
                        loose.push(row);
                    }
                }
            }
        }
        frozen.extend(configured.into_iter().map(|(tool, path)| {
            evidence(
                format!("{tool} is configured to install immutably by default"),
                Some(path),
            )
        }));
    }
    let status = match (frozen.is_empty(), loose.is_empty()) {
        (true, true) => {
            return assessment(
                id,
                ControlStatus::NotApplicable,
                vec![evidence(
                    "No install commands were found in package scripts, CI configs, or Dockerfiles",
                    None,
                )],
                Vec::new(),
            );
        }
        (false, true) => ControlStatus::Passed,
        (true, false) => ControlStatus::Failed,
        (false, false) => ControlStatus::Partial,
    };
    // Show the problems when there are any; the frozen commands otherwise.
    let mut rows = if status == ControlStatus::Passed {
        frozen
    } else {
        loose
    };
    rows.truncate(12);
    assessment(id, status, rows, Vec::new())
}

// ---------------------------------------------------------------------------
// dependency-security / malicious-packages
// ---------------------------------------------------------------------------

/// The advisory sources that could not answer for this scan.
///
/// A source with nothing in its ecosystem still reports `ok` (the Arch feed on
/// a machine with no pacman packages says so and succeeds), so a failed row
/// means a database that had something to say could not say it. Which
/// coordinates it would have covered is precisely what husk does not know, so
/// one failure taints the whole verdict rather than one ecosystem's.
fn blocked_sources<'a>(ctx: &ControlContext<'a>) -> Vec<&'a crate::model::ProviderStatus> {
    ctx.report
        .providers
        .iter()
        .filter(|provider| !provider.ok)
        .collect()
}

fn source_names(blocked: &[&crate::model::ProviderStatus]) -> String {
    blocked
        .iter()
        .map(|provider| provider.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A control over findings that only exist when an online database answered.
///
/// The absence of an advisory is evidence of safety only if the databases that
/// would have reported one were actually reachable. A scan that could not ask
/// reports [`ControlStatus::Unknown`], never `Passed`: asserting safety husk
/// never established is the one failure mode a security tool cannot have, and
/// it is invisible precisely when it matters, because a rate-limited source and
/// a clean machine produce the same empty finding list.
///
/// `subject` names what was checked against, so both the reassuring and the
/// unreassuring sentence can be built from it.
fn package_findings_control(
    ctx: &ControlContext<'_>,
    id: &str,
    wanted: fn(Category) -> bool,
    subject: &str,
) -> ControlAssessment {
    let findings = ctx
        .report
        .findings
        .iter()
        .filter(|finding| finding.package.is_some() && wanted(finding.category))
        .collect::<Vec<_>>();
    let blocked = blocked_sources(ctx);

    if !findings.is_empty() {
        let mut rows = Vec::new();
        // Leads the evidence rather than trailing a hundred advisories: a list
        // the reader takes as exhaustive, when it is not, is the same lie in a
        // quieter register.
        if !blocked.is_empty() {
            rows.push(evidence(
                format!(
                    "This list may be incomplete: {} did not answer",
                    source_names(&blocked)
                ),
                None,
            ));
        }
        rows.extend(findings.iter().map(|finding| finding_evidence(finding)));
        return assessment(id, ControlStatus::Failed, rows, findings);
    }

    let packages = ctx.report.packages.len();
    if packages == 0 {
        return assessment(
            id,
            ControlStatus::NotApplicable,
            vec![evidence(
                format!("No packages were discovered to check against {subject}"),
                None,
            )],
            Vec::new(),
        );
    }

    // How many coordinates any one source got through. Sources overlap, so the
    // largest is the best single measure of what was covered; all that matters
    // here is whether anything was.
    let covered = ctx
        .report
        .providers
        .iter()
        .filter(|provider| provider.ok)
        .map(|provider| provider.checked_packages)
        .max()
        .unwrap_or(0);
    if covered == 0 {
        // Nothing was queried: `husk scan --offline`, a fan-out that failed
        // outright, or packages no source covers. An offline scan is a
        // deliberate choice rather than a failure, so the sources state the
        // reason in their own words instead of husk guessing at it.
        let mut rows = vec![evidence(
            format!(
                "{packages} packages were not checked against {subject}: \
                 no advisory database was queried for them"
            ),
            None,
        )];
        rows.extend(
            ctx.report
                .providers
                .iter()
                .map(|provider| evidence(format!("{}: {}", provider.name, provider.message), None)),
        );
        return assessment(id, ControlStatus::Unknown, rows, Vec::new());
    }
    if !blocked.is_empty() {
        let mut rows = vec![evidence(
            format!(
                "{packages} packages were only partly checked against {subject}: \
                 {} did not answer",
                source_names(&blocked)
            ),
            None,
        )];
        rows.extend(
            blocked
                .iter()
                .map(|provider| evidence(format!("{}: {}", provider.name, provider.message), None)),
        );
        return assessment(id, ControlStatus::Unknown, rows, Vec::new());
    }
    assessment(
        id,
        ControlStatus::Passed,
        vec![evidence(
            format!("{packages} packages checked against {subject}, none matched"),
            None,
        )],
        Vec::new(),
    )
}

pub(super) fn dependency_security(ctx: &ControlContext<'_>) -> ControlAssessment {
    package_findings_control(
        ctx,
        "dependency-security",
        |category| matches!(category, Category::Vulnerability),
        "known vulnerabilities",
    )
}

pub(super) fn malicious_packages(ctx: &ControlContext<'_>) -> ControlAssessment {
    package_findings_control(
        ctx,
        "malicious-packages",
        |category| matches!(category, Category::Malware | Category::Typosquat),
        "malware and typosquat intel",
    )
}

pub(super) fn dependency_fixes(
    ctx: &ControlContext<'_>,
    _: &ControlAssessment,
) -> Vec<RemediationProposal> {
    crate::remediation::dependency_proposals(ctx.report)
}

// ---------------------------------------------------------------------------
// registry-scoping
// ---------------------------------------------------------------------------

pub(super) fn registry_scoping(ctx: &ControlContext<'_>) -> ControlAssessment {
    let id = "registry-scoping";
    let roots = project_roots(ctx);
    let mut checked = false;
    let mut fails: Vec<Evidence> = Vec::new();
    let mut nondefault: Vec<Evidence> = Vec::new();

    let mut npmrc_paths: Vec<PathBuf> = roots.iter().map(|r| r.join(".npmrc")).collect();
    if let Some(h) = home(ctx) {
        npmrc_paths.push(h.join(".npmrc"));
    }
    for path in npmrc_paths {
        let Some(contents) = read_text(&path) else {
            continue;
        };
        checked = true;
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());
            let is_registry =
                key == "registry" || (key.starts_with('@') && key.ends_with(":registry"));
            if !is_registry {
                continue;
            }
            if value.starts_with("http://") {
                fails.push(evidence(
                    format!("{key} uses a plaintext http registry ({})", snippet(value)),
                    Some(path.clone()),
                ));
            } else if value.trim_end_matches('/') != "https://registry.npmjs.org" {
                nondefault.push(evidence(
                    format!(
                        "{key} points at a non-default registry ({})",
                        snippet(value)
                    ),
                    Some(path.clone()),
                ));
            }
        }
    }

    let mut pip_paths: Vec<PathBuf> = roots.iter().map(|r| r.join("pip.conf")).collect();
    if let Some(h) = home(ctx) {
        pip_paths.push(h.join(".config/pip/pip.conf"));
    }
    if let Some(venv) = std::env::var_os("VIRTUAL_ENV") {
        pip_paths.push(PathBuf::from(venv).join("pip.conf"));
    }
    for path in pip_paths {
        let Some(contents) = read_text(&path) else {
            continue;
        };
        checked = true;
        if ini_value(&contents, "extra-index-url").is_some_and(|v| !v.is_empty()) {
            fails.push(evidence(
                "pip extra-index-url is set: any index can satisfy any package name (dependency confusion)",
                Some(path.clone()),
            ));
        }
        if let Some(index) = ini_value(&contents, "index-url") {
            if index.starts_with("http://") {
                fails.push(evidence(
                    format!("pip index-url uses plaintext http ({})", snippet(&index)),
                    Some(path.clone()),
                ));
            } else if index.trim_end_matches('/') != "https://pypi.org/simple" {
                nondefault.push(evidence(
                    format!(
                        "pip index-url points at a non-default index ({})",
                        snippet(&index)
                    ),
                    Some(path.clone()),
                ));
            }
        }
    }

    let mut cargo_paths: Vec<PathBuf> =
        roots.iter().map(|r| r.join(".cargo/config.toml")).collect();
    if let Some(h) = home(ctx) {
        cargo_paths.push(h.join(".cargo/config.toml"));
    }
    for path in cargo_paths {
        let Some(contents) = read_text(&path) else {
            continue;
        };
        checked = true;
        if toml_value(&contents, Some("source.crates-io"), "replace-with").is_some() {
            nondefault.push(evidence(
                "crates.io source is replaced ([source.crates-io] replace-with)",
                Some(path),
            ));
        }
    }

    if let Some(h) = home(ctx) {
        let path = h.join(".config/go/env");
        if let Some(contents) = read_text(&path) {
            checked = true;
            if let Some(proxy) = ini_value(&contents, "GOPROXY") {
                if proxy.contains("http://") {
                    fails.push(evidence(
                        format!("GOPROXY uses a plaintext http proxy ({})", snippet(&proxy)),
                        Some(path),
                    ));
                } else if !proxy.is_empty() && proxy != "https://proxy.golang.org,direct" {
                    nondefault.push(evidence(
                        format!("GOPROXY is redirected ({})", snippet(&proxy)),
                        Some(path),
                    ));
                }
            }
        }
    }

    if !fails.is_empty() {
        fails.extend(nondefault);
        return assessment(id, ControlStatus::Failed, fails, Vec::new());
    }
    if !nondefault.is_empty() {
        return assessment(id, ControlStatus::Partial, nondefault, Vec::new());
    }
    if checked {
        return assessment(
            id,
            ControlStatus::Passed,
            vec![evidence(
                "All discovered registry configs use the default trusted indexes",
                None,
            )],
            Vec::new(),
        );
    }
    assessment(
        id,
        ControlStatus::NotApplicable,
        vec![evidence("No registry configuration files were found", None)],
        Vec::new(),
    )
}

// ---------------------------------------------------------------------------
// dependency-updates
// ---------------------------------------------------------------------------

/// Manifests both Dependabot and Renovate know how to raise a pull request for.
const UPDATE_MANIFESTS: &[&str] = &[
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "composer.json",
];

fn update_config(base: &Path) -> Option<(PathBuf, bool)> {
    const CANDIDATES: &[&str] = &[
        ".github/dependabot.yml",
        ".github/dependabot.yaml",
        "renovate.json",
        "renovate.json5",
        ".github/renovate.json",
        ".github/renovate.json5",
        ".renovaterc",
        ".renovaterc.json",
        ".renovaterc.json5",
    ];
    for name in CANDIDATES {
        let path = base.join(name);
        if path.is_file() {
            let cooldown = name.contains("dependabot")
                && read_text(&path).is_some_and(|c| c.contains("cooldown:"));
            return Some((path, cooldown));
        }
    }
    None
}

pub(super) fn dependency_updates(ctx: &ControlContext<'_>) -> ControlAssessment {
    let id = "dependency-updates";
    let mut rows = Vec::new();
    let (mut with, mut without) = (0usize, 0usize);
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for root in manifest_dirs(ctx) {
        if !UPDATE_MANIFESTS
            .iter()
            .any(|name| root.join(name).is_file())
        {
            continue;
        }
        let base = git_root(&root).unwrap_or_else(|| root.clone());
        if !seen.insert(base.clone()) {
            continue;
        }
        match update_config(&base) {
            Some((path, cooldown)) => {
                with += 1;
                rows.push(evidence(
                    if cooldown {
                        "Update automation configured, and it sets a cooldown"
                    } else {
                        "Update automation configured"
                    },
                    Some(path),
                ));
            }
            None => {
                without += 1;
                rows.push(evidence(
                    "No Dependabot or Renovate configuration was found",
                    Some(base),
                ));
            }
        }
    }
    if with + without == 0 {
        return assessment(
            id,
            ControlStatus::NotApplicable,
            vec![evidence("No dependency manifests were discovered", None)],
            Vec::new(),
        );
    }
    let status = if without == 0 {
        ControlStatus::Passed
    } else if with == 0 {
        ControlStatus::Failed
    } else {
        ControlStatus::Partial
    };
    assessment(id, status, rows, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::super::report_with_home;
    use super::*;
    use crate::model::{Finding, PackageRef, ProviderStatus, ScanReport, Severity};

    /// An advisory source that answered. A source with nothing in its
    /// ecosystem reports this shape too, with `checked_packages` at zero.
    fn answering_source(name: &str, checked: usize) -> ProviderStatus {
        ProviderStatus {
            name: name.to_string(),
            ok: true,
            checked_packages: checked,
            findings: 0,
            message: "queried".to_string(),
        }
    }

    fn report_with_root(home: &Path, root: &Path) -> ScanReport {
        let mut report = report_with_home(home);
        report.roots = vec![root.to_path_buf()];
        report
    }

    /// Mark `root` as a repository root so `git_root`-based probes never walk
    /// above the fixture (the host tempdir can itself sit under a repo).
    fn pin_repo_root(root: &Path) {
        std::fs::create_dir_all(root.join(".git")).unwrap();
    }

    fn npm_package(manifest: &Path) -> PackageRef {
        PackageRef {
            ecosystem: "npm".into(),
            name: "left-pad".into(),
            version: "1.3.0".into(),
            manifest_path: manifest.to_path_buf(),
            line: None,
        }
    }

    fn advisory_finding(category: Category) -> Finding {
        let mut finding = Finding::new(
            "test-advisory",
            "test advisory",
            Severity::High,
            category,
            "test",
            None,
            None,
            "",
            None,
            "",
        );
        finding.package = Some(npm_package(Path::new("package.json")));
        finding
    }

    #[test]
    fn cooldown_reads_project_and_home_config() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("package.json"), "{}\n").unwrap();

        let report = report_with_root(&home, &root);
        let ctx = ControlContext { report: &report };
        assert_eq!(cooldown(&ctx).status, ControlStatus::Failed);

        std::fs::write(root.join(".npmrc"), "min-release-age=7\n").unwrap();
        assert_eq!(cooldown(&ctx).status, ControlStatus::Passed);

        // A zeroed value is the feature switched off, so home config must not
        // rescue it either unless actually set.
        std::fs::write(root.join(".npmrc"), "min-release-age=0\n").unwrap();
        assert_eq!(cooldown(&ctx).status, ControlStatus::Failed);
        std::fs::write(home.join(".npmrc"), "min-release-age=14\n").unwrap();
        assert_eq!(cooldown(&ctx).status, ControlStatus::Passed);
    }

    #[test]
    fn cooldown_covers_python_via_tool_uv_and_is_not_applicable_without_surfaces() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("py");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"x\"\n[tool.uv]\nexclude-newer = \"7 days\"\n",
        )
        .unwrap();
        let report = report_with_root(&home, &root);
        assert_eq!(
            cooldown(&ControlContext { report: &report }).status,
            ControlStatus::Passed
        );

        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let report = report_with_root(&home, &empty);
        assert_eq!(
            cooldown(&ControlContext { report: &report }).status,
            ControlStatus::NotApplicable
        );
    }

    #[test]
    fn install_scripts_pass_via_home_npmrc_pnpm_allowlist_or_npm12_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("package.json"), "{}\n").unwrap();

        let report = report_with_root(&home, &root);
        let ctx = ControlContext { report: &report };
        assert_eq!(install_scripts(&ctx).status, ControlStatus::Failed);

        std::fs::write(home.join(".npmrc"), "ignore-scripts=true\n").unwrap();
        assert_eq!(install_scripts(&ctx).status, ControlStatus::Passed);
        std::fs::remove_file(home.join(".npmrc")).unwrap();

        std::fs::write(
            root.join("pnpm-workspace.yaml"),
            "onlyBuiltDependencies:\n  - esbuild\n",
        )
        .unwrap();
        assert_eq!(install_scripts(&ctx).status, ControlStatus::Passed);
        std::fs::remove_file(root.join("pnpm-workspace.yaml")).unwrap();

        std::fs::write(
            root.join("package.json"),
            "{\"allowScripts\": {\"esbuild\": true}}\n",
        )
        .unwrap();
        assert_eq!(install_scripts(&ctx).status, ControlStatus::Passed);
    }

    #[test]
    fn lockfile_present_requires_a_sibling_or_workspace_lock() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        pin_repo_root(&root);
        std::fs::write(root.join("package.json"), "{}\n").unwrap();

        let report = report_with_root(&home, &root);
        let ctx = ControlContext { report: &report };
        assert_eq!(lockfile_present(&ctx).status, ControlStatus::Failed);

        std::fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: 9\n").unwrap();
        assert_eq!(lockfile_present(&ctx).status, ControlStatus::Passed);
    }

    #[test]
    fn cargo_libraries_are_exempt_from_lockfile_present_but_binaries_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("crate");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        pin_repo_root(&root);
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        std::fs::write(root.join("src/lib.rs"), "\n").unwrap();

        let report = report_with_root(&home, &root);
        let ctx = ControlContext { report: &report };
        assert_eq!(lockfile_present(&ctx).status, ControlStatus::NotApplicable);

        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        assert_eq!(lockfile_present(&ctx).status, ControlStatus::Failed);

        std::fs::write(root.join("Cargo.lock"), "\n").unwrap();
        assert_eq!(lockfile_present(&ctx).status, ControlStatus::Passed);
    }

    #[test]
    fn frozen_install_grades_ci_install_commands() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("proj");
        let workflows = root.join(".github/workflows");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&workflows).unwrap();

        let report = report_with_root(&home, &root);
        let ctx = ControlContext { report: &report };
        assert_eq!(frozen_install(&ctx).status, ControlStatus::NotApplicable);

        std::fs::write(workflows.join("ci.yml"), "steps:\n  - run: npm install\n").unwrap();
        assert_eq!(frozen_install(&ctx).status, ControlStatus::Failed);

        std::fs::write(workflows.join("ci.yml"), "steps:\n  - run: npm ci\n").unwrap();
        assert_eq!(frozen_install(&ctx).status, ControlStatus::Passed);

        // Global tool installs do not touch a lockfile and must not fail CI.
        std::fs::write(
            workflows.join("ci.yml"),
            "steps:\n  - run: npm install -g pnpm\n",
        )
        .unwrap();
        assert_eq!(frozen_install(&ctx).status, ControlStatus::NotApplicable);
    }

    #[test]
    fn frozen_install_reads_package_json_scripts() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            "{\"scripts\": {\"postinstall\": \"npm install --prefix client\"}}\n",
        )
        .unwrap();
        let report = report_with_root(&home, &root);
        assert_eq!(
            frozen_install(&ControlContext { report: &report }).status,
            ControlStatus::Failed
        );
    }

    #[test]
    fn registry_scoping_fails_on_extra_index_url_and_flags_nondefault_registries() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&root).unwrap();

        std::fs::write(
            root.join("pip.conf"),
            "[global]\nextra-index-url = https://internal.example.com/simple\n",
        )
        .unwrap();
        let report = report_with_root(&home, &root);
        let ctx = ControlContext { report: &report };
        assert_eq!(registry_scoping(&ctx).status, ControlStatus::Failed);
        std::fs::remove_file(root.join("pip.conf")).unwrap();

        std::fs::write(
            root.join(".npmrc"),
            "registry=https://npm.corp.example.com\n",
        )
        .unwrap();
        assert_eq!(registry_scoping(&ctx).status, ControlStatus::Partial);

        std::fs::write(
            root.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        assert_eq!(registry_scoping(&ctx).status, ControlStatus::Passed);

        std::fs::write(
            root.join(".npmrc"),
            "registry=http://npm.corp.example.com\n",
        )
        .unwrap();
        assert_eq!(registry_scoping(&ctx).status, ControlStatus::Failed);
    }

    #[test]
    fn dependency_updates_looks_for_dependabot_or_renovate() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("proj");
        std::fs::create_dir_all(root.join(".github")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        pin_repo_root(&root);
        std::fs::write(root.join("package.json"), "{}\n").unwrap();

        let report = report_with_root(&home, &root);
        let ctx = ControlContext { report: &report };
        assert_eq!(dependency_updates(&ctx).status, ControlStatus::Failed);

        std::fs::write(
            root.join(".github/dependabot.yml"),
            "updates:\n  - package-ecosystem: npm\n    cooldown:\n      default-days: 7\n",
        )
        .unwrap();
        let result = dependency_updates(&ctx);
        assert_eq!(result.status, ControlStatus::Passed);
        assert!(result.evidence[0].summary.contains("cooldown"));
    }

    #[test]
    fn manifests_below_the_project_root_still_count_as_discovered() {
        // Probing only the root reports a repo whose manifests live in
        // subdirectories as having no dependencies at all, on a machine where
        // the scan just parsed them.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let root = dir.path().join("proj");
        let service = root.join("services/api");
        std::fs::create_dir_all(&service).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        pin_repo_root(&root);
        std::fs::write(service.join("package.json"), "{}\n").unwrap();
        std::fs::write(service.join("package-lock.json"), "{}\n").unwrap();

        let mut report = report_with_root(&home, &root);
        report.packages = vec![npm_package(&service.join("package-lock.json"))];
        let ctx = ControlContext { report: &report };
        assert_eq!(dependency_updates(&ctx).status, ControlStatus::Failed);
        assert_eq!(lockfile_present(&ctx).status, ControlStatus::Passed);
    }

    #[test]
    fn dependency_security_is_vulnerability_only_and_malware_goes_to_malicious_packages() {
        let mut report = ScanReport::new(
            Vec::new(),
            vec![npm_package(Path::new("package.json"))],
            vec![advisory_finding(Category::Malware)],
            Vec::new(),
        );
        report
            .findings
            .push(advisory_finding(Category::Vulnerability));
        let ctx = ControlContext { report: &report };
        let security = dependency_security(&ctx);
        assert_eq!(security.status, ControlStatus::Failed);
        assert_eq!(security.finding_ids.len(), 1);
        let malicious = malicious_packages(&ctx);
        assert_eq!(malicious.status, ControlStatus::Failed);
        assert_eq!(malicious.finding_ids.len(), 1);

        let mut clean = ScanReport::new(
            Vec::new(),
            vec![npm_package(Path::new("package.json"))],
            Vec::new(),
            vec![answering_source("OSV.dev", 1)],
        );
        let ctx = ControlContext { report: &clean };
        assert_eq!(dependency_security(&ctx).status, ControlStatus::Passed);
        assert_eq!(malicious_packages(&ctx).status, ControlStatus::Passed);

        clean.providers.clear();
        let ctx = ControlContext { report: &clean };
        assert_eq!(dependency_security(&ctx).status, ControlStatus::Unknown);

        let empty = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let ctx = ControlContext { report: &empty };
        assert_eq!(
            malicious_packages(&ctx).status,
            ControlStatus::NotApplicable
        );
    }

    /// The failure a security tool cannot have: an unreachable advisory
    /// database produces the same empty finding list as a clean machine, so
    /// husk must not read the silence as an all-clear.
    #[test]
    fn an_advisory_source_that_could_not_answer_never_reads_as_clean() {
        let mut report = ScanReport::new(
            Vec::new(),
            vec![npm_package(Path::new("package.json"))],
            Vec::new(),
            vec![
                answering_source("OSV.dev", 1),
                ProviderStatus {
                    name: "GitHub Advisory Database".to_string(),
                    ok: false,
                    checked_packages: 1,
                    findings: 0,
                    message: "rate limited".to_string(),
                },
            ],
        );

        for control in [dependency_security, malicious_packages] {
            let assessment = control(&ControlContext { report: &report });
            assert_eq!(
                assessment.status,
                ControlStatus::Unknown,
                "a partly answered scan cannot assert that nothing matched"
            );
            let said = assessment
                .evidence
                .iter()
                .map(|row| row.summary.clone())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                said.contains("only partly checked") && said.contains("GitHub Advisory Database"),
                "the reader has to be told what went unchecked, got: {said}"
            );
            assert!(
                !said.contains("none matched"),
                "an unchecked scan must not borrow the wording of a clean one"
            );
        }

        // Findings do not make the gap disappear: the list is still partial,
        // and a reader takes a finding list as exhaustive unless told.
        report
            .findings
            .push(advisory_finding(Category::Vulnerability));
        let assessment = dependency_security(&ControlContext { report: &report });
        assert_eq!(assessment.status, ControlStatus::Failed);
        assert!(
            assessment.evidence[0].summary.contains("may be incomplete"),
            "a partial scan must say so above its findings"
        );
    }

    /// An offline scan is a deliberate choice. It reports "not checked" plainly
    /// rather than as a provider failure, and still never reports clean.
    ///
    /// `--offline` does not leave the provider list empty: the scan records one
    /// succeeding row saying it skipped the fan-out. Reading that as a source
    /// that answered is exactly how an offline scan came to certify a machine
    /// nothing had looked at, so coverage is judged on packages actually
    /// checked, never on the presence of a row.
    #[test]
    fn an_offline_scan_reports_not_checked_rather_than_clean() {
        let offline = ProviderStatus {
            name: "online providers".to_string(),
            ok: true,
            checked_packages: 0,
            findings: 0,
            message: "skipped because --offline was used".to_string(),
        };
        for providers in [Vec::new(), vec![offline]] {
            let report = ScanReport::new(
                Vec::new(),
                vec![npm_package(Path::new("package.json"))],
                Vec::new(),
                providers,
            );
            let assessment = dependency_security(&ControlContext { report: &report });
            assert_eq!(assessment.status, ControlStatus::Unknown);
            let said = assessment
                .evidence
                .iter()
                .map(|row| row.summary.clone())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                said.contains("were not checked") && said.contains("no advisory database"),
                "got: {said}"
            );
            assert!(
                !said.contains("none matched"),
                "an unchecked scan must not borrow the wording of a clean one"
            );
        }
    }

    /// A source reporting `ok` after checking nothing (the Arch feed with no
    /// pacman packages) must not by itself count as coverage, but it also must
    /// not mask a source that did check.
    #[test]
    fn coverage_comes_from_packages_checked_not_from_a_row_existing() {
        let report = ScanReport::new(
            Vec::new(),
            vec![npm_package(Path::new("package.json"))],
            Vec::new(),
            vec![
                answering_source("Arch Security", 0),
                answering_source("OSV.dev", 1),
            ],
        );
        assert_eq!(
            dependency_security(&ControlContext { report: &report }).status,
            ControlStatus::Passed
        );
    }

    /// A lockfile only protects the machines that receive it, so an existing
    /// but uncommitted lock is as much a failure as a missing one.
    #[test]
    fn lockfile_present_requires_the_lock_to_be_committed() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let git = |args: &[&str]| {
            let ok = crate::gitcmd::git_command()
                .args(["-C", &repo.to_string_lossy()])
                .args(args)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false);
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "--quiet"]);
        git(&["config", "user.email", "test@example.com"]);
        git(&["config", "user.name", "test"]);
        std::fs::write(repo.join("package.json"), "{}\n").unwrap();

        let mut report = ScanReport::new(Vec::new(), Vec::new(), Vec::new(), Vec::new());
        report.roots = vec![repo.clone()];
        let status = || lockfile_present(&ControlContext { report: &report }).status;
        assert_eq!(status(), ControlStatus::Failed, "no lockfile at all");

        std::fs::write(repo.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(status(), ControlStatus::Failed, "lockfile is untracked");

        git(&["add", "package.json", "package-lock.json"]);
        git(&["commit", "--quiet", "-m", "lockfile"]);
        assert_eq!(status(), ControlStatus::Passed);
    }

    #[test]
    fn git_tracking_is_resolved_per_repository_for_tracked_and_untracked_lockfiles() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join("nested")).unwrap();
        let git = |args: &[&str]| {
            let ok = crate::gitcmd::git_command()
                .args(["-C", &repo.to_string_lossy()])
                .args(args)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false);
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "--quiet"]);
        git(&["config", "user.email", "test@example.com"]);
        git(&["config", "user.name", "test"]);

        let tracked = repo.join("Cargo.lock");
        let nested = repo.join("nested").join("yarn.lock");
        let untracked = repo.join("package-lock.json");
        for path in [&tracked, &nested, &untracked] {
            std::fs::write(path, "{}\n").unwrap();
        }
        git(&["add", "Cargo.lock", "nested/yarn.lock"]);
        git(&["commit", "--quiet", "-m", "lockfiles"]);

        // Outside any repository: neither tracked nor untracked, just unknown.
        let outside = dir.path().join("loose.lock");
        std::fs::write(&outside, "{}\n").unwrap();

        let paths = [&tracked, &nested, &untracked, &outside]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let status = git_tracks_all(&paths);

        assert_eq!(status.get(&tracked).copied().flatten(), Some(true));
        assert_eq!(
            status.get(&nested).copied().flatten(),
            Some(true),
            "a lockfile in a subdirectory is still tracked"
        );
        assert_eq!(
            status.get(&untracked).copied().flatten(),
            Some(false),
            "ls-files omits untracked paths, which must not read as tracked"
        );
        assert_eq!(status.get(&outside).copied().flatten(), None);
    }
}
