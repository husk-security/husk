use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

fn default_verification() -> String {
    "automatic".to_string()
}

fn default_scope() -> String {
    "machine".to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuideMeta {
    id: String,
    category: String,
    kind: String,
    severity: String,
    /// Absent exactly when `verification = "manual"`.
    #[serde(default)]
    control: Option<String>,
    /// `automatic` (the default) means a registered control observes this
    /// guide. `manual` means husk cannot observe it at all, so the guide has no
    /// control and is resolved only by the user reading and deciding.
    #[serde(default = "default_verification")]
    verification: String,
    /// `machine` (the default), `project`, or `project-ecosystem`: how many
    /// tasks this one item becomes once the scan says what is on the machine.
    #[serde(default = "default_scope")]
    scope: String,
    #[serde(default)]
    related_rules: Vec<String>,
    #[serde(default)]
    estimate: String,
    solution_name: String,
    #[serde(default)]
    solution_url: String,
    #[serde(default)]
    solution_husk: bool,
}

#[derive(Serialize)]
struct Step {
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
}

#[derive(Serialize)]
struct OptionEntry {
    name: String,
    recommended: bool,
    note: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    steps: Vec<Step>,
}

#[derive(Serialize)]
struct Source {
    title: String,
    url: String,
}

#[derive(Serialize)]
struct Solution {
    name: String,
    url: String,
    husk: bool,
}

#[derive(Serialize)]
struct GuideTask {
    id: String,
    category: String,
    kind: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    control: Option<String>,
    verification: String,
    scope: String,
    related_rules: Vec<String>,
    title: String,
    why: String,
    problem: String,
    estimate: String,
    steps: Vec<Step>,
    options: Vec<OptionEntry>,
    sources: Vec<Source>,
    solution: Solution,
}

/// When the `web` feature is enabled, `rust-embed` bakes `web/dist/` into the
/// binary at compile time, so the built Vite front-end must already exist.
///
/// There are exactly two builds, gated by the single `web` Cargo feature:
///
/// * **`cargo build`** (default features, `web` on): embeds the *real*
///   `web/dist/`, so the front-end must be built first. A missing or empty
///   `web/dist` is a hard build error with an actionable message (below).
/// * **`cargo build --no-default-features`**: CLI + TUI only, no web feature,
///   no front-end needed; this script does nothing.
///
/// CI and release builds run the Vite build *before* compiling (via the
/// `build-web` composite action), so `web/dist/index.html` already exists and
/// the real assets are embedded unchanged. There is deliberately no third
/// "placeholder" state: a `web`-feature binary always serves the real UI.
fn main() {
    // A build script that prints no `rerun-if-changed` line is re-run on every
    // build. With the `web` feature off we emit none below, so set a self-
    // referential baseline to keep TUI-only / Nix builds from re-running it.
    println!("cargo:rerun-if-changed=build.rs");
    compile_guides();
    if std::env::var_os("CARGO_FEATURE_WEB").is_none() {
        return;
    }

    let dist = Path::new("web/dist");
    let index = dist.join("index.html");

    // Reject a symlinked build target before reading anything. A crafted
    // checkout could point `web/dist` or its `index.html` outside the
    // repository; refuse rather than embed assets from a redirected path.
    reject_symlink(dist);
    reject_symlink(&index);

    println!("cargo:rerun-if-changed=web/dist");

    // A missing/empty dist is a hard error, never a warning-and-continue, so a
    // `web`-feature binary can never ship without its UI.
    let has_index = std::fs::metadata(&index)
        .map(|m| m.is_file() && m.len() > 0)
        .unwrap_or(false);
    if !has_index {
        // Surface the guidance as a cargo warning too, visible even when the
        // panic message is buried.
        println!(
            "cargo:warning=husk: the `web` feature embeds web/dist, which is missing. \
             Build the web UI first: npm --prefix web ci && npm --prefix web run build \
             (or build the CLI/TUI only: cargo build --no-default-features)."
        );
        panic!(
            "husk: the `web` feature embeds web/dist, which is missing.\n  \
             Build the web UI first:  npm --prefix web ci && npm --prefix web run build\n  \
             Or build the CLI/TUI only: cargo build --no-default-features"
        );
    }
}

fn compile_guides() {
    let dir = Path::new("guides");
    println!("cargo:rerun-if-changed=guides");
    let mut paths = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("md"))
        .filter(|path| path.file_name().and_then(|name| name.to_str()) != Some("README.md"))
        .collect::<Vec<_>>();
    paths.sort();

    let mut tasks = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
        let task = parse_guide(&path);
        assert!(
            ids.insert(task.id.clone()),
            "duplicate guide id `{}`",
            task.id
        );
        tasks.push(task);
    }
    assert!(!tasks.is_empty(), "guides/ must contain Markdown guides");

    validate_controls(&tasks);

    let out =
        PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("guide_catalog.json");
    fs::write(&out, serde_json::to_vec(&tasks).expect("serialize guides"))
        .unwrap_or_else(|err| panic!("write {}: {err}", out.display()));
}

/// Every guide's `control` must name a real entry in the `GuideControl`
/// registry. Without this, a typo compiles fine and silently degrades the guide
/// to a permanent `Unknown` status at runtime, so the check is a build failure
/// rather than a test: a broken binary must not be produceable at all.
///
/// The registry is Rust source that cannot be imported from a build script, so
/// the ids are lifted textually from the `control("<id>", ...)` registrations.
/// The extraction is fail-closed: if the registration syntax ever changes, no
/// ids are found and the build stops with the message below instead of quietly
/// passing.
fn validate_controls(tasks: &[GuideTask]) {
    let source_path = Path::new("src/guide/control/mod.rs");
    println!("cargo:rerun-if-changed={}", source_path.display());
    let source = fs::read_to_string(source_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", source_path.display()));

    // rustfmt wraps long registrations, so the id can sit on the line after
    // `control(`. Skip whitespace between the paren and the opening quote
    // rather than requiring them to be adjacent.
    let registered = source
        .match_indices("control(")
        .filter_map(|(at, marker)| {
            let rest = source[at + marker.len()..].trim_start();
            let literal = rest.strip_prefix('"')?;
            literal.find('"').map(|end| literal[..end].to_string())
        })
        .collect::<std::collections::HashSet<_>>();

    assert!(
        !registered.is_empty(),
        "{} yielded no control registrations. The registry syntax changed; \
         update validate_controls in build.rs so guide controls stay verified.",
        source_path.display()
    );

    for task in tasks {
        let Some(control) = &task.control else {
            continue;
        };
        assert!(
            registered.contains(control),
            "guide `{}` names control `{control}`, which is not registered in {}. \
             Register it, or fix the name: an unregistered control never runs and \
             the guide would ship stuck on `unknown`.",
            task.id,
            source_path.display()
        );
    }

    let used = tasks
        .iter()
        .filter_map(|task| task.control.clone())
        .collect::<std::collections::HashSet<_>>();
    let mut orphans = registered.difference(&used).cloned().collect::<Vec<_>>();
    orphans.sort();
    assert!(
        orphans.is_empty(),
        "controls registered in {} with no guide in guides/: {}. Every control \
         exists to back a guide; add the guide or drop the control.",
        source_path.display(),
        orphans.join(", ")
    );
}

fn parse_guide(path: &Path) -> GuideTask {
    let source =
        fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let rest = source
        .strip_prefix("+++\n")
        .unwrap_or_else(|| panic!("{} must start with TOML frontmatter", path.display()));
    let (frontmatter, body) = rest
        .split_once("\n+++\n")
        .unwrap_or_else(|| panic!("{} has unterminated frontmatter", path.display()));
    let meta: GuideMeta = toml::from_str(frontmatter)
        .unwrap_or_else(|err| panic!("parse {} frontmatter: {err}", path.display()));
    assert!(
        matches!(meta.kind.as_str(), "baseline" | "recommendation"),
        "{} has invalid guide kind `{}`",
        path.display(),
        meta.kind
    );
    assert!(
        matches!(
            meta.severity.as_str(),
            "critical" | "high" | "medium" | "low" | "info"
        ),
        "{} has invalid severity `{}`",
        path.display(),
        meta.severity
    );
    assert!(
        meta.id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-'),
        "{} has invalid id `{}`",
        path.display(),
        meta.id
    );
    assert!(
        matches!(meta.verification.as_str(), "automatic" | "manual"),
        "{} has verification `{}`; expected `automatic` or `manual`",
        path.display(),
        meta.verification
    );
    assert!(
        matches!(
            meta.scope.as_str(),
            "machine" | "project" | "project-ecosystem"
        ),
        "{} has scope `{}`; expected `machine`, `project`, or `project-ecosystem`",
        path.display(),
        meta.scope
    );
    // A split is driven by the findings a control attached, so an item husk
    // cannot observe has nothing to split along.
    assert!(
        meta.scope == "machine" || meta.verification == "automatic",
        "{} is verification `manual` but declares scope `{}`. A scoped item is \
         split by the findings its control attached, and a manual item has no \
         control.",
        path.display(),
        meta.scope
    );
    // A guide is either observed by a registered control or explicitly manual.
    // Both at once would claim a verification husk does not perform; neither
    // would leave the guide with no way to ever resolve.
    let control = meta
        .control
        .as_ref()
        .map(|control| control.trim())
        .filter(|control| !control.is_empty());
    match (meta.verification.as_str(), control) {
        ("automatic", None) => panic!(
            "{} is verification `automatic` but names no control. Give it a \
             registered control, or set verification = \"manual\" if husk cannot \
             observe it.",
            path.display()
        ),
        ("manual", Some(control)) => panic!(
            "{} is verification `manual` but still names control `{control}`. \
             Manual guides have no control: husk cannot check them, so they are \
             resolved by the user alone. Remove the control field.",
            path.display()
        ),
        _ => {}
    }
    assert!(
        !meta.solution_name.trim().is_empty(),
        "{} needs solution_name",
        path.display()
    );
    let lines = body.lines().collect::<Vec<_>>();

    let title = lines
        .iter()
        .find_map(|line| line.strip_prefix("# "))
        .unwrap_or_else(|| panic!("{} needs a # title", path.display()))
        .to_string();
    let why_idx = lines
        .iter()
        .position(|line| line.starts_with("> "))
        .unwrap_or_else(|| panic!("{} needs a > risk summary", path.display()));
    let why = lines[why_idx].trim_start_matches("> ").to_string();
    let steps_heading = heading(&lines, "## Steps", path);
    let problem = join_text(&lines[why_idx + 1..steps_heading]);
    assert!(!problem.is_empty(), "{} needs problem text", path.display());

    let options_heading = lines.iter().position(|line| *line == "## Options");
    let sources_heading = lines.iter().position(|line| *line == "## Sources");
    let steps_end = options_heading.or(sources_heading).unwrap_or(lines.len());
    let steps = parse_steps(&lines[steps_heading + 1..steps_end], path);
    assert!(
        !steps.is_empty(),
        "{} needs at least one step",
        path.display()
    );

    let options = options_heading
        .map(|start| {
            parse_options(
                &lines[start + 1..sources_heading.unwrap_or(lines.len())],
                path,
            )
        })
        .unwrap_or_default();
    let sources = sources_heading
        .map(|start| parse_sources(&lines[start + 1..], path))
        .unwrap_or_default();
    assert!(
        !sources.is_empty(),
        "{} needs at least one source",
        path.display()
    );

    GuideTask {
        id: meta.id,
        category: meta.category,
        kind: meta.kind,
        severity: meta.severity,
        control: control.map(str::to_string),
        verification: meta.verification,
        scope: meta.scope,
        related_rules: meta.related_rules,
        title,
        why,
        problem,
        estimate: meta.estimate,
        steps,
        options,
        sources,
        solution: Solution {
            name: meta.solution_name,
            url: meta.solution_url,
            husk: meta.solution_husk,
        },
    }
}

fn heading(lines: &[&str], wanted: &str, path: &Path) -> usize {
    lines
        .iter()
        .position(|line| *line == wanted)
        .unwrap_or_else(|| panic!("{} needs {wanted}", path.display()))
}

fn join_text(lines: &[&str]) -> String {
    lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn parse_steps(lines: &[&str], path: &Path) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim_start();
        let Some((number, text)) = line.split_once(". ") else {
            i += 1;
            continue;
        };
        if number.parse::<usize>().is_err() {
            i += 1;
            continue;
        }
        let mut step = Step {
            text: text.trim().to_string(),
            command: None,
            platform: None,
        };
        i += 1;
        while i < lines.len() {
            let current = lines[i].trim();
            if current
                .split_once(". ")
                .is_some_and(|(n, _)| n.parse::<usize>().is_ok())
            {
                break;
            }
            if let Some(platform) = current.strip_prefix("Platform: ") {
                step.platform = Some(platform.to_string());
                i += 1;
                continue;
            }
            if current == "```command" {
                i += 1;
                let mut command = Vec::new();
                while i < lines.len() && lines[i].trim() != "```" {
                    command.push(lines[i]);
                    i += 1;
                }
                assert!(
                    i < lines.len(),
                    "{} has an unclosed command block",
                    path.display()
                );
                step.command = Some(command.join("\n").trim().to_string());
            }
            i += 1;
        }
        steps.push(step);
    }
    steps
}

fn parse_options(lines: &[&str], path: &Path) -> Vec<OptionEntry> {
    let starts = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("### ") && !line.starts_with("#### "))
        .map(|(idx, _)| idx)
        .collect::<Vec<_>>();
    starts
        .iter()
        .enumerate()
        .map(|(position, start)| {
            let end = starts.get(position + 1).copied().unwrap_or(lines.len());
            let chunk = &lines[start + 1..end];
            let raw_name = lines[*start].trim_start_matches("### ");
            let recommended = raw_name.ends_with(" [recommended]");
            let name = raw_name.trim_end_matches(" [recommended]").to_string();
            let steps_heading = chunk.iter().position(|line| *line == "#### Steps");
            let prose_end = steps_heading.unwrap_or(chunk.len());
            let url = chunk[..prose_end]
                .iter()
                .find_map(|line| line.trim().strip_prefix("URL: "))
                .map(str::to_string);
            let note = chunk[..prose_end]
                .iter()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty() && !line.starts_with("URL: "))
                .collect::<Vec<_>>()
                .join("\n\n");
            assert!(
                !note.is_empty(),
                "{} option `{name}` needs prose",
                path.display()
            );
            let steps = steps_heading
                .map(|idx| parse_steps(&chunk[idx + 1..], path))
                .unwrap_or_default();
            OptionEntry {
                name,
                recommended,
                note,
                url,
                steps,
            }
        })
        .collect()
}

fn parse_sources(lines: &[&str], path: &Path) -> Vec<Source> {
    lines
        .iter()
        .filter_map(|line| line.trim().strip_prefix("- ["))
        .map(|line| {
            let (title, url) = line
                .rsplit_once("](")
                .unwrap_or_else(|| panic!("{} has malformed source `{line}`", path.display()));
            Source {
                title: title.to_string(),
                url: url.trim_end_matches(')').to_string(),
            }
        })
        .collect()
}

/// Fail the build if `path` exists and is a symlink. `web/dist` and its
/// `index.html` must be real paths inside the repository, not links that could
/// redirect the embed to assets outside the build directory.
fn reject_symlink(path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        panic!(
            "refusing to build: {} is a symlink; web/dist and its index.html must be real \
             paths inside the repository, not links that could redirect the build read",
            path.display()
        );
    }
}
