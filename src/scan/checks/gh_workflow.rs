//! GitHub Actions workflow and composite-action risks.
//!
//! Line/substring oriented on purpose: workflows are small, hand-written YAML,
//! and a bounded scan of key lines and scalar blocks keeps the detector cheap
//! and predictable without a full YAML model.

use super::util::{find_line, is_full_sha, line_for_offset, snippet_at, trim_evidence};
use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Rule, RuleId};
use regex::Regex;
use std::borrow::Cow;
use std::path::Path;
use std::sync::OnceLock;

pub struct GithubWorkflow;

macro_rules! rule {
    ($id:literal, $title:literal, $sev:expr) => {
        Rule {
            id: RuleId::lit($id),
            title: Cow::Borrowed($title),
            category: Category::LifecycleScript,
            default_severity: $sev,
            rationale: Cow::Borrowed(""),
        }
    };
}

static RULES: &[Rule] = &[
    rule!(
        "gha-pull-request-target",
        "pull_request_target checks out untrusted fork code",
        Severity::Critical
    ),
    rule!(
        "gha-write-all",
        "GitHub Actions grants write-all permissions",
        Severity::High
    ),
    rule!(
        "gha-unpinned-action",
        "GitHub Action is not pinned to a commit SHA",
        Severity::Medium
    ),
    rule!(
        "gha-curl-shell",
        "Workflow pipes network content into a shell",
        Severity::High
    ),
    rule!(
        "gha-event-injection",
        "Workflow interpolates event input into a shell command",
        Severity::High
    ),
    rule!(
        "gha-missing-permissions",
        "Workflow sets no explicit permissions",
        Severity::Medium
    ),
    rule!(
        "gha-persist-credentials",
        "actions/checkout leaves the workflow token in the workspace",
        Severity::Medium
    ),
    rule!(
        "gha-secrets-inherit",
        "Workflow passes the entire secrets context",
        Severity::High
    ),
    rule!(
        "gha-self-hosted-fork",
        "Self-hosted runner is reachable from pull requests",
        Severity::High
    ),
    rule!(
        "gha-publish-token",
        "Publish workflow uses a long-lived registry token",
        Severity::High
    ),
    rule!(
        "gha-cache-in-publish",
        "Cache is enabled in a publishing workflow",
        Severity::Medium
    ),
];

fn is_github_workflow(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yml" | "yaml")
    ) && super::util::path_contains(path, "workflows")
        && super::util::path_contains(path, ".github")
}

/// Composite/JS action manifests. Only the template-injection rule runs on
/// them: their `runs.steps[].run` blocks execute with the calling workflow's
/// privileges (the Ultralytics injection lived in exactly such a step).
fn is_composite_action(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("action.yml" | "action.yaml")
    )
}

fn uses_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)^\s*(?:-\s*)?uses:\s*([^@\s#]+)@([^\s#]+)").expect("valid regex")
    })
}
fn pipe_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(curl|wget)[^|\n]{0,120}\|\s*(bash|sh)").expect("valid regex")
    })
}
/// Attacker-controllable expression contexts: any `github.event.*` field plus
/// the branch-derived `head_ref`/`ref_name` (branch names admit `$IFS`
/// payloads because they cannot contain spaces).
fn injection_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\$\{\{[^}]*github\.(event\.|head_ref|ref_name)").expect("valid regex")
    })
}
/// A checkout `ref:` pointing at the pull request's head (the pwn-request
/// ingredient that makes `pull_request_target` dangerous).
fn head_checkout_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"ref:[^\n#]*(github\.event\.pull_request\.head|github\.head_ref)")
            .expect("valid regex")
    })
}
fn permissions_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*permissions:").expect("valid regex"))
}
fn persist_false_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"persist-credentials:\s*['"]?false"#).expect("valid regex"))
}
fn workspace_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?m)^\s*-?\s*path:\s*['"]?(\.|\./|\$\{\{\s*github\.workspace\s*\}\}/?)['"]?\s*$"#,
        )
        .expect("valid regex")
    })
}
fn secrets_inherit_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*secrets:\s*inherit\s*$").expect("valid regex"))
}
fn whole_secrets_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)tojson\(\s*secrets\s*\)|\$\{\{\s*secrets\s*\}\}").expect("valid regex")
    })
}
fn self_hosted_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*runs-on:[^\n]*self-hosted").expect("valid regex"))
}
fn publish_cmd_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(npm|pnpm|yarn)\s+publish|twine\s+upload|uv\s+publish|maturin\s+publish|cargo\s+publish|gh\s+release\s+(create|upload)",
        )
        .expect("valid regex")
    })
}
fn publish_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"secrets\.(NPM_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|PYPI_API_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|CARGO_REGISTRY_TOKEN|CRATES_IO_TOKEN)",
        )
        .expect("valid regex")
    })
}
fn id_token_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"id-token:\s*write").expect("valid regex"))
}
fn cache_action_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*(?:-\s*)?uses:\s*actions/cache@").expect("valid regex"))
}
fn setup_cache_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*cache:\s*(\S+)").expect("valid regex"))
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// `run:` / `script:` scalar blocks: the inline value plus every following
/// line indented deeper than the key line. Returns the 1-based line of the key
/// with each block, so findings point at the offending step.
fn run_blocks(contents: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = contents.lines().collect();
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let key = line.trim_start().trim_start_matches("- ");
        if key.starts_with("run:") || key.starts_with("script:") {
            let indent = indent_of(line);
            let mut block = key
                .split_once(':')
                .map(|(_, value)| value.trim())
                .unwrap_or("")
                .to_string();
            let mut j = i + 1;
            while j < lines.len() {
                let next = lines[j];
                if !next.trim().is_empty() && indent_of(next) <= indent {
                    break;
                }
                block.push('\n');
                block.push_str(next.trim_start());
                j += 1;
            }
            blocks.push((i + 1, block));
            i = j;
        } else {
            i += 1;
        }
    }
    blocks
}

/// The top-level `on:` trigger declaration, so trigger checks do not match
/// the word `pull_request` inside an unrelated script line.
fn trigger_block(contents: &str) -> String {
    let lines: Vec<&str> = contents.lines().collect();
    let Some(start) = lines.iter().position(|line| {
        indent_of(line) == 0
            && (line.starts_with("on:") || line.starts_with("\"on\":") || line.starts_with("'on':"))
    }) else {
        return String::new();
    };
    let mut block = lines[start].to_string();
    for line in &lines[start + 1..] {
        if !line.trim().is_empty() && indent_of(line) == 0 {
            break;
        }
        block.push('\n');
        block.push_str(line);
    }
    block
}

/// The lines of the step containing `start` (the index of its `uses:` line):
/// everything until the next list item at the same level or a dedent.
fn step_window(lines: &[&str], start: usize) -> String {
    let indent = indent_of(lines[start]);
    let mut window = lines[start].to_string();
    for line in &lines[start + 1..] {
        if line.trim().is_empty() {
            continue;
        }
        let line_indent = indent_of(line);
        if line_indent < indent || (line.trim_start().starts_with("- ") && line_indent <= indent) {
            break;
        }
        window.push('\n');
        window.push_str(line);
    }
    window
}

/// Indices of `uses:` lines naming `action` (e.g. "actions/checkout@").
fn uses_lines(lines: &[&str], action: &str) -> Vec<usize> {
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            let key = line.trim_start().trim_start_matches("- ");
            key.starts_with("uses:") && key.contains(action)
        })
        .map(|(idx, _)| idx)
        .collect()
}

fn check_event_injection(path: &Path, contents: &str, out: &mut Vec<Finding>) {
    for (line, block) in run_blocks(contents) {
        if let Some(mat) = injection_re().find(&block) {
            out.push(
                Finding::from_rule("gha-event-injection")
                    .id("gha-event-input")
                    .source("Husk GitHub Actions scanner")
                    .at(path.to_path_buf(), Some(line))
                    .summary(
                        "An attacker-controllable event field is substituted into this shell command before it runs, which is direct command injection.",
                    )
                    .evidence(snippet_at(&block, mat.start()))
                    .recommend(
                        "Bind the expression to a variable under env: and reference it as a quoted shell variable instead of interpolating it into the script.",
                    ),
            );
            return;
        }
    }
}

impl Check for GithubWorkflow {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, ctx: &CheckContext) -> bool {
        is_github_workflow(ctx.path) || is_composite_action(ctx.path)
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        let path = ctx.path;
        let contents = ctx.contents;

        check_event_injection(path, contents, out);
        if !is_github_workflow(path) {
            return;
        }

        let lines: Vec<&str> = contents.lines().collect();
        let triggers = trigger_block(contents);

        if contents.contains("pull_request_target") && head_checkout_re().is_match(contents) {
            out.push(
                Finding::from_rule("gha-pull-request-target")
                    .id("gha-pr-target")
                    .source("Husk GitHub Actions scanner")
                    .at(path.to_path_buf(), find_line(contents, "pull_request_target"))
                    .summary(
                        "pull_request_target runs with base repository secrets and write access, and this workflow checks out the pull request head, so fork code runs in that privileged context.",
                    )
                    .recommend(
                        "Use the pull_request trigger for fork code, or split privileged work into a separate workflow_run stage that never checks out the untrusted head.",
                    ),
            );
        }

        if contents.contains("permissions: write-all") {
            out.push(
                Finding::from_rule("gha-write-all")
                    .id("gha-write-all")
                    .source("Husk GitHub Actions scanner")
                    .at(
                        path.to_path_buf(),
                        find_line(contents, "permissions: write-all"),
                    )
                    .summary("The workflow grants every available GITHUB_TOKEN write permission.")
                    .recommend("Set the smallest explicit permissions needed by each job."),
            );
        } else if !triggers.is_empty() && !permissions_re().is_match(contents) {
            out.push(
                Finding::from_rule("gha-missing-permissions")
                    .id("gha-missing-permissions")
                    .source("Husk GitHub Actions scanner")
                    .at(path.to_path_buf(), None)
                    .summary(
                        "The workflow declares no permissions: key, so the GITHUB_TOKEN inherits the repository default, which is often broad write access.",
                    )
                    .recommend(
                        "Add a top-level permissions: contents: read and grant extra scopes per job only where needed.",
                    ),
            );
        }

        for capture in uses_re().captures_iter(contents) {
            let action = capture.get(1).map(|m| m.as_str()).unwrap_or("");
            let reference = capture.get(2).map(|m| m.as_str()).unwrap_or("");
            if action.starts_with("./") || is_full_sha(reference) {
                continue;
            }
            let line = capture
                .get(0)
                .map(|mat| line_for_offset(contents, mat.start()));
            out.push(
                Finding::from_rule("gha-unpinned-action")
                    .id(format!("gha-unpinned:{action}"))
                    .source("Husk GitHub Actions scanner")
                    .at(path.to_path_buf(), line)
                    .summary(format!(
                        "{action}@{reference} can change when the tag or branch is moved."
                    ))
                    .recommend(
                        "Pin third-party actions to a full commit SHA and review updates intentionally.",
                    ),
            );
        }

        if let Some(mat) = pipe_re().find(contents) {
            out.push(
                Finding::from_rule("gha-curl-shell")
                    .id("gha-curl-shell")
                    .source("Husk GitHub Actions scanner")
                    .at(path.to_path_buf(), Some(line_for_offset(contents, mat.start())))
                    .summary("The workflow executes code directly from the network.")
                    .evidence(trim_evidence(mat.as_str()))
                    .recommend(
                        "Download, checksum, and execute trusted artifacts instead of piping remote content into a shell.",
                    ),
            );
        }

        let unhardened_checkouts: Vec<usize> = uses_lines(&lines, "actions/checkout@")
            .into_iter()
            .filter(|&idx| !persist_false_re().is_match(&step_window(&lines, idx)))
            .collect();
        if let Some(&first) = unhardened_checkouts.first() {
            let uploads_workspace = uses_lines(&lines, "actions/upload-artifact@")
                .into_iter()
                .any(|idx| workspace_path_re().is_match(&step_window(&lines, idx)));
            let mut finding = Finding::from_rule("gha-persist-credentials")
                .id("gha-persist-credentials")
                .source("Husk GitHub Actions scanner")
                .at(path.to_path_buf(), Some(first + 1))
                .summary(
                    "actions/checkout stores the GITHUB_TOKEN in .git/config by default, where every later step and any uploaded copy of the workspace can read it.",
                )
                .recommend(
                    "Set persist-credentials: false under with: on every checkout; steps that must push should supply their own credential explicitly.",
                );
            if uploads_workspace {
                finding = finding.severity(Severity::High).summary(
                    "actions/checkout stores the GITHUB_TOKEN in .git/config and this workflow uploads the workspace as an artifact, which publishes a live token (artifacts are downloadable while the job still runs).",
                );
            }
            out.push(finding);
        }

        let inherit = secrets_inherit_re().find(contents);
        let whole = whole_secrets_re().find(contents);
        if let Some(mat) = inherit.or(whole) {
            out.push(
                Finding::from_rule("gha-secrets-inherit")
                    .id("gha-secrets-inherit")
                    .source("Husk GitHub Actions scanner")
                    .at(path.to_path_buf(), Some(line_for_offset(contents, mat.start())))
                    .summary(
                        "The workflow hands the entire secrets context to called or generated code instead of passing the individual secrets it needs.",
                    )
                    .evidence(snippet_at(contents, mat.start()))
                    .recommend(
                        "Pass each required secret by name to reusable workflows and steps; never secrets: inherit, toJSON(secrets), or a bare secrets context.",
                    ),
            );
        }

        if triggers.contains("pull_request")
            && let Some(mat) = self_hosted_re().find(contents)
        {
            out.push(
                    Finding::from_rule("gha-self-hosted-fork")
                        .id("gha-self-hosted-fork")
                        .source("Husk GitHub Actions scanner")
                        .at(path.to_path_buf(), Some(line_for_offset(contents, mat.start())))
                        .summary(
                            "A self-hosted runner serves a pull-request-triggered workflow. Whether fork PRs actually reach it depends on the repository's approval policy, which is server-side and not visible to a local scan.",
                        )
                        .evidence(snippet_at(contents, mat.start()))
                        .recommend(
                            "Keep pull-request workflows on hosted runners, require approval for all outside collaborators, and make self-hosted runners ephemeral.",
                        ),
                );
        }

        let publishes = publish_cmd_re().is_match(contents);
        let has_id_token = id_token_write_re().is_match(contents);
        if publishes
            && !has_id_token
            && let Some(mat) = publish_token_re().find(contents)
        {
            out.push(
                    Finding::from_rule("gha-publish-token")
                        .id("gha-publish-token")
                        .source("Husk GitHub Actions scanner")
                        .at(path.to_path_buf(), Some(line_for_offset(contents, mat.start())))
                        .summary(
                            "This workflow publishes with a stored long-lived registry token instead of a short-lived OIDC credential (no id-token: write).",
                        )
                        .evidence(snippet_at(contents, mat.start()))
                        .recommend(
                            "Register the workflow as a trusted publisher on the registry, grant permissions: id-token: write, and revoke the stored token.",
                        ),
                );
        }

        let holds_publish_creds = has_id_token || publish_token_re().is_match(contents);
        if holds_publish_creds && publishes {
            let cache_hit = cache_action_re().find(contents).or_else(|| {
                let uses_setup = uses_re()
                    .captures_iter(contents)
                    .any(|cap| cap.get(1).is_some_and(|m| m.as_str().contains("/setup-")));
                if !uses_setup {
                    return None;
                }
                setup_cache_re().captures_iter(contents).find_map(|cap| {
                    let value = cap
                        .get(1)
                        .map(|m| m.as_str().trim_matches(['\'', '"']))
                        .unwrap_or("");
                    (!value.is_empty() && value != "false")
                        .then(|| cap.get(0).expect("whole match"))
                })
            });
            if let Some(mat) = cache_hit {
                out.push(
                    Finding::from_rule("gha-cache-in-publish")
                        .id("gha-cache-in-publish")
                        .source("Husk GitHub Actions scanner")
                        .at(path.to_path_buf(), Some(line_for_offset(contents, mat.start())))
                        .summary(
                            "A build cache is restored inside a workflow that holds publish credentials; a poisoned cache entry becomes part of the published artifact and still receives valid provenance.",
                        )
                        .evidence(snippet_at(contents, mat.start()))
                        .recommend(
                            "Disable actions/cache and setup-* cache options in release and publish workflows; build from clean sources.",
                        ),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run(contents: &str) -> Vec<Finding> {
        run_at("/repo/.github/workflows/ci.yml", contents)
    }

    fn run_at(path: &str, contents: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        let ctx = CheckContext::new(Path::new(path), contents);
        if GithubWorkflow.applies(&ctx) {
            GithubWorkflow.run(&ctx, &mut out);
        }
        out
    }

    fn has_rule(findings: &[Finding], rule: &str) -> bool {
        findings
            .iter()
            .any(|f| f.rule_id.as_ref().is_some_and(|id| id.as_str() == rule))
    }

    #[test]
    fn flags_write_all_and_unpinned() {
        let f = run(
            "on: push\npermissions: write-all\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
        );
        assert!(has_rule(&f, "gha-write-all"));
        assert!(has_rule(&f, "gha-unpinned-action"));
        assert!(!has_rule(&f, "gha-missing-permissions"));
        assert!(f.iter().all(|f| f.category == Category::LifecycleScript));
    }

    #[test]
    fn bare_workflow_filenames_outside_dot_github_are_ignored() {
        for path in ["/x/ansible/main.yml", "/x/main.yaml", "/x/docs/ci.yml"] {
            let ctx = CheckContext::new(Path::new(path), "pull_request_target");
            assert!(!GithubWorkflow.applies(&ctx), "{path} is not a workflow");
        }
        let ctx = CheckContext::new(Path::new("/r/.github/workflows/x.yaml"), "");
        assert!(GithubWorkflow.applies(&ctx));
        let ctx = CheckContext::new(Path::new("/r/.github/actions/greet/action.yml"), "");
        assert!(GithubWorkflow.applies(&ctx));
    }

    #[test]
    fn pull_request_target_requires_head_checkout() {
        let bare = "on:\n  pull_request_target:\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: echo ok\n";
        assert!(!has_rule(&run(bare), "gha-pull-request-target"));

        let pwn = "on:\n  pull_request_target:\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          persist-credentials: false\n";
        let f = run(pwn);
        assert!(has_rule(&f, "gha-pull-request-target"));
        assert!(
            !has_rule(&f, "gha-event-injection"),
            "with: values are not run blocks"
        );
    }

    #[test]
    fn event_injection_only_in_run_blocks() {
        let via_env = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: |\n          echo \"$TITLE\"\n";
        assert!(!has_rule(&run(via_env), "gha-event-injection"));

        let direct = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: |\n          echo \"${{ github.event.pull_request.title }}\"\n";
        assert!(has_rule(&run(direct), "gha-event-injection"));

        let head_ref = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: git checkout ${{ github.head_ref }}\n";
        assert!(has_rule(&run(head_ref), "gha-event-injection"));

        let script = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n        with:\n          script: |\n            console.log(`${{ github.event.issue.title }}`)\n";
        assert!(has_rule(&run(script), "gha-event-injection"));
    }

    #[test]
    fn event_injection_covers_composite_actions() {
        let composite = "name: Greet\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ github.event.discussion.body }}\"\n      shell: bash\n";
        let f = run_at("/repo/.github/actions/greet/action.yml", composite);
        assert!(has_rule(&f, "gha-event-injection"));
        assert!(
            !has_rule(&f, "gha-missing-permissions"),
            "composite actions have no permissions key"
        );
    }

    #[test]
    fn missing_permissions_fires_only_without_any_permissions_key() {
        let none = "on: push\njobs:\n  a:\n    steps:\n      - run: echo ok\n";
        assert!(has_rule(&run(none), "gha-missing-permissions"));

        let job_level = "on: push\njobs:\n  a:\n    permissions:\n      contents: read\n    steps:\n      - run: echo ok\n";
        assert!(!has_rule(&run(job_level), "gha-missing-permissions"));

        let not_a_workflow = "foo: bar\n";
        assert!(!has_rule(&run(not_a_workflow), "gha-missing-permissions"));
    }

    #[test]
    fn persist_credentials_flags_default_checkout_and_escalates_on_upload() {
        let hardened = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - name: Checkout\n        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          persist-credentials: false\n";
        assert!(!has_rule(&run(hardened), "gha-persist-credentials"));

        let default = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n";
        let f = run(default);
        assert!(has_rule(&f, "gha-persist-credentials"));
        assert_eq!(f[0].severity, Severity::Medium);

        let artipacked = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n        with:\n          name: workspace\n          path: .\n";
        let f = run(artipacked);
        let finding = f
            .iter()
            .find(|f| {
                f.rule_id
                    .as_ref()
                    .is_some_and(|id| id.as_str() == "gha-persist-credentials")
            })
            .expect("persist-credentials finding");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn secrets_inherit_and_whole_context_forms() {
        for contents in [
            "on: push\npermissions: {}\njobs:\n  call:\n    uses: ./.github/workflows/reuse.yml\n    secrets: inherit\n",
            "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: echo done\n        env:\n          ALL: ${{ toJSON(secrets) }}\n",
            "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: echo done\n        env:\n          ALL: ${{ secrets }}\n",
        ] {
            assert!(
                has_rule(&run(contents), "gha-secrets-inherit"),
                "{contents}"
            );
        }
        let named = "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: echo done\n        env:\n          TOKEN: ${{ secrets.SOME_TOKEN }}\n";
        assert!(!has_rule(&run(named), "gha-secrets-inherit"));
    }

    #[test]
    fn self_hosted_flagged_only_with_pull_request_trigger() {
        let fork_reachable = "on:\n  pull_request:\njobs:\n  a:\n    runs-on: [self-hosted, linux]\n    permissions: {}\n    steps:\n      - run: echo ok\n";
        assert!(has_rule(&run(fork_reachable), "gha-self-hosted-fork"));

        let push_only = "on:\n  push:\njobs:\n  a:\n    runs-on: self-hosted\n    permissions: {}\n    steps:\n      - run: echo pull_request in a script does not count\n";
        assert!(!has_rule(&run(push_only), "gha-self-hosted-fork"));
    }

    #[test]
    fn publish_token_requires_publish_plus_token_minus_oidc() {
        let token = "on: push\npermissions: {}\njobs:\n  pub:\n    steps:\n      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n";
        assert!(has_rule(&run(token), "gha-publish-token"));

        let oidc = "on: push\npermissions:\n  id-token: write\njobs:\n  pub:\n    steps:\n      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n";
        assert!(!has_rule(&run(oidc), "gha-publish-token"));

        let no_publish = "on: push\npermissions: {}\njobs:\n  test:\n    steps:\n      - run: npm test\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n";
        assert!(!has_rule(&run(no_publish), "gha-publish-token"));
    }

    #[test]
    fn cache_in_publish_needs_cache_plus_credentials() {
        let poisoned = "on: push\npermissions:\n  id-token: write\njobs:\n  pub:\n    steps:\n      - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n        with:\n          path: ~/.npm\n          key: npm\n      - run: npm publish\n";
        assert!(has_rule(&run(poisoned), "gha-cache-in-publish"));

        let setup_cache = "on: push\npermissions: {}\njobs:\n  pub:\n    steps:\n      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020\n        with:\n          cache: npm\n      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n";
        assert!(has_rule(&run(setup_cache), "gha-cache-in-publish"));

        let cache_no_creds = "on: push\npermissions: {}\njobs:\n  test:\n    steps:\n      - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n        with:\n          path: ~/.npm\n          key: npm\n      - run: npm test\n";
        assert!(!has_rule(&run(cache_no_creds), "gha-cache-in-publish"));

        let cache_false = "on: push\npermissions: {}\njobs:\n  pub:\n    steps:\n      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020\n        with:\n          cache: false\n      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n";
        assert!(!has_rule(&run(cache_false), "gha-cache-in-publish"));
    }
}
