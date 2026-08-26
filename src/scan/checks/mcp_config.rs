//! MCP server configuration risks.

use super::util::{find_line, looks_secretish, path_contains, trim_evidence};
use super::{Check, CheckContext};
use crate::model::{Finding, Severity};
use crate::rule::{Category, Rule, RuleId};
use serde_json::Value as JsonValue;
use std::borrow::Cow;
use std::path::Path;

pub struct McpConfig;

macro_rules! rule {
    ($id:literal, $title:literal, $sev:expr) => {
        Rule {
            id: RuleId::lit($id),
            title: Cow::Borrowed($title),
            category: Category::RiskyAgentConfig,
            default_severity: $sev,
            rationale: Cow::Borrowed(""),
        }
    };
}

static RULES: &[Rule] = &[
    rule!(
        "mcp-shell-wrapper",
        "MCP server runs through a shell",
        Severity::High
    ),
    rule!(
        "mcp-unpinned-npx",
        "MCP server uses unpinned npx package",
        Severity::Medium
    ),
    rule!(
        "mcp-plaintext-http",
        "MCP server references plaintext HTTP",
        Severity::Medium
    ),
    rule!(
        "mcp-root-fs",
        "MCP server receives root filesystem access",
        Severity::High
    ),
    rule!(
        "mcp-hardcoded-secret",
        "MCP config contains hardcoded secret",
        Severity::High
    ),
];

fn is_mcp_config(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    matches!(
        file_name,
        "mcp.json" | ".mcp.json" | "claude_desktop_config.json"
    )
}

impl Check for McpConfig {
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn applies(&self, ctx: &CheckContext) -> bool {
        is_mcp_config(ctx.path)
            || (ctx.file_name() == "config.json" && path_contains(ctx.path, ".cursor"))
    }
    fn run(&self, ctx: &CheckContext, out: &mut Vec<Finding>) {
        let path = ctx.path;
        let contents = ctx.contents;
        let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
            return;
        };
        let servers = json
            .get("mcpServers")
            .or_else(|| json.get("servers"))
            .and_then(|value| value.as_object());
        let Some(servers) = servers else {
            return;
        };

        for (server_name, server) in servers {
            let command = server.get("command").and_then(|value| value.as_str());
            let args = server
                .get("args")
                .and_then(|value| value.as_array())
                .map(|args| {
                    args.iter()
                        .filter_map(|arg| arg.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if let Some(command) = command {
                if matches!(
                    command,
                    "sh" | "bash" | "zsh" | "fish" | "cmd" | "powershell" | "pwsh"
                ) || args.iter().any(|arg| *arg == "-c" || *arg == "/c")
                {
                    out.push(
                        Finding::from_rule("mcp-shell-wrapper")
                            .id(format!("mcp-shell:{server_name}"))
                            .source("Husk MCP scanner")
                            .at(path.to_path_buf(), find_line(contents, server_name))
                            .summary(format!(
                                "{server_name} uses a shell command wrapper, making command injection and hidden behavior harder to review."
                            ))
                            .evidence(format!("{command} {}", args.join(" ")).trim().to_string())
                            .recommend(
                                "Use a direct executable path with pinned package versions instead of shell wrappers.",
                            ),
                    );
                }

                if command == "npx" && !args.iter().any(|arg| arg.contains('@')) {
                    out.push(
                        Finding::from_rule("mcp-unpinned-npx")
                            .id(format!("mcp-npx:{server_name}"))
                            .source("Husk MCP scanner")
                            .at(path.to_path_buf(), find_line(contents, server_name))
                            .summary(format!(
                                "{server_name} launches via npx without a pinned package version."
                            ))
                            .evidence(args.join(" "))
                            .recommend(
                                "Pin the package version or vendor the server code before giving it access to local tools.",
                            ),
                    );
                }
            }

            let joined = args.join(" ");
            if joined.contains("http://") {
                out.push(
                    Finding::from_rule("mcp-plaintext-http")
                        .id(format!("mcp-http:{server_name}"))
                        .source("Husk MCP scanner")
                        .at(path.to_path_buf(), find_line(contents, "http://"))
                        .summary(format!("{server_name} references a non-TLS URL."))
                        .evidence(trim_evidence(&joined))
                        .recommend(
                            "Use HTTPS endpoints for remote MCP transports and fetched resources.",
                        ),
                );
            }

            if args.iter().any(|arg| *arg == "/" || arg.ends_with(":/")) {
                out.push(
                    Finding::from_rule("mcp-root-fs")
                        .id(format!("mcp-root-fs:{server_name}"))
                        .source("Husk MCP scanner")
                        .at(path.to_path_buf(), find_line(contents, server_name))
                        .summary(format!(
                            "{server_name} appears to receive root filesystem scope."
                        ))
                        .evidence(args.join(" "))
                        .recommend(
                            "Narrow filesystem MCP servers to specific project directories.",
                        ),
                );
            }

            if let Some(env) = server.get("env").and_then(|value| value.as_object()) {
                for (key, value) in env {
                    if value.as_str().map(looks_secretish).unwrap_or(false) {
                        out.push(
                            Finding::from_rule("mcp-hardcoded-secret")
                                .id(format!("mcp-env-secret:{server_name}:{key}"))
                                .source("Husk MCP scanner")
                                .at(path.to_path_buf(), find_line(contents, key))
                                .summary(format!(
                                    "{server_name} has a hardcoded environment value for {key}."
                                ))
                                .recommend(
                                    "Move MCP credentials into a secret store or inherited environment and rotate exposed values.",
                                ),
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn run(contents: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        McpConfig.run(
            &CheckContext::new(Path::new("/x/mcp.json"), contents),
            &mut out,
        );
        out
    }

    #[test]
    fn flags_shell_wrapped_server() {
        let f = run(r#"{"mcpServers":{"x":{"command":"bash","args":["-c","echo hi"]}}}"#);
        assert!(f.iter().any(|f| f.category == Category::RiskyAgentConfig));
        assert!(
            f.iter()
                .any(|f| f.rule_id.as_ref().unwrap().as_str() == "mcp-shell-wrapper")
        );
    }
}
