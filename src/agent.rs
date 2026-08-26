//! `husk mcp install <agent>`: idempotently register husk's MCP server in a
//! coding agent's config.
//!
//! Each agent reads MCP servers from a JSON or TOML config file under a known
//! key. We read the existing file (if any), upsert just the `husk` entry, and
//! write it back; running twice is a no-op, and unrelated config is preserved.
//! Known agents only: for an unlisted agent we print the snippet instead of
//! guessing a path.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::PathBuf;

/// Deliberately the bare binary, not the `npx husk-sec mcp` form the shipped
/// plugin manifests use. Reaching this code proves husk is already installed
/// and on `PATH`, so routing the user's own binary through npm would be slower
/// and could serve a different version than the one they installed.
fn server_command() -> (&'static str, Vec<&'static str>) {
    ("husk", vec!["mcp"])
}

enum Layout {
    /// JSON file with servers under `obj[key]["husk"] = {command, args, ...}`.
    Json {
        key: &'static str,
        /// Extra fields VS Code wants (`type: stdio`); empty for the rest.
        extra: Vec<(&'static str, Value)>,
    },
    /// Codex `~/.codex/config.toml` with a `[mcp_servers.husk]` table.
    CodexToml,
    /// OpenCode `opencode.json`: `mcp.husk = {type:"local", command:[..], enabled}`.
    /// Its `command` is the whole argv array, not a string + separate `args`.
    OpencodeJson,
}

struct Target {
    path: PathBuf,
    layout: Layout,
}

pub fn install(agent: &str, global: bool, dry_run: bool) -> Result<()> {
    let target = resolve(agent, global)?;
    let (cmd, args) = server_command();

    match &target.layout {
        Layout::Json { key, extra } => {
            let mut root = read_json(&target.path)?;
            let obj = root
                .as_object_mut()
                .context("config root is not a JSON object")?;
            let servers = obj
                .entry((*key).to_string())
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .with_context(|| format!("`{key}` in config is not an object"))?;

            let mut entry = serde_json::Map::new();
            for (k, v) in extra {
                entry.insert((*k).to_string(), v.clone());
            }
            entry.insert("command".to_string(), json!(cmd));
            entry.insert("args".to_string(), json!(args));
            servers.insert("husk".to_string(), Value::Object(entry));

            let text = serde_json::to_string_pretty(&root)? + "\n";
            write_or_print(&target.path, &text, dry_run)
        }
        Layout::CodexToml => {
            let existing = std::fs::read_to_string(&target.path).unwrap_or_default();
            if existing.contains("[mcp_servers.husk]") {
                println!(
                    "husk already registered in {}, nothing to do",
                    target.path.display()
                );
                return Ok(());
            }
            let block = format!(
                "\n[mcp_servers.husk]\ncommand = \"{cmd}\"\nargs = [{}]\n",
                args.iter()
                    .map(|a| format!("\"{a}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let text = format!("{}{block}", existing.trim_end_matches('\n'));
            write_or_print(&target.path, &text, dry_run)
        }
        Layout::OpencodeJson => {
            let mut root = read_json(&target.path)?;
            let obj = root
                .as_object_mut()
                .context("config root is not a JSON object")?;
            let servers = obj
                .entry("mcp".to_string())
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .context("`mcp` in config is not an object")?;

            let mut argv = vec![cmd];
            argv.extend(args);
            servers.insert(
                "husk".to_string(),
                json!({ "type": "local", "command": argv, "enabled": true }),
            );

            let text = serde_json::to_string_pretty(&root)? + "\n";
            write_or_print(&target.path, &text, dry_run)
        }
    }
}

/// Agent ids that `husk mcp install <id>` supports: the set the web UI shows
/// config status for. (Claude Code uses the plugin path, not this command.)
#[cfg(feature = "web")]
pub const INSTALL_AGENTS: &[&str] = &[
    "cursor",
    "vscode",
    "gemini",
    "codex",
    "claude-desktop",
    "opencode",
];

/// Is husk's MCP server already registered for `agent`? Checks both the project
/// (cwd) and global config locations; either one counts. Best-effort: a missing
/// or unparseable config just reads as "not installed", never an error.
///
/// `claude-code` is special: it's the plugin path, not `husk mcp install`, so
/// we detect the installed plugin instead of an MCP config entry.
#[cfg(feature = "web")]
pub fn is_installed(agent: &str) -> bool {
    if agent == "claude-code" {
        return claude_code_plugin_installed();
    }
    [false, true]
        .into_iter()
        .filter_map(|global| resolve(agent, global).ok())
        .any(|t| target_has_husk(&t))
}

/// True when the husk plugin is recorded in Claude Code's installed-plugins
/// registry (`~/.claude/plugins/installed_plugins.json`), keyed `husk@<market>`.
#[cfg(feature = "web")]
fn claude_code_plugin_installed() -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    let path = home.join(".claude/plugins/installed_plugins.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| {
            Some(
                v.get("plugins")?
                    .as_object()?
                    .keys()
                    .any(|k| k.starts_with("husk@")),
            )
        })
        .unwrap_or(false)
}

#[cfg(feature = "web")]
fn target_has_husk(target: &Target) -> bool {
    match &target.layout {
        Layout::Json { key, .. } => read_json(&target.path)
            .ok()
            .and_then(|root| root.get(*key).and_then(|s| s.get("husk")).cloned())
            .is_some(),
        Layout::OpencodeJson => read_json(&target.path)
            .ok()
            .and_then(|root| root.get("mcp").and_then(|s| s.get("husk")).cloned())
            .is_some(),
        Layout::CodexToml => std::fs::read_to_string(&target.path)
            .map(|s| s.contains("[mcp_servers.husk]"))
            .unwrap_or(false),
    }
}

fn resolve(agent: &str, global: bool) -> Result<Target> {
    let home = dirs::home_dir().context("could not locate home directory")?;
    let config = dirs::config_dir().context("could not locate config directory")?;
    let cwd = std::env::current_dir()?;

    let json = |key, extra: Vec<(&'static str, Value)>, path| Target {
        path,
        layout: Layout::Json { key, extra },
    };

    Ok(match agent {
        // Claude Desktop is global-only (no per-project config).
        "claude-desktop" | "claude" => json(
            "mcpServers",
            vec![],
            config.join("Claude").join("claude_desktop_config.json"),
        ),
        "cursor" => {
            let path = if global {
                home.join(".cursor").join("mcp.json")
            } else {
                cwd.join(".cursor").join("mcp.json")
            };
            json("mcpServers", vec![], path)
        }
        "vscode" | "vs-code" | "copilot" => {
            let path = if global {
                config.join("Code").join("User").join("mcp.json")
            } else {
                cwd.join(".vscode").join("mcp.json")
            };
            json("servers", vec![("type", json!("stdio"))], path)
        }
        "gemini" | "gemini-cli" => {
            let path = if global {
                home.join(".gemini").join("settings.json")
            } else {
                cwd.join(".gemini").join("settings.json")
            };
            json("mcpServers", vec![], path)
        }
        // Codex MCP config is global TOML.
        "codex" => Target {
            path: home.join(".codex").join("config.toml"),
            layout: Layout::CodexToml,
        },
        "opencode" => Target {
            path: if global {
                config.join("opencode").join("opencode.json")
            } else {
                cwd.join("opencode.json")
            },
            layout: Layout::OpencodeJson,
        },
        other => bail!(
            "unknown agent `{other}`; supported: claude-desktop, cursor, vscode, gemini, codex, opencode"
        ),
    })
}

fn read_json(path: &PathBuf) -> Result<Value> {
    match std::fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => {
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
        }
        _ => Ok(json!({})),
    }
}

fn write_or_print(path: &PathBuf, text: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("# would write {}\n{text}", path.display());
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    println!("husk registered in {}", path.display());
    println!("note: husk must be on PATH; restart the agent to pick up the server.");
    Ok(())
}
