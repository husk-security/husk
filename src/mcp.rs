//! Model Context Protocol server over stdio.
//!
//! `husk mcp` speaks JSON-RPC 2.0, one message per line, on stdin/stdout so AI
//! agents (Claude Code, Codex, OpenCode, ...) can read scan results from the
//! locally installed husk. Nothing but protocol messages may be written to
//! stdout; diagnostics go to stderr.

use crate::model::{Finding, PackageRef, ScanOptions, ScanReport, Severity};
use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{Value, json};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;

const FALLBACK_PROTOCOL_VERSION: &str = "2025-03-26";
const DEFAULT_FINDING_LIMIT: usize = 50;
const DEFAULT_PACKAGE_LIMIT: usize = 100;
const SCAN_RESULT_FINDING_LIMIT: usize = 20;
/// Cached reports older than this are flagged `stale` so the agent rescans.
const STALE_AFTER_SECONDS: i64 = 86_400;

/// Outgoing messages (responses + progress notifications) flow through this
/// channel to a single writer task, so concurrent handlers never interleave
/// bytes on stdout.
type Outbox = UnboundedSender<Value>;

pub async fn run() -> Result<()> {
    crate::cloud::telemetry::bump_one(crate::cloud::telemetry::counters::MCP_SESSION);
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();

    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(message) = rx.recv().await {
            if write_message(&mut stdout, &message).await.is_err() {
                break;
            }
        }
    });

    // Each request is handled on its own task so a long husk_scan can't block
    // pings or other tool calls.
    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let tx = tx.clone();
        tokio::spawn(async move {
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(message) => handle_message(message, &tx).await,
                Err(err) => Some(error_response(
                    Value::Null,
                    -32700,
                    &format!("parse error: {err}"),
                )),
            };
            if let Some(response) = response {
                let _ = tx.send(response);
            }
        });
    }
    drop(tx);
    let _ = writer.await;
    Ok(())
}

/// `husk mcp --selfcheck`: validate the server can start and report what an
/// agent would see, without entering the protocol loop.
pub fn selfcheck() -> Result<()> {
    let tools = tool_definitions();
    let tool_count = tools.as_array().map(Vec::len).unwrap_or(0);
    let cache_path = crate::cache::report_dir()?;
    let cached = crate::cache::load_any_latest_report()
        .ok()
        .flatten()
        .map(|report| {
            format!(
                "cached scan from {} covering {:?}",
                report.generated_at.to_rfc3339(),
                report.roots
            )
        })
        .unwrap_or_else(|| "no cached scan yet (run `husk scan` first)".to_string());
    println!("husk mcp self-check: OK");
    println!("  protocol:  {FALLBACK_PROTOCOL_VERSION}");
    println!("  version:   {}", env!("CARGO_PKG_VERSION"));
    println!("  tools:     {tool_count}");
    println!("  cache:     {}", cache_path.display());
    println!("  state:     {cached}");
    Ok(())
}

async fn write_message(stdout: &mut tokio::io::Stdout, message: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(message)?;
    bytes.push(b'\n');
    stdout.write_all(&bytes).await?;
    stdout.flush().await?;
    Ok(())
}

async fn handle_message(message: Value, tx: &Outbox) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let params = message.get("params").cloned().unwrap_or(Value::Null);

    // Notifications carry no id and must not get a response.
    let id = id?;
    if method.is_empty() {
        return Some(error_response(id, -32600, "missing method"));
    }

    let result = match method.as_str() {
        "initialize" => Ok(initialize_result(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => tool_call_result(&params, tx).await,
        "prompts/list" => Ok(prompts_list()),
        "prompts/get" => prompts_get(&params),
        "resources/list" => Ok(resources_list()),
        "resources/read" => resources_read(&params),
        _ => {
            return Some(error_response(
                id,
                -32601,
                &format!("method not found: {method}"),
            ));
        }
    };

    Some(finish(id, result))
}

/// Wrap a fallible method result into a JSON-RPC response. Caller mistakes
/// (unknown tool/prompt/resource names, bad arguments) map to -32602 Invalid
/// params; anything else is an internal fault (-32603).
fn finish(id: Value, result: Result<Value>) -> Value {
    match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(err) => {
            let code = if err.downcast_ref::<InvalidParams>().is_some() {
                -32602
            } else {
                -32603
            };
            error_response(id, code, &format!("{err:#}"))
        }
    }
}

/// Typed "the caller's arguments are wrong" error so [`finish`] can answer
/// -32602 Invalid params while genuine internal faults stay -32603.
#[derive(Debug)]
struct InvalidParams(String);

impl std::fmt::Display for InvalidParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidParams {}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

/// Protocol revisions this server implements. `initialize` echoes the client's
/// requested version only when it is one of these; anything unknown gets
/// [`FALLBACK_PROTOCOL_VERSION`] instead of a blind echo, so the server never
/// claims support for a protocol revision it has never seen.
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

fn initialize_result(params: &Value) -> Value {
    let protocol_version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .filter(|requested| SUPPORTED_PROTOCOL_VERSIONS.contains(requested))
        .unwrap_or(FALLBACK_PROTOCOL_VERSION);
    json!({
        "protocolVersion": protocol_version,
        "capabilities": {
            "tools": { "listChanged": false },
            "prompts": { "listChanged": false },
            "resources": { "listChanged": false },
        },
        "serverInfo": {
            "name": "husk",
            "title": "Husk local security scanner",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": "Husk is a developer security scanner. Use husk_status \
            for the latest cached scan summary, husk_findings / husk_packages / \
            husk_guide to inspect scan-backed guidance, and husk_scan to run a fresh \
            scan of specific paths. Use husk_guide to read the security to-do checklist \
            (each task carries evidence and copy-pasteable steps) and husk_guide_update to record \
            read/completed/dismissed decisions. Husk only reads files and writes its own \
            state; perform any actual fixes with your normal (user-permissioned) tools. \
            Unless offline is set, scans send discovered package names and versions to \
            public advisory databases (OSV.dev, npm, PyPI, GitHub).",
    })
}

pub fn tool_definitions() -> Value {
    json!([
        {
            "name": "husk_status",
            "description": "Summarize the latest cached husk scan: when it ran, scanned roots, finding counts by severity, finding counts by category, and online provider status. Run this first to see whether scan data exists.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        },
        {
            "name": "husk_findings",
            "description": "List findings from the latest cached husk scan, sorted by severity. Each finding has an id, title, severity (critical/high/medium/low/info), category (e.g. secret, vulnerability, malware, prompt-injection, risky-agent-config, lifecycle-script), file path, line, summary, and recommendation.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "min_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Only return findings at or above this severity.",
                    },
                    "category": {
                        "type": "string",
                        "description": "Only return findings whose category equals this value (a kebab-case category id, e.g. `secret`, `vulnerability`, `risky-agent-config`; legacy aliases like `ai-config` are accepted).",
                    },
                    "path_contains": {
                        "type": "string",
                        "description": "Only return findings whose file path contains this substring.",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Maximum number of findings to return. Defaults to 50.",
                    },
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "husk_packages",
            "description": "List packages discovered by the latest cached husk scan across ~68 package ecosystems (language manifests such as npm, PyPI, cargo, Go; OS package managers such as Debian, Alpine, Homebrew; editor/AI surfaces such as VSCode extensions, MCP servers, Ollama models; CI/IaC/containers; and SBOMs), with the manifest file each package came from.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ecosystem": {
                        "type": "string",
                        "description": "Only return packages from this ecosystem id (e.g. npm, pypi, cargo, go, debian:12, vscode-extension).",
                    },
                    "name_contains": {
                        "type": "string",
                        "description": "Only return packages whose name contains this substring.",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Maximum number of packages to return. Defaults to 100.",
                    },
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "husk_fix",
            "description": "Return the typed remediation proposals produced by registered guide controls. READ-ONLY: this tool never writes. Proposals are `auto_safe` (idempotent, reversible config/file edits), `confirm` (ecosystem-specific package updates that run only on explicit CLI/API request), or `manual`.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        },
        {
            "name": "husk_scan",
            "description": "Run a fresh husk security scan and cache the result. Scans the given paths (defaults to the current directory) for vulnerable packages, secrets, risky automation, and AI config issues. Prefer scanning specific project paths; a full home scan can take a while.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Directories to scan. Defaults to the current working directory.",
                    },
                    "home": {
                        "type": "boolean",
                        "description": "Scan the whole home directory instead of paths. Slow; defaults to false.",
                    },
                    "offline": {
                        "type": "boolean",
                        "description": "Skip online vulnerability providers. Defaults to false.",
                    },
                    "include_home_inventory": {
                        "type": "boolean",
                        "description": "Also scan home inventory locations such as editor extensions and MCP configs. Defaults to false for scoped MCP scans (the husk CLI defaults to true).",
                    },
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "husk_policy",
            "description": "Read the committed project security policy (`.husk/policy.toml`) for a path: the team's blocked/allowed package coordinates, suppressed finding ids, and the CI failure threshold. Use this before installing or recommending a dependency so you respect the team's decisions; no scan required.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "A directory inside the project. Husk walks up to the nearest `.husk/policy.toml`. Defaults to the current working directory.",
                    },
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "husk_ledger",
            "description": "Read the user's personal append-only trust ledger (`~/.husk/ledger.jsonl`): the history of `husk approve` security decisions, newest last. Shows what the user has already accepted or blocked so you don't re-flag a triaged decision. Strictly local; reports whether the hash chain is intact.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of most-recent entries to return. Defaults to 50.",
                    },
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "husk_guide",
            "description": "Read scan-backed security guidance. Every Markdown-authored item includes realistic severity, local control status and evidence, related findings and typed remediation ids, plus human-editable steps and sources. Items are baseline or recommendation; progress means the item was read and then verified, completed, or dismissed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "string",
                        "enum": ["action-needed", "recommended", "verified", "completed", "dismissed", "unknown"],
                        "description": "Only return items with this effective status.",
                    },
                    "category": {
                        "type": "string",
                        "description": "Only return tasks in this category (its slug or title, e.g. `secrets-credentials` or `Secrets & credentials`).",
                    },
                    "task_id": {
                        "type": "string",
                        "description": "Return the full detail (problem, steps, options, sources) for this single task id, e.g. `firewall`.",
                    },
                    "include_steps": {
                        "type": "boolean",
                        "description": "Include the full tutorial steps/options/sources for every returned task. Defaults to false (compact list).",
                    },
                },
                "additionalProperties": false,
            },
        },
        {
            "name": "husk_guide_update",
            "description": "Record review state for a guide item. Use `read` after presenting it, `complete` after doing unverified work, `dismiss` when it does not apply or another solution is used, and `clear` to reopen it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "The guide task id to update (see husk_guide), e.g. `firewall`.",
                    },
                    "action": {
                        "type": "string",
                        "enum": ["read", "complete", "dismiss", "clear"],
                        "description": "Review-state transition to persist.",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Optional free-text note stored with the override (handy for dismiss).",
                    },
                },
                "required": ["id", "action"],
                "additionalProperties": false,
            },
        },
        {
            "name": "husk_feedback",
            "description": "Send free-text product feedback about husk to the husk developers. Use when the user asks to send feedback, report an annoyance, or praise/complain about husk itself. Sends only the message, an optional reply email, and the husk version; nothing else leaves the machine. Ask the user before sending on their behalf.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The feedback text (1-4096 characters).",
                    },
                    "contact": {
                        "type": "string",
                        "description": "Optional reply email address to include.",
                    },
                },
                "required": ["message"],
                "additionalProperties": false,
            },
        },
    ])
}

async fn tool_call_result(params: &Value, tx: &Outbox) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
    let progress = params
        .get("_meta")
        .and_then(|meta| meta.get("progressToken"))
        .cloned();

    let outcome = match name {
        "husk_status" => status_tool(),
        "husk_findings" => findings_tool(&arguments),
        "husk_packages" => packages_tool(&arguments),
        "husk_fix" => fix_tool(),
        "husk_policy" => policy_tool(&arguments),
        "husk_ledger" => ledger_tool(&arguments),
        "husk_guide" => guide_tool(&arguments),
        "husk_guide_update" => guide_update_tool(&arguments),
        "husk_feedback" => feedback_tool(&arguments).await,
        "husk_scan" => scan_tool(&arguments, tx, progress).await,
        _ => {
            // Client-chosen names must never become counter keys; unknown
            // tools share one fixed bucket.
            crate::cloud::telemetry::bump_one(crate::cloud::telemetry::counters::MCP_TOOL_UNKNOWN);
            return Err(InvalidParams(format!("unknown tool: {name}")).into());
        }
    };

    // One bump per tool dispatch, success or not, plus a per-tool error
    // marker on an error result. Only names the match above dispatches reach
    // here, so every key is from the closed counter set.
    let mut bumps: Vec<(String, u32)> = Vec::new();
    if let Some(counter) = crate::cloud::telemetry::counters::mcp_tool(name) {
        bumps.push((counter, 1));
    }
    if outcome.is_err()
        && let Some(counter) = crate::cloud::telemetry::counters::mcp_tool_err(name)
    {
        bumps.push((counter, 1));
    }
    crate::cloud::telemetry::bump(&bumps);

    // Tool results carry both a human-readable text block and machine-readable
    // structuredContent; errors are tagged with a stable `kind`.
    let (value, is_error) = match outcome {
        Ok(value) => (value, false),
        Err(err) => {
            let kind = if err.downcast_ref::<NoCache>().is_some() {
                "no_cache"
            } else {
                "tool_error"
            };
            (json!({ "error": format!("{err:#}"), "kind": kind }), true)
        }
    };
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|err| err.to_string());
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": value,
        "isError": is_error,
    }))
}

/// Typed "no cached scan" error so callers get a stable `kind: "no_cache"`
/// instead of having to string-match the message.
#[derive(Debug)]
struct NoCache;

impl std::fmt::Display for NoCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no cached husk scan found; run the husk_scan tool or `husk scan` first")
    }
}

impl std::error::Error for NoCache {}

fn load_cached_report() -> Result<ScanReport> {
    match crate::cache::load_any_latest_report()? {
        Some(report) => Ok(report),
        None => Err(NoCache.into()),
    }
}

/// Cache provenance attached to every cached-read tool result so the agent can
/// tell whether the data is fresh and which roots it covers.
fn cache_meta(report: &ScanReport) -> Value {
    let age = (Utc::now() - report.generated_at).num_seconds().max(0);
    json!({
        "cached_roots": report.roots,
        "generated_at": report.generated_at.to_rfc3339(),
        "age_seconds": age,
        "stale": age > STALE_AFTER_SECONDS,
    })
}

fn policy_tool(arguments: &Value) -> Result<Value> {
    let root = match arguments.get("path").and_then(Value::as_str) {
        Some(path) => PathBuf::from(path),
        None => std::env::current_dir()?,
    };
    let Some(policy) = crate::policy::Policy::discover(std::slice::from_ref(&root))? else {
        return Ok(json!({
            "policy": null,
            "message": "no `.husk/policy.toml` found from this path; run `husk init` to create one",
        }));
    };
    let cfg = &policy.config;
    Ok(json!({
        "policy_file": policy.dir.join(crate::policy::POLICY_FILE),
        "schema_version": cfg.schema_version,
        "block": cfg.packages.block,
        "allow": cfg.packages.allow,
        "suppress": cfg.suppress.iter().map(|s| json!({
            "id": s.id,
            "reason": s.reason,
        })).collect::<Vec<_>>(),
        "ci_fail_on": cfg.ci.fail_on.as_deref().unwrap_or("high"),
    }))
}

fn ledger_tool(arguments: &Value) -> Result<Value> {
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(50);
    let entries = crate::ledger::load()?;
    let chain_intact = crate::ledger::verify(&entries).is_none();
    let total = entries.len();
    // Return the most-recent `limit` entries (the ledger is oldest-first).
    let recent: Vec<&crate::ledger::LedgerEntry> = entries.iter().rev().take(limit).rev().collect();
    Ok(json!({
        "total": total,
        "chain_intact": chain_intact,
        "entries": recent,
    }))
}

/// Assess the guide against scan controls and personal review state.
fn guide_report() -> Result<crate::guide::GuideReport> {
    let report = load_cached_report()?;
    let machine = if report.kind == crate::model::ScanKind::Machine {
        None
    } else {
        crate::cache::load_machine_report().ok().flatten()
    };
    Ok(crate::guide::assess(
        &report,
        machine.as_ref(),
        &crate::guide::load_state(),
    ))
}

/// Every guide task, flattened to `(category title, task)` pairs.
fn guide_tasks(
    guide: &crate::guide::GuideReport,
) -> impl Iterator<Item = (&str, &crate::guide::AssessedTask)> {
    guide
        .categories
        .iter()
        .flat_map(|c| c.items.iter().map(move |t| (c.title.as_str(), t)))
}

fn guide_status_str(status: crate::guide::GuideStatus) -> &'static str {
    use crate::guide::GuideStatus::*;
    match status {
        ActionNeeded => "action-needed",
        Recommended => "recommended",
        Verified => "verified",
        Completed => "completed",
        Dismissed => "dismissed",
        Unknown => "unknown",
    }
}

fn guide_task_json(
    task: &crate::guide::AssessedTask,
    category: &str,
    include_steps: bool,
) -> Value {
    let mut value = json!({
        "id": task.id,
        "category": category,
        "title": task.title,
        "status": guide_status_str(task.status),
        "kind": task.kind,
        "severity": task.severity,
        "verification": task.verification,
        // Null for manual guides: husk ran no check, so it reports no result.
        "control_status": task.control_status,
        "read": task.read,
        "handled": task.handled,
        "bucket": task.bucket,
        "evidence": task.evidence,
        "finding_ids": task.finding_ids,
        "remediation_ids": task.remediation_ids,
        "why": task.why,
        "estimate": task.estimate,
        "solution": task.solution,
        "decision": task.decision,
        "reason": task.reason,
    });
    if include_steps {
        value["problem"] = json!(task.problem);
        value["steps"] = serde_json::to_value(&task.steps).unwrap_or(Value::Null);
        value["options"] = serde_json::to_value(&task.options).unwrap_or(Value::Null);
        value["sources"] = serde_json::to_value(&task.sources).unwrap_or(Value::Null);
    }
    value
}

fn guide_tool(arguments: &Value) -> Result<Value> {
    let guide = guide_report()?;

    // Single-task detail: always return the full tutorial.
    if let Some(id) = arguments.get("task_id").and_then(Value::as_str) {
        let (category, task) = guide_tasks(&guide)
            .find(|(_, t)| t.id == id)
            .ok_or_else(|| {
                InvalidParams(format!(
                    "no guide task with id `{id}`; call husk_guide to list ids"
                ))
            })?;
        return Ok(guide_task_json(task, category, true));
    }

    let want_status = arguments.get("status").and_then(Value::as_str);
    let want_category = arguments.get("category").and_then(Value::as_str);
    let include_steps = arguments
        .get("include_steps")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut matched: Vec<(&str, &crate::guide::AssessedTask)> = guide
        .categories
        .iter()
        .filter(|c| want_category.is_none_or(|w| w == c.id || w == c.title))
        .flat_map(|c| c.items.iter().map(move |t| (c.title.as_str(), t)))
        .filter(|(_, t)| want_status.is_none_or(|w| w == guide_status_str(t.status)))
        .collect();
    matched.sort_by_key(|(_, t)| std::cmp::Reverse(t.priority));

    Ok(json!({
        "summary": {
            "total": guide.total,
            "todo": guide.todo,
            "done": guide.done,
            "ignored": guide.ignored,
            "handled": guide.handled,
            "percent": guide.percent,
            "verified": guide.verified,
            "completed": guide.completed,
        },
        "returned": matched.len(),
        "tasks": matched
            .iter()
            .map(|(category, task)| guide_task_json(task, category, include_steps))
            .collect::<Vec<_>>(),
    }))
}

fn guide_update_tool(arguments: &Value) -> Result<Value> {
    let id = arguments
        .get("id")
        .and_then(Value::as_str)
        .context("`id` is required (a guide task id; call husk_guide to list them)")?;
    let action = arguments
        .get("action")
        .and_then(Value::as_str)
        .context("`action` is required: `read`, `complete`, `dismiss`, or `clear`")?;
    let parsed: crate::guide::GuideAction = action.parse()?;
    let reason = arguments
        .get("reason")
        .and_then(Value::as_str)
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty());

    // Reject unknown ids so a typo can't silently write dead state (the same
    // shared catalog check the web `/api/guide/task` handler uses).
    if !crate::guide::is_known_task(id) {
        return Err(InvalidParams(format!(
            "no guide task with id `{id}`; call husk_guide to list valid ids"
        ))
        .into());
    }

    crate::guide::apply(id, parsed, reason)?;

    // Re-assess (once) so the caller sees the task's new effective status.
    let guide = guide_report()?;
    let (category, task) = guide_tasks(&guide)
        .find(|(_, t)| t.id == id)
        .context("task vanished after update")?;
    Ok(json!({
        "updated": id,
        "action": action,
        "state_file": crate::guide::data_file().ok(),
        "task": guide_task_json(task, category, false),
    }))
}

fn status_tool() -> Result<Value> {
    let report = load_cached_report()?;
    let mut categories = std::collections::BTreeMap::<&str, usize>::new();
    for finding in &report.findings {
        *categories.entry(finding.category.id()).or_default() += 1;
    }
    Ok(json!({
        "cache": cache_meta(&report),
        "stats": report.stats,
        "findings_by_category": categories,
        "providers": report.providers.iter().map(|provider| json!({
            "name": provider.name,
            "ok": provider.ok,
            "checked_packages": provider.checked_packages,
            "findings": provider.findings,
            "message": provider.message,
        })).collect::<Vec<_>>(),
        "guidance": report.guidance,
    }))
}

fn findings_tool(arguments: &Value) -> Result<Value> {
    let report = load_cached_report()?;
    let min_severity = arguments
        .get("min_severity")
        .and_then(Value::as_str)
        .map(|value| {
            Severity::parse_strict(value).ok_or_else(|| {
                InvalidParams(format!(
                    "unknown min_severity `{value}`; valid values: critical, high, medium, low, info"
                ))
            })
        })
        .transpose()?
        .unwrap_or(Severity::Info);
    let category = arguments
        .get("category")
        .and_then(Value::as_str)
        .map(|value| {
            crate::rule::Category::parse_strict(value).ok_or_else(|| {
                InvalidParams(format!(
                    "unknown category `{value}`; valid values are the kebab-case ids from husk_status's findings_by_category"
                ))
            })
        })
        .transpose()?;
    let path_contains = arguments.get("path_contains").and_then(Value::as_str);
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(DEFAULT_FINDING_LIMIT);

    let mut findings = report
        .findings
        .iter()
        .filter(|finding| finding.severity >= min_severity)
        .filter(|finding| category.is_none_or(|category| finding.category == category))
        .filter(|finding| {
            path_contains.is_none_or(|needle| {
                finding
                    .path
                    .as_ref()
                    .is_some_and(|path| path.display().to_string().contains(needle))
            })
        })
        .collect::<Vec<_>>();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    let total = findings.len();
    Ok(json!({
        "cache": cache_meta(&report),
        "total_matching": total,
        "returned": findings.len().min(limit),
        "findings": findings
            .iter()
            .take(limit)
            .map(|finding| finding_json(finding))
            .collect::<Vec<_>>(),
    }))
}

fn finding_json(finding: &Finding) -> Value {
    json!({
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.category.id(),
        "source": finding.source,
        "path": finding.path,
        "line": finding.line,
        "summary": finding.summary,
        "recommendation": finding.recommendation,
        "references": finding.references,
        "package": finding.package.as_ref().map(PackageRef::key),
    })
}

fn packages_tool(arguments: &Value) -> Result<Value> {
    let report = load_cached_report()?;
    let ecosystem = arguments.get("ecosystem").and_then(Value::as_str);
    let name_contains = arguments.get("name_contains").and_then(Value::as_str);
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(DEFAULT_PACKAGE_LIMIT);

    let packages = report
        .packages
        .iter()
        .filter(|package| ecosystem.is_none_or(|ecosystem| package.ecosystem == ecosystem))
        .filter(|package| name_contains.is_none_or(|needle| package.name.contains(needle)))
        .collect::<Vec<_>>();
    let total = packages.len();
    Ok(json!({
        "cache": cache_meta(&report),
        "total_matching": total,
        "returned": packages.len().min(limit),
        "packages": packages
            .iter()
            .take(limit)
            .map(|package| json!({
                "key": package.key(),
                "ecosystem": package.ecosystem,
                "name": package.name,
                "version": package.version,
                "manifest_path": package.manifest_path,
            }))
            .collect::<Vec<_>>(),
    }))
}

/// Read-only fix planner: classifies the safe-fixable subset without writing
/// anything. `husk_fix` never applies; that stays a user-driven
/// `husk fix --apply`.
fn fix_tool() -> Result<Value> {
    let report = load_cached_report()?;
    let plan = crate::remediation::plan(&report);
    Ok(json!({
        "cache": cache_meta(&report),
        "dry_run": true,
        "note": "Plan only; husk_fix never writes. `auto_safe` fixes can be applied with `husk fix --apply` once the user agrees; do `confirm`/`manual` fixes with your own user-permissioned tools.",
        "summary": {
            "auto_safe": plan.auto_safe_count(),
            "confirm": plan.confirm_count(),
            "manual": plan.manual_count(),
        },
        "remediations": plan.proposals,
    }))
}

/// Send free-text product feedback to the Husk backend with context `mcp`.
async fn feedback_tool(arguments: &Value) -> Result<Value> {
    let raw = arguments
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| InvalidParams("`message` is required (the feedback text)".to_string()))?;
    let message = crate::cloud::feedback::clean_message(raw)
        .map_err(|err| InvalidParams(format!("{err:#}")))?;
    let contact =
        crate::cloud::feedback::clean_contact(arguments.get("contact").and_then(Value::as_str));
    crate::cloud::feedback::send(&message, contact.as_deref(), "mcp").await?;
    Ok(json!({
        "sent": true,
        "note": "Feedback delivered to the husk developers. Thanks!",
    }))
}

async fn scan_tool(arguments: &Value, tx: &Outbox, progress: Option<Value>) -> Result<Value> {
    let home = arguments
        .get("home")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let roots = if home {
        vec![dirs::home_dir().context("could not locate home directory")?]
    } else {
        let paths = arguments
            .get("paths")
            .and_then(Value::as_array)
            .map(|paths| {
                paths
                    .iter()
                    .filter_map(Value::as_str)
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if paths.is_empty() {
            vec![std::env::current_dir()?]
        } else {
            paths
        }
    };

    let mut options = ScanOptions::new(roots);
    options.online = !arguments
        .get("offline")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    options.include_home_inventory = arguments
        .get("include_home_inventory")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Emit progress around the (potentially slow) scan so the client doesn't
    // think the call hung. No-op unless the caller sent a token.
    send_progress(tx, &progress, 0.0, 1.0, "scan started");
    let report = crate::scan::run_scan(options).await?;
    send_progress(tx, &progress, 1.0, 1.0, "scan complete");
    let _ = crate::cache::save_latest_report(&report);

    let mut findings = report.findings.iter().collect::<Vec<_>>();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Ok(json!({
        "cache": cache_meta(&report),
        "stats": report.stats,
        "providers": report.providers,
        "top_findings": findings
            .iter()
            .take(SCAN_RESULT_FINDING_LIMIT)
            .map(|finding| finding_json(finding))
            .collect::<Vec<_>>(),
        "note": format!(
            "showing up to {SCAN_RESULT_FINDING_LIMIT} findings by severity; use husk_findings to page through all {} findings",
            report.stats.findings
        ),
    }))
}

/// Send a `notifications/progress` message if the caller supplied a token.
fn send_progress(tx: &Outbox, token: &Option<Value>, progress: f64, total: f64, message: &str) {
    let Some(token) = token else { return };
    let _ = tx.send(json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": token,
            "progress": progress,
            "total": total,
            "message": message,
        },
    }));
}

/// The shared agent guide, embedded so it is reachable as an MCP resource even
/// when the repo/file layout isn't on disk next to the binary.
const AGENT_GUIDE: &str = include_str!("../integrations/husk-agent-guide.md");

fn prompts_list() -> Value {
    json!({
        "prompts": [{
            "name": "husk-audit",
            "title": "Audit this machine/project with husk",
            "description": "Drive husk end-to-end: check for a cached scan, (re)scan if needed, then triage and remediate findings.",
            "arguments": [{
                "name": "path",
                "description": "Project directory to scan. Defaults to the current directory.",
                "required": false,
            }],
        }],
    })
}

fn prompts_get(params: &Value) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if name != "husk-audit" {
        return Err(InvalidParams(format!(
            "unknown prompt `{name}`; call prompts/list for the available prompts"
        ))
        .into());
    }
    let path = params
        .get("arguments")
        .and_then(|a| a.get("path"))
        .and_then(Value::as_str)
        .unwrap_or(".");
    let text = format!(
        "Run a husk security audit of `{path}`.\n\n\
         1. Call husk_status first. If there is no cached scan, or its `cache.stale` is true, \
         or `cache.cached_roots` does not cover `{path}`, call husk_scan with paths=[\"{path}\"].\n\
         2. Review the high/critical items with husk_findings (min_severity=\"high\").\n\
         3. For actionable remediation, walk husk_guide (status=\"recommended\") and/or husk_fix. \
         Apply each fix with your normal user-permissioned tools, then call husk_guide_update \
         (action=\"complete\") for guide tasks you complete.\n\n\
         husk only reads files and writes its own state; it never performs the fix. Respect any \
         husk_policy decisions and don't re-flag items already in husk_ledger."
    );
    Ok(json!({
        "description": "Husk audit workflow",
        "messages": [{
            "role": "user",
            "content": { "type": "text", "text": text },
        }],
    }))
}

fn resources_list() -> Value {
    json!({
        "resources": [
            {
                "uri": "husk://agent-guide",
                "name": "husk-agent-guide",
                "title": "Husk agent guide",
                "description": "How to drive husk's MCP tools and CLI, and how to read its output.",
                "mimeType": "text/markdown",
            },
            {
                "uri": "husk://policy",
                "name": "husk-policy",
                "title": "Project security policy",
                "description": "The committed `.husk/policy.toml` for the current directory (block/allow/suppress + CI threshold).",
                "mimeType": "application/json",
            },
        ],
    })
}

fn resources_read(params: &Value) -> Result<Value> {
    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (text, mime) = match uri {
        "husk://agent-guide" => (AGENT_GUIDE.to_string(), "text/markdown"),
        "husk://policy" => {
            let root = std::env::current_dir()?;
            let value = policy_tool(&json!({ "path": root.display().to_string() }))?;
            (serde_json::to_string_pretty(&value)?, "application/json")
        }
        other => {
            return Err(InvalidParams(format!(
                "unknown resource `{other}`; call resources/list for the available uris"
            ))
            .into());
        }
    };
    Ok(json!({
        "contents": [{
            "uri": uri,
            "mimeType": mime,
            "text": text,
        }],
    }))
}
