//! MCP server coordinates (`.mcp.json` / `claude_desktop_config.json` / etc.
//! -> OSV `npm` for `npx`-launched servers, OSV `PyPI` for `uvx`-launched).
//!
//! MCP client configs are NOT package manifests: they invoke package runners,
//! and the installable coordinate is buried inside each server's `args` array
//! (never the user-chosen server-map key). There is no resolved/locked
//! version, so the version is best-effort from the spec string (`@1.2.3`,
//! `==1.2.3`); most real entries are unpinned and inventory-only.

use super::support::{Emitter, read_text, strip_jsonc};
use super::{ScanTarget, exact_semver_pin, file_name, find_line, pep503_name};
use serde_json::Value as JsonValue;
use std::path::Path;

pub struct McpTarget;

impl ScanTarget for McpTarget {
    fn ecosystem_id(&self) -> &'static str {
        // Registry id only; actual coordinates are emitted per-spec as real
        // "npm" / "pypi" ecosystems (mirroring jupyter / docker / pre-commit).
        "mcp"
    }

    fn detects(&self, path: &Path) -> bool {
        match file_name(path) {
            Some(
                ".mcp.json"
                | "claude_desktop_config.json"
                | ".claude.json"
                | "cline_mcp_settings.json",
            ) => true,
            // `mcp.json`/`config.json` are too generic on their own, so
            // require the owning parent directory.
            Some("mcp.json") => parent_dir_is(path, ".vscode") || parent_dir_is(path, ".cursor"),
            Some("config.json") => parent_dir_is(path, ".continue"),
            _ => false,
        }
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(contents) = read_text(path, out) {
            parse_mcp_config(&contents, out);
        }
    }
}

fn parent_dir_is(path: &Path, name: &str) -> bool {
    path.parent().and_then(file_name) == Some(name)
}

#[derive(Debug, PartialEq, Eq)]
struct Coord {
    ecosystem: &'static str,
    name: String,
    /// `Some` only for an exact pin (`@1.2.3` / `==1.2.3`); `None` for floating
    /// (`@latest`, ranges, bare name) or unresolvable (alias/url/git) specs.
    version: Option<String>,
}

/// Parse an MCP client config (tolerant of JSONC comments / trailing commas).
/// Duplicate coordinates across server maps collapse in discovery's global
/// dedup.
fn parse_mcp_config(contents: &str, out: &mut Emitter<'_>) {
    let cleaned = strip_jsonc(contents);
    let Ok(root) = serde_json::from_str::<JsonValue>(&cleaned) else {
        out.warn("MCP client config is not valid JSON");
        return;
    };

    let mut coords: Vec<Coord> = Vec::new();

    // `mcpServers` (most clients) or `servers` (VS Code's `.vscode/mcp.json`).
    collect_server_map(root.get("mcpServers"), &mut coords);
    collect_server_map(root.get("servers"), &mut coords);

    // Claude Code's `~/.claude.json` also nests per-project server maps under
    // `projects.<abs path>.mcpServers`.
    if let Some(projects) = root.get("projects").and_then(JsonValue::as_object) {
        for project in projects.values() {
            collect_server_map(project.get("mcpServers"), &mut coords);
        }
    }

    for coord in &coords {
        let line = find_line(contents, &coord.name);
        let version = coord.version.as_deref().unwrap_or_default();
        out.pkg_in(coord.ecosystem, &coord.name, version, line);
    }
}

fn collect_server_map(map: Option<&JsonValue>, coords: &mut Vec<Coord>) {
    let Some(servers) = map.and_then(JsonValue::as_object) else {
        return;
    };
    for server in servers.values() {
        if let Some(coord) = coord_from_server(server) {
            coords.push(coord);
        }
    }
}

/// Extract a coordinate from one server object; remote/local/container/
/// non-package servers yield `None`.
fn coord_from_server(server: &JsonValue) -> Option<Coord> {
    let command = server.get("command")?.as_str()?;
    let args: Vec<&str> = server
        .get("args")
        .and_then(JsonValue::as_array)
        .map(|arr| arr.iter().filter_map(JsonValue::as_str).collect())
        .unwrap_or_default();

    // The command basename decides the runner (handles absolute paths and the
    // Windows `.cmd` shims).
    let base = command_basename(command);
    match base {
        "npx" | "bunx" | "npx.cmd" | "bunx.cmd" => {
            let spec = npm_spec_from_args(&args)?;
            Some(parse_npm_spec(spec))
        }
        "uvx" | "uvx.cmd" => {
            let spec = pypi_spec_from_args(&args)?;
            Some(parse_pypi_spec(spec))
        }
        "pipx" => {
            // Only `pipx run <pkg>` executes a package the way uvx does;
            // `pipx install`/`list` would yield a bogus coordinate named
            // after the subcommand.
            if args.first() != Some(&"run") {
                return None;
            }
            let spec = pypi_spec_from_args(&args)?;
            Some(parse_pypi_spec(spec))
        }
        // node / python / docker / a local script path / etc. are not
        // published registry coordinates.
        _ => None,
    }
}

fn command_basename(command: &str) -> &str {
    command
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(command)
}

/// Find the npm package spec token in `npx`/`bunx` args, skipping runner flags.
/// `-p`/`--package` takes the spec as its VALUE.
fn npm_spec_from_args<'a>(args: &[&'a str]) -> Option<&'a str> {
    let mut iter = args.iter().copied().peekable();
    while let Some(arg) = iter.next() {
        match arg {
            "-y" | "--yes" | "--quiet" | "-q" | "--no-install" | "--" => continue,
            "-p" | "--package" => return iter.next(), // value IS the package
            _ if arg.starts_with('-') => continue,    // unknown flag, skip
            _ => return Some(arg),                    // first positional
        }
    }
    None
}

/// Find the PyPI package spec token in `uvx`/`pipx run` args. `--from` wins
/// (its value is the package; the trailing positional is an entrypoint name).
fn pypi_spec_from_args<'a>(args: &[&'a str]) -> Option<&'a str> {
    let mut iter = args.iter().copied().peekable();
    let mut positional: Option<&str> = None;
    while let Some(arg) = iter.next() {
        match arg {
            "--from" => return iter.next(), // value IS the package spec
            // Flags that consume a following value.
            "--python" | "-p" | "--with" | "--index" | "--index-url" | "--refresh-package" => {
                iter.next();
            }
            "--refresh" | "--reinstall" | "--quiet" | "-q" | "--isolated" | "--" | "run" => {
                continue;
            }
            _ if arg.starts_with('-') => continue,
            _ => {
                if positional.is_none() {
                    positional = Some(arg);
                }
            }
        }
    }
    positional
}

/// Parse an npm spec token. Unresolvable alias/url/git specs are recorded
/// raw with no version.
fn parse_npm_spec(token: &str) -> Coord {
    if token.contains("npm:")
        || token.starts_with("file:")
        || token.starts_with("git+")
        || token.starts_with("http://")
        || token.starts_with("https://")
    {
        return Coord {
            ecosystem: "npm",
            name: token.to_string(),
            version: None,
        };
    }

    // Scoped (`@scope/name[@ver]`): the version delimiter is the first '@' at
    // index >= 1. Unscoped: split on the LAST '@' (if not at index 0), NOT
    // `support::split_scoped_at`, which splits unscoped names on the first `@`.
    let delim = if let Some(rest) = token.strip_prefix('@') {
        rest.find('@').map(|i| i + 1) // +1 to re-add the stripped '@'
    } else {
        token.rfind('@').filter(|&i| i != 0)
    };

    let (name, version) = match delim {
        Some(i) => (&token[..i], Some(&token[i + 1..])),
        None => (token, None),
    };

    Coord {
        ecosystem: "npm",
        name: name.to_string(),
        version: version.and_then(exact_semver_pin),
    }
}

/// Parse a uvx/PyPI spec token. Only `==` (or uvx's `@X.Y.Z`) is an exact
/// pin; other PEP 508 operators are ranges → floating.
fn parse_pypi_spec(token: &str) -> Coord {
    // Longest-first so `>=`/`<=` win over `>`/`<`.
    const OPS: [&str; 7] = ["==", ">=", "<=", "~=", "!=", "<", ">"];

    let mut name_part = token;
    let mut version: Option<String> = None;

    if let Some(idx) = token.find('@') {
        name_part = &token[..idx];
        version = normalize_pypi_version(&token[idx + 1..]);
    } else {
        for op in OPS {
            if let Some(idx) = token.find(op) {
                name_part = &token[..idx];
                if op == "==" {
                    // Single version after `==`, stopping at any extra
                    // constraint separator.
                    let rest = &token[idx + op.len()..];
                    let pin = rest.split(',').next().unwrap_or(rest);
                    version = normalize_pypi_version(pin);
                }
                break;
            }
        }
    }

    Coord {
        ecosystem: "pypi",
        name: pep503_name(name_part),
        version,
    }
}

/// Strip a single leading `v`, keep epoch/pre/post as-is; empty or
/// non-version strings → `None`.
fn normalize_pypi_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim().strip_prefix('v').unwrap_or(raw.trim());
    if trimmed.is_empty() {
        return None;
    }
    let first = trimmed.chars().next()?;
    if first.is_ascii_digit() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str) -> Vec<PackageRef> {
        run_parser("npm", contents, parse_mcp_config)
    }

    #[test]
    fn parses_npx_and_uvx_coordinates() {
        let json = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@2024.11.5", "/home/u"]
                },
                "sqlite": {
                    "command": "uvx",
                    "args": ["mcp-server-sqlite==0.6.2", "--db-path", "./app.db"]
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "-p", "@modelcontextprotocol/server-github@1.0.4", "mcp-server-github"]
                },
                "remote-only": { "type": "http", "url": "https://api.example.com/mcp" },
                "local-source": { "command": "node", "args": ["/home/u/dist/index.js"] }
            }
        }"#;
        let pkgs = parse(json);
        // 3 package coordinates; remote + local-source skipped.
        assert_eq!(pkgs.len(), 3);
        assert!(pkgs.iter().any(|p| p.ecosystem == "npm"
            && p.name == "@modelcontextprotocol/server-filesystem"
            && p.version == "2024.11.5"));
        assert!(pkgs.iter().any(|p| p.ecosystem == "npm"
            && p.name == "@modelcontextprotocol/server-github"
            && p.version == "1.0.4"));
        assert!(pkgs.iter().any(|p| p.ecosystem == "pypi"
            && p.name == "mcp-server-sqlite"
            && p.version == "0.6.2"));
    }

    #[test]
    fn scoped_name_at_split_and_floating_versions() {
        let scoped = parse_npm_spec("@scope/name@1.2.3");
        assert_eq!(scoped.name, "@scope/name");
        assert_eq!(scoped.version.as_deref(), Some("1.2.3"));

        let floating = parse_npm_spec("server-everything@latest");
        assert_eq!(floating.name, "server-everything");
        assert_eq!(floating.version, None); // dist-tag → no exact match

        let scoped_bare = parse_npm_spec("@scope/name");
        assert_eq!(scoped_bare.name, "@scope/name");
        assert_eq!(scoped_bare.version, None);

        let v_prefixed = parse_npm_spec("pkg@v2.0.0");
        assert_eq!(v_prefixed.version.as_deref(), Some("2.0.0"));

        let prerelease = parse_npm_spec("pkg@1.2.3-beta.1+build.5");
        assert_eq!(prerelease.version.as_deref(), Some("1.2.3-beta.1"));

        let partial = parse_npm_spec("pkg@1.2");
        assert_eq!(partial.version, None);
    }

    #[test]
    fn pypi_name_normalization_and_constraints() {
        let pinned = parse_pypi_spec("MCP_Server.SQLite==0.6.2");
        assert_eq!(pinned.name, "mcp-server-sqlite");
        assert_eq!(pinned.version.as_deref(), Some("0.6.2"));

        let ranged = parse_pypi_spec("some-pkg>=1,<2");
        assert_eq!(ranged.name, "some-pkg");
        assert_eq!(ranged.version, None); // range → not exact
    }

    #[test]
    fn from_flag_wins_over_entrypoint() {
        let args = ["--from", "mcp-real-pkg==1.0.0", "some-entrypoint"];
        let spec = pypi_spec_from_args(&args).unwrap();
        assert_eq!(spec, "mcp-real-pkg==1.0.0");
    }

    #[test]
    fn pipx_requires_the_run_subcommand() {
        // `pipx run <pkg>` is a package execution, a real coordinate.
        let json = r#"{
            "mcpServers": {
                "runner": { "command": "pipx", "args": ["run", "mcp-server-time==1.0.0"] },
                "installer": { "command": "pipx", "args": ["install", "mcp-server-time"] }
            }
        }"#;
        let pkgs = parse(json);
        // Only the `run` invocation yields a coordinate; `pipx install` must
        // not produce a bogus package named "install".
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, "pypi");
        assert_eq!(pkgs[0].name, "mcp-server-time");
        assert_eq!(pkgs[0].version, "1.0.0");
    }

    #[test]
    fn strips_jsonc_comments_and_trailing_commas() {
        let jsonc = r#"{
            // a line comment
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "pkg@1.0.0"], /* block */
                },
            }
        }"#;
        let pkgs = parse(jsonc);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "pkg");
        assert_eq!(pkgs[0].version, "1.0.0");
    }

    #[test]
    fn walks_claude_code_per_project_maps() {
        let json = r#"{
            "mcpServers": { "g": { "command": "npx", "args": ["global-pkg@1.0.0"] } },
            "projects": {
                "/home/u/proj": {
                    "mcpServers": { "p": { "command": "npx", "args": ["proj-pkg@2.0.0"] } }
                }
            }
        }"#;
        let pkgs = parse(json);
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.name == "global-pkg"));
        assert!(pkgs.iter().any(|p| p.name == "proj-pkg"));
    }
}
