//! Cheap system-context gathering (user, OS, shell, dev-config summary) for
//! the report's [`SystemContext`](crate::model::SystemContext) block.

use crate::model::{DevConfigSummary, SystemContext};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn collect_context(scan_roots: &[PathBuf]) -> SystemContext {
    let home = dirs::home_dir();
    SystemContext {
        user: username(),
        home_dir: home.clone(),
        current_dir: std::env::current_dir().ok(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        distro: distro_name(),
        kernel: command_output("uname", &["-sr"]),
        git_name: git_config("user.name"),
        git_email: git_config("user.email"),
        package_managers: detected_tools(),
        dev_configs: dev_configs(home.as_deref()),
        scan_roots: scan_roots.to_vec(),
    }
}

fn username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|value| !value.is_empty())
}

fn distro_name() -> Option<String> {
    let contents = fs::read_to_string("/etc/os-release").ok()?;
    let mut name = None;
    let mut version = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
            return Some(unquote(value));
        }
        if let Some(value) = line.strip_prefix("NAME=") {
            name = Some(unquote(value));
        }
        if let Some(value) = line.strip_prefix("VERSION_ID=") {
            version = Some(unquote(value));
        }
    }
    match (name, version) {
        (Some(name), Some(version)) => Some(format!("{name} {version}")),
        (Some(name), None) => Some(name),
        _ => None,
    }
}

fn unquote(value: &str) -> String {
    value.trim_matches('"').to_string()
}

fn git_config(key: &str) -> Option<String> {
    command_output("git", &["config", "--global", "--get", key])
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    // Git probes go through the hardened, read-only builder (see `gitcmd`).
    let mut command = if program == "git" {
        crate::gitcmd::git_command()
    } else {
        Command::new(program)
    };
    let output = command.args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

/// Dev/security tools found on `PATH`: package managers plus security tooling
/// (gitleaks, gpg, gh, sops, …). Feeds `SystemContext.package_managers` (the
/// field keeps its legacy wire name for client compatibility). Detection is an
/// in-process `PATH` scan: no subprocesses, and it works on hosts without a
/// `which` binary.
fn detected_tools() -> Vec<String> {
    let candidates = [
        ("npm", "npm"),
        ("pnpm", "pnpm"),
        ("yarn", "yarn"),
        ("node", "node"),
        ("python", "python"),
        ("python3", "python3"),
        ("pip", "pip"),
        ("uv", "uv"),
        ("poetry", "poetry"),
        ("cargo", "cargo"),
        ("rustc", "rustc"),
        ("go", "go"),
        ("gem", "gem"),
        ("bundle", "bundle"),
        ("brew", "brew"),
        ("nix", "nix"),
        ("safe-chain", "safe-chain"),
        ("1password-cli", "op"),
        ("bitwarden-cli", "bw"),
        ("infisical", "infisical"),
        ("sops", "sops"),
        ("age", "age"),
        ("gitleaks", "gitleaks"),
        ("osv-scanner", "osv-scanner"),
        ("trivy", "trivy"),
        ("cargo-audit", "cargo-audit"),
        ("cargo-deny", "cargo-deny"),
        ("pre-commit", "pre-commit"),
        ("gpg", "gpg"),
        ("gh", "gh"),
    ];
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    candidates
        .iter()
        .filter(|(_, binary)| on_path(&path_dirs, binary))
        .map(|(label, _)| (*label).to_string())
        .collect()
}

/// Whether `binary` exists in any `PATH` directory.
fn on_path(path_dirs: &[PathBuf], binary: &str) -> bool {
    path_dirs.iter().any(|dir| dir.join(binary).is_file())
}

fn dev_configs(home: Option<&Path>) -> Vec<DevConfigSummary> {
    let Some(home) = home else {
        return Vec::new();
    };
    [
        ("VS Code extensions", home.join(".vscode/extensions")),
        ("Cursor extensions", home.join(".cursor/extensions")),
        ("Cursor MCP", home.join(".cursor/mcp.json")),
        ("Claude config", home.join(".claude")),
        (
            "Claude Desktop MCP",
            home.join(".config/Claude/claude_desktop_config.json"),
        ),
        ("npm config", home.join(".npmrc")),
        ("Cargo config", home.join(".cargo/config.toml")),
        ("Git config", home.join(".gitconfig")),
        ("SSH config", home.join(".ssh/config")),
        ("AWS credentials", home.join(".aws/credentials")),
    ]
    .into_iter()
    .map(|(label, path)| DevConfigSummary {
        label: label.to_string(),
        present: path.exists(),
        path,
    })
    .collect()
}
