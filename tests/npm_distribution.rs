//! Drift guard for the npm distribution and the MCP Registry listing.
//!
//! Several hand-maintained files have to agree: `server.json` names the
//! registry entry and both upstream packages, `npm/build.mjs` stamps the
//! matching `mcpName` into the published `package.json` and `README.md` carries
//! the equivalent token for crates.io (each registry's proof of ownership), and
//! the shipped agent manifests launch that same package. A mismatch in any of
//! them is only visible when a release fails or a user's plugin does not start.

use std::process::Command;

const SERVER_JSON: &str = include_str!("../server.json");
const BUILD_MJS: &str = include_str!("../npm/build.mjs");
const PLUGIN_MCP: &str = include_str!("../integrations/plugin/.mcp.json");
const GEMINI_EXTENSION: &str = include_str!("../gemini-extension.json");
const README: &str = include_str!("../README.md");

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("valid JSON")
}

#[test]
fn server_json_declares_every_upstream_package() {
    let server = json(SERVER_JSON);
    let packages = server["packages"].as_array().expect("packages array");

    let types: Vec<&str> = packages
        .iter()
        .map(|p| p["registryType"].as_str().expect("registryType"))
        .collect();
    assert_eq!(types, ["npm", "cargo"]);

    for package in packages {
        let kind = package["registryType"].as_str().expect("registryType");
        assert_eq!(package["identifier"], "husk-sec", "{kind}");
        assert_eq!(package["transport"]["type"], "stdio", "{kind}");
        // Both validators require an exact version and reject fileSha256,
        // neither of which the JSON schema expresses.
        assert!(package.get("fileSha256").is_none(), "{kind}");
        assert_eq!(package["version"], server["version"], "{kind}");
        // Without this the client runs bare `husk`, which prints help and
        // exits instead of speaking MCP.
        assert_eq!(package["packageArguments"][0]["value"], "mcp", "{kind}");
    }

    let name = server["name"].as_str().expect("server name");
    assert!(
        BUILD_MJS.contains(&format!("const MCP_NAME = \"{name}\";")),
        "npm/build.mjs must stamp mcpName = {name}"
    );
    assert!(BUILD_MJS.contains("const MAIN_PACKAGE = \"husk-sec\";"));
}

/// crates.io strips HTML comments when it renders a README, so the crate's
/// ownership token has to survive as visible text with a non-name character
/// after it. Reflowing the paragraph it sits in would silently break the
/// registry's cargo validation.
#[test]
fn readme_carries_the_cargo_ownership_token() {
    let name = json(SERVER_JSON)["name"]
        .as_str()
        .expect("server name")
        .to_string();
    let token = format!("mcp-name: {name}");

    let rest = README
        .split_once(&token)
        .unwrap_or_else(|| panic!("README.md must contain a visible `{token}`"))
        .1;
    let next = rest.chars().next().expect("token is not at end of file");
    assert!(
        !(next.is_ascii_alphanumeric() || "._-/".contains(next)),
        "`{token}` must be followed by a boundary, found {next:?}"
    );
}

#[test]
fn shipped_manifests_launch_the_npm_package() {
    for (label, text, pointer) in [
        ("plugin/.mcp.json", PLUGIN_MCP, "/mcpServers/husk"),
        (
            "gemini-extension.json",
            GEMINI_EXTENSION,
            "/mcpServers/husk",
        ),
    ] {
        let entry = json(text)
            .pointer(pointer)
            .unwrap_or_else(|| panic!("{label} has no husk server entry"))
            .clone();
        assert_eq!(entry["command"], "npx", "{label}");
        assert_eq!(
            entry["args"],
            serde_json::json!(["-y", "husk-sec", "mcp"]),
            "{label}"
        );
    }
}

#[test]
fn mcp_install_writes_the_local_binary_not_npx() {
    // The shipped manifests cannot assume husk is on PATH, so they go through
    // npx. `husk mcp install` can: running it proves the binary exists, so it
    // registers that binary directly. The two are deliberately different.
    let out = Command::new(env!("CARGO_BIN_EXE_husk"))
        .args(["mcp", "install", "cursor", "--dry-run"])
        .output()
        .expect("husk mcp install --dry-run runs");
    assert!(out.status.success(), "install --dry-run failed");

    let printed = String::from_utf8_lossy(&out.stdout);
    assert!(
        printed.contains("\"command\": \"husk\""),
        "expected the bare binary in the written config, got:\n{printed}"
    );
    assert!(!printed.contains("npx"));
}
