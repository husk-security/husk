//! Drift guard: the MCP server's tool list, the shared agent guide, and the
//! `using-husk` skill must document the same `husk_*` tools. The docs are
//! hand-maintained mirrors; this test fails CI the moment they diverge so
//! "update both" can't silently rot.

use std::collections::BTreeSet;

const GUIDE: &str = include_str!("../integrations/husk-agent-guide.md");
const SKILL: &str = include_str!("../integrations/plugin/skills/using-husk/SKILL.md");

/// Every `husk_<name>` token in `text`.
fn tool_tokens(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(rel) = text[i..].find("husk_") {
        let start = i + rel;
        let mut end = start + "husk_".len();
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        // Trim a trailing `_` so `husk_guide_update.` etc. stays intact but a
        // bare `husk_` doesn't sneak in.
        let token = text[start..end].trim_end_matches('_').to_string();
        if token != "husk" {
            out.insert(token);
        }
        i = end;
    }
    out
}

fn server_tools() -> BTreeSet<String> {
    husk::mcp::tool_definitions()
        .as_array()
        .expect("tool_definitions is an array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name").to_string())
        .collect()
}

#[test]
fn guide_and_skills_cover_exactly_the_server_tools() {
    let server = server_tools();
    assert!(!server.is_empty(), "no MCP tools defined");

    for (label, doc) in [("husk-agent-guide.md", GUIDE), ("plugin SKILL.md", SKILL)] {
        let documented = tool_tokens(doc);
        let missing: Vec<_> = server.difference(&documented).collect();
        let extra: Vec<_> = documented.difference(&server).collect();
        assert!(
            missing.is_empty(),
            "{label} is missing MCP tools the server exposes: {missing:?}"
        );
        assert!(
            extra.is_empty(),
            "{label} documents tools the server no longer exposes: {extra:?}"
        );
    }
}

/// Every agent plugin/extension manifest carries husk's own version, so a
/// crate release does not leave an agent installing a stale-looking build.
#[test]
fn plugin_manifests_carry_the_crate_version() {
    let expected = format!("\"version\": \"{}\"", env!("CARGO_PKG_VERSION"));
    for (label, manifest) in [
        (
            "claude-plugin",
            include_str!("../integrations/plugin/.claude-plugin/plugin.json"),
        ),
        (
            "codex-plugin",
            include_str!("../integrations/plugin/.codex-plugin/plugin.json"),
        ),
        (
            "cursor-plugin",
            include_str!("../integrations/plugin/.cursor-plugin/plugin.json"),
        ),
        ("gemini-extension", include_str!("../gemini-extension.json")),
    ] {
        assert!(
            manifest.contains(&expected),
            "{label} manifest does not declare {expected}"
        );
    }
}
