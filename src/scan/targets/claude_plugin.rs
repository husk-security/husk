//! Claude Code plugins: `~/.claude/plugins/installed_plugins.json` (or
//! `$CLAUDE_CONFIG_DIR/plugins/`), the resolved registry of installed plugins.
//!
//! Inventory-only (no advisory ecosystem). Plugins can ship hooks (arbitrary
//! command execution) and MCP servers, unvetted; knowing what is installed,
//! from which marketplace, is the security signal. Coordinate identity is
//! `"<plugin-name>@<marketplace-name>"` (plugin names are only unique within
//! a marketplace); the version is kept verbatim, including the literal
//! `"unknown"` (plugin declared no version; never coerced to a fake semver).

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name};
use serde_json::Value as JsonValue;
use std::path::Path;

pub struct ClaudePluginTarget;

impl ScanTarget for ClaudePluginTarget {
    fn ecosystem_id(&self) -> &'static str {
        "claude-plugin"
    }

    /// The `plugins/` parent requirement keeps an unrelated
    /// `installed_plugins.json` from being hijacked.
    fn detects(&self, path: &Path) -> bool {
        if !matches!(file_name(path), Some("installed_plugins.json")) {
            return false;
        }
        path.parent()
            .and_then(file_name)
            .is_some_and(|p| p == "plugins")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(contents) = read_text(path, out) {
            parse_installed_plugins(&contents, out);
        }
    }
}

/// Shape: `{ "version": 2, "plugins": { "<name>@<marketplace>": [ <record>, .. ] } }`.
/// Each value is an **array** of install records (one per scope:
/// user/project/local); one coordinate per record.
fn parse_installed_plugins(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("installed_plugins.json is not valid JSON");
        return;
    };
    let Some(plugins) = json.get("plugins").and_then(JsonValue::as_object) else {
        return;
    };

    for (key, value) in plugins {
        // The qualified `"<plugin>@<marketplace>"` key is the join key for
        // any future advisory feed: kept verbatim and case-sensitive.
        let Some(records) = value.as_array() else {
            continue;
        };
        for record in records {
            // Missing/empty version means the plugin declared none: the
            // literal "unknown", never a fake semver.
            let version = record
                .get("version")
                .and_then(JsonValue::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or("unknown");
            out.pkg(key, version, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str) -> Vec<PackageRef> {
        run_parser("claude-plugin", contents, parse_installed_plugins)
    }

    #[test]
    fn parses_multiple_pinned_and_unknown_versions() {
        let contents = r#"{
            "version": 2,
            "plugins": {
                "security-guidance@claude-plugins-official": [
                    { "scope": "user", "version": "2.0.3",
                      "installPath": "/x/cache/claude-plugins-official/security-guidance/2.0.3" }
                ],
                "example-tools@example-marketplace": [
                    { "scope": "user", "version": "0.0.3",
                      "gitCommitSha": "0123456789abcdef0123456789abcdef01234567" }
                ],
                "frontend-design@claude-plugins-official": [
                    { "scope": "user", "version": "unknown" }
                ]
            }
        }"#;
        let pkgs = parse(contents);
        assert_eq!(pkgs.len(), 3);

        let find = |name: &str| pkgs.iter().find(|p| p.name == name).expect("present");
        assert_eq!(
            find("security-guidance@claude-plugins-official").version,
            "2.0.3"
        );
        assert_eq!(find("example-tools@example-marketplace").version, "0.0.3");
        // "unknown" is preserved verbatim, never coerced to a fake semver.
        assert_eq!(
            find("frontend-design@claude-plugins-official").version,
            "unknown"
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == "claude-plugin"));
    }

    #[test]
    fn multi_scope_records_each_emit_a_coordinate() {
        let contents = r#"{
            "version": 2,
            "plugins": {
                "dual@mkt": [
                    { "scope": "user", "version": "1.0.0" },
                    { "scope": "project", "version": "1.0.0" }
                ]
            }
        }"#;
        let pkgs = parse(contents);
        assert_eq!(pkgs.len(), 2, "one coordinate per install record/scope");
    }

    #[test]
    fn missing_version_field_becomes_unknown() {
        let contents = r#"{ "version": 9, "plugins": { "p@m": [ { "scope": "user" } ] } }"#;
        let pkgs = parse(contents);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version, "unknown");
    }

    #[test]
    fn malformed_input_yields_empty_not_panic() {
        assert!(parse("not json").is_empty());
        assert!(parse("{}").is_empty());
        assert!(parse(r#"{"plugins": 7}"#).is_empty());
    }
}
