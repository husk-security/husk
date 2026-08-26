//! Firefox add-ons: per-profile `extensions.json` -> ecosystem `firefox-addon`.
//!
//! Inventory-only: no OSV/GHSA ecosystem covers Firefox add-ons (Mozilla's
//! blocklist is fetched at browser runtime, not a local file), so the goal is
//! a faithful `id@version` inventory to match against curated blocklists.
//! Coordinates key on the canonical add-on `id` (email-style or brace-GUID);
//! the `version` is toolkit-format, NOT semver; stored verbatim.
//!
//! Unrelated `extensions.json` files (e.g. VS Code recommendations) are
//! excluded by (a) requiring a Mozilla/Firefox path marker in `detects()` and
//! (b) requiring an `addons` array at parse time. Mozilla-shipped
//! builtin/system add-ons (`location` starting `app-builtin`/`app-system`)
//! are not third-party attack surface and are skipped.

use super::ScanTarget;
use super::support::{Emitter, LineFinder, read_text};
use serde_json::Value as JsonValue;
use std::path::Path;

const ECOSYSTEM: &str = "firefox-addon";

pub struct FirefoxAddonTarget;

impl ScanTarget for FirefoxAddonTarget {
    fn ecosystem_id(&self) -> &'static str {
        ECOSYSTEM
    }

    fn detects(&self, path: &Path) -> bool {
        let is_file = matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("extensions.json")
        );
        is_file && path_has_firefox_marker(&path.to_string_lossy())
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(contents) = read_text(path, out) {
            parse_db(&contents, out);
        }
    }
}

/// Deliberately broad marker (just `mozilla` or `firefox`, any case, either
/// separator); Snap/Flatpak/ESR/Nightly relocations all still carry the
/// substring.
fn path_has_firefox_marker(raw_path: &str) -> bool {
    let lowered = raw_path.replace('\\', "/").to_ascii_lowercase();
    lowered.contains("mozilla") || lowered.contains("firefox")
}

/// Requires an `addons` array at the root; anything else (a VS Code
/// recommendations file, `{}`, a truncated mid-write dump) yields an empty
/// inventory with no warning. Coordinates key on the stable add-on `id`, not
/// the localized display name.
fn parse_db(contents: &str, out: &mut Emitter<'_>) {
    let Ok(root) = serde_json::from_str::<JsonValue>(contents) else {
        return;
    };
    let Some(JsonValue::Array(addons)) = root.get("addons") else {
        return;
    };

    let mut lines = LineFinder::new(contents);
    for addon in addons {
        // Coordinates are trimmed on emission so a padded value in an
        // oddly-serialized db still matches blocklist entries exactly.
        let Some(id) = addon
            .get("id")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };

        let Some(version) = addon
            .get("version")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };

        if is_builtin_location(addon.get("location").and_then(JsonValue::as_str)) {
            continue;
        }

        out.pkg(id, version, lines.find(id));
    }
}

/// Mozilla-bundled locations (`app-builtin*`, `app-system*`). A missing
/// location is treated as installed so a genuine entry is never dropped on
/// schema variance.
fn is_builtin_location(location: Option<&str>) -> bool {
    matches!(location, Some(loc) if loc.starts_with("app-builtin") || loc.starts_with("app-system"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn detects_marker_on_normalized_paths() {
        // Linux, macOS, and Windows (backslash + AppData) layouts all match.
        assert!(path_has_firefox_marker(
            "/home/dev/.mozilla/firefox/abc.default-release/extensions.json"
        ));
        assert!(path_has_firefox_marker(
            "/Users/dev/Library/Application Support/Firefox/Profiles/x.default/extensions.json"
        ));
        assert!(path_has_firefox_marker(
            r"C:\Users\dev\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\extensions.json"
        ));
        // A VS Code workspace recommendations file has no Mozilla/Firefox marker.
        assert!(!path_has_firefox_marker(
            "/home/dev/project/.vscode/extensions.json"
        ));
    }

    #[test]
    fn parses_addons_keyed_on_id_skipping_builtins() {
        let json = r#"{
            "schemaVersion": 35,
            "addons": [
                {
                    "id": "uBlock0@raymondhill.net",
                    "version": "1.57.2",
                    "type": "extension",
                    "location": "app-profile",
                    "defaultLocale": { "name": "uBlock Origin" }
                },
                {
                    "id": "{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}",
                    "version": "2.0.3",
                    "type": "extension",
                    "location": "app-profile",
                    "signedState": 0,
                    "defaultLocale": { "name": "Sideloaded Helper" }
                },
                {
                    "id": "default-theme@mozilla.org",
                    "version": "1.3",
                    "type": "theme",
                    "location": "app-builtin",
                    "defaultLocale": { "name": "System theme" }
                }
            ]
        }"#;
        let pkgs = run_parser(ECOSYSTEM, json, parse_db);
        // Two app-profile add-ons; the app-builtin theme is filtered out.
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().all(|p| p.ecosystem == "firefox-addon"));

        let ublock = pkgs
            .iter()
            .find(|p| p.name == "uBlock0@raymondhill.net")
            .expect("ublock present");
        assert_eq!(ublock.version, "1.57.2");

        let guid = pkgs
            .iter()
            .find(|p| p.name == "{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}")
            .expect("guid add-on present");
        // Toolkit version stored verbatim.
        assert_eq!(guid.version, "2.0.3");
    }

    #[test]
    fn skips_vscode_recommendations_object() {
        // No `addons` key -> nothing emitted (the parse-time safety net).
        let json = r#"{ "recommendations": ["ms-python.python"],
                        "unwantedRecommendations": [] }"#;
        let pkgs = run_parser(ECOSYSTEM, json, parse_db);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn skips_entries_without_version() {
        let json = r#"{ "addons": [ { "id": "noversion@example.com" } ] }"#;
        let pkgs = run_parser(ECOSYSTEM, json, parse_db);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn skips_whitespace_only_id_and_version() {
        // A whitespace-only id or version is as useless as an empty one and
        // must not produce a coordinate.
        let json = r#"{ "addons": [
            { "id": "   ", "version": "1.0" },
            { "id": "real@example.com", "version": "  " }
        ] }"#;
        let pkgs = run_parser(ECOSYSTEM, json, parse_db);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn trims_padded_id_and_version() {
        // Padded coordinates are normalized, not dropped: the emitted package
        // must carry the trimmed id/version so blocklist matching stays exact.
        let json = r#"{ "addons": [
            { "id": "  addon@example.com  ", "version": " 1.0 " }
        ] }"#;
        let pkgs = run_parser(ECOSYSTEM, json, parse_db);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "addon@example.com");
        assert_eq!(pkgs[0].version, "1.0");
    }

    #[test]
    fn tolerates_malformed_json() {
        let pkgs = run_parser(ECOSYSTEM, r#"{ "addons": [ { truncated"#, parse_db);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn builtin_location_classifier() {
        assert!(is_builtin_location(Some("app-builtin")));
        assert!(is_builtin_location(Some("app-system-defaults")));
        assert!(!is_builtin_location(Some("app-profile")));
        assert!(!is_builtin_location(Some("app-global")));
        assert!(!is_builtin_location(None));
    }
}
