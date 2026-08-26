//! Shopify themes & apps: `config/settings_schema.json` (themes) and
//! `shopify.app.toml` / `shopify.app.<config>.toml` (apps) -> ecosystem
//! `"shopify"`.
//!
//! **No OSV/GHSA ecosystem exists for Shopify themes or apps**, so this target
//! is strictly **inventory-only**: it records coordinates for visibility and
//! `PackageRef::osv_ecosystem` has no mapping for `"shopify"`. A theme's or
//! app's *real* vulnerability surface lives in its bundled npm/RubyGems
//! dependencies, which the npm/rubygems scanners already cover; we deliberately
//! do **not** re-parse those sibling lockfiles here (double-counting hazard).
//!
//! ## Source files
//! - **Themes (primary, versioned):** a file named exactly `settings_schema.json`
//!   whose immediate parent directory is named exactly `config`. The top level
//!   is a JSON **array** of setting-category objects; the element whose
//!   `"name" == "theme_info"` carries `theme_name` (-> coordinate name) and
//!   `theme_version` (-> coordinate version, a free-form string). `theme_info`
//!   is conventionally the first element but is scanned positionally-agnostic.
//!   A blank/missing `theme_version` (common in forks/WIP themes) is treated as
//!   absent and the entry is skipped.
//! - **Apps (presence marker, no version):** `shopify.app.toml` (and the
//!   multi-environment variants `shopify.app.<config>.toml`). TOML carrying
//!   top-level `name` (-> coordinate name) and `client_id` (stable identity, NOT
//!   a version). Apps have no version field anywhere, so they are emitted as
//!   presence markers with an empty version: one marker per config file, so a
//!   project with `shopify.app.toml` + `shopify.app.<env>.toml` variants shows
//!   one entry per variant (each is an independently-attackable config).
//!
//! `config/settings_data.json` (merchant-set values, no version) and
//! `shopify.web.toml` / `extensions/*/shopify.extension.toml` (api_version is a
//! `YYYY-MM` platform contract, never a release) are intentionally NOT detectors.

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name, find_line};
use serde_json::Value as JsonValue;
use std::path::Path;
use toml::Value as TomlValue;

/// One Shopify coordinate (a theme or an app). `version` is empty for apps
/// (presence-only) and a verbatim free-form string for themes.
#[derive(Debug, PartialEq, Eq)]
struct ShopifyCoord {
    name: String,
    version: String,
}

pub struct ShopifyThemeTarget;

impl ScanTarget for ShopifyThemeTarget {
    fn ecosystem_id(&self) -> &'static str {
        "shopify"
    }

    fn detects(&self, path: &Path) -> bool {
        // Load-bearing path shape: `settings_schema.json` directly inside a dir
        // named `config`. A bare `settings_schema.json` elsewhere is NOT a
        // Shopify theme. Cheap path/stat only; contents validated in parse().
        if !matches!(file_name(path), Some("settings_schema.json")) {
            return false;
        }
        path.parent()
            .and_then(|dir| dir.file_name())
            .and_then(|n| n.to_str())
            == Some("config")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        if let Some(coord) = parse_theme(&contents) {
            out.pkg(
                &coord.name,
                &coord.version,
                find_line(&contents, "theme_info"),
            );
        }
    }
}

pub struct ShopifyAppTarget;

impl ScanTarget for ShopifyAppTarget {
    fn ecosystem_id(&self) -> &'static str {
        "shopify"
    }

    fn detects(&self, path: &Path) -> bool {
        match file_name(path) {
            Some("shopify.app.toml") => true,
            Some(name) => name.starts_with("shopify.app.") && name.ends_with(".toml"),
            None => false,
        }
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        if let Some(coord) = parse_app(&contents) {
            out.pkg(&coord.name, &coord.version, find_line(&contents, "name"));
        }
    }
}

/// Strip a UTF-8 BOM if present, so `serde_json`/`toml` parse cleanly.
fn strip_bom(s: &str) -> &str {
    s.strip_prefix('\u{feff}').unwrap_or(s)
}

/// Treat empty / `"0.0.0"` placeholder / null as an absent version.
fn version_is_absent(v: &str) -> bool {
    let t = v.trim();
    t.is_empty() || t == "0.0.0"
}

/// Pure helper: extract the theme coordinate from a `settings_schema.json` body.
///
/// The top level must be a JSON **array**; we scan every element for an object
/// with `"name" == "theme_info"` (NOT assumed at index 0). From the first match
/// we read `theme_name` (coordinate name, trimmed) and `theme_version`
/// (coordinate version, verbatim/trimmed). A non-string `theme_version` (e.g. a
/// number) is coerced to its display form. Returns `None` when: the body is not
/// an array, no `theme_info` element exists, the name is blank, or the version
/// is absent/placeholder (skip-if-absent). Parse errors propagate as `None` via
/// the caller so a malformed file never aborts the scan.
fn parse_theme(contents: &str) -> Option<ShopifyCoord> {
    let value: JsonValue = serde_json::from_str(strip_bom(contents)).ok()?;
    let array = value.as_array()?;

    let info = array
        .iter()
        .find(|el| el.get("name").and_then(JsonValue::as_str) == Some("theme_info"))?;

    let name = info.get("theme_name").and_then(JsonValue::as_str)?.trim();
    if name.is_empty() {
        return None;
    }

    // `theme_version` is required by spec but routinely blank/missing/non-string.
    let version = match info.get("theme_version") {
        Some(JsonValue::String(s)) => s.trim().to_string(),
        Some(JsonValue::Number(n)) => n.to_string(),
        _ => return None,
    };
    if version_is_absent(&version) {
        return None;
    }

    Some(ShopifyCoord {
        name: name.to_string(),
        version,
    })
}

/// Pure helper: extract the app presence-marker coordinate from a
/// `shopify.app[.<config>].toml` body. Reads top-level `name` (coordinate name).
/// There is **no** version field in this format: `client_id` is identity and
/// `api_version` (under `[webhooks]`) is a `YYYY-MM` platform contract, never a
/// release. So the version is always empty (presence marker). Returns `None`
/// when the TOML fails to parse or carries no non-blank top-level `name`.
fn parse_app(contents: &str) -> Option<ShopifyCoord> {
    // toml 1.x: parse a full document as a `Table` (str::parse::<Value>() now
    // expects a bare value).
    let table = strip_bom(contents).parse::<toml::Table>().ok()?;
    let name = table.get("name").and_then(TomlValue::as_str)?.trim();
    if name.is_empty() {
        return None;
    }
    Some(ShopifyCoord {
        name: name.to_string(),
        version: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAWN_SCHEMA: &str = r##"[
  {
    "name": "theme_info",
    "theme_name": "Dawn",
    "theme_author": "Shopify",
    "theme_version": "15.3.0",
    "theme_documentation_url": "https://help.shopify.com/manual/online-store/themes/themes-by-shopify/dawn",
    "theme_support_url": "https://support.shopify.com/"
  },
  {
    "name": "Colors",
    "settings": [
      { "type": "color", "id": "colors_accent_1", "label": "Accent 1", "default": "#121212" }
    ]
  }
]"##;

    #[test]
    fn theme_extracts_name_and_version() {
        let coord = parse_theme(DAWN_SCHEMA).expect("theme_info present with version");
        assert_eq!(
            coord,
            ShopifyCoord {
                name: "Dawn".into(),
                version: "15.3.0".into()
            }
        );
    }

    #[test]
    fn theme_info_not_first_element_is_still_found() {
        // Spec does not mandate index 0; scan all elements.
        let body = r#"[
            { "name": "Colors", "settings": [] },
            { "name": "theme_info", "theme_name": "Forked", "theme_version": "1.0" }
        ]"#;
        let coord = parse_theme(body).expect("theme_info found regardless of position");
        assert_eq!(coord.name, "Forked");
        assert_eq!(coord.version, "1.0");
    }

    #[test]
    fn theme_blank_or_placeholder_version_is_skipped() {
        let blank = r#"[{ "name": "theme_info", "theme_name": "Acme", "theme_version": "" }]"#;
        let placeholder =
            r#"[{ "name": "theme_info", "theme_name": "Acme", "theme_version": "0.0.0" }]"#;
        let missing = r#"[{ "name": "theme_info", "theme_name": "Acme" }]"#;
        assert!(parse_theme(blank).is_none());
        assert!(parse_theme(placeholder).is_none());
        assert!(parse_theme(missing).is_none());
    }

    #[test]
    fn theme_numeric_version_is_coerced() {
        let body = r#"[{ "name": "theme_info", "theme_name": "N", "theme_version": 2 }]"#;
        assert_eq!(parse_theme(body).unwrap().version, "2");
    }

    #[test]
    fn theme_top_level_object_is_not_a_theme() {
        // Older/hand-edited files using an object top level are skipped, not errored.
        let body = r#"{ "theme_info": { "theme_name": "X", "theme_version": "1.0.0" } }"#;
        assert!(parse_theme(body).is_none());
    }

    #[test]
    fn theme_handles_bom_and_malformed() {
        let bom = format!("\u{feff}{DAWN_SCHEMA}");
        assert_eq!(parse_theme(&bom).unwrap().name, "Dawn");
        // serde_json rejects comments/trailing commas -> None, never panics.
        assert!(parse_theme("[ { /* c */ } ]").is_none());
        assert!(parse_theme("not json").is_none());
    }

    const APP_TOML: &str = r#"name = "Acme Inventory Sync"
client_id = "a61950a2cbd5f32876b0b55587ec7a27"
application_url = "https://app.acme.test/"
embedded = true
handle = "acme-inventory-sync"

[access_scopes]
scopes = "read_products,write_products"

[webhooks]
api_version = "2025-04"

[build]
automatically_update_urls_on_dev = true
"#;

    #[test]
    fn app_emits_presence_marker_without_version() {
        let coord = parse_app(APP_TOML).expect("name present");
        assert_eq!(
            coord,
            ShopifyCoord {
                name: "Acme Inventory Sync".into(),
                version: String::new()
            }
        );
        // api_version (YYYY-MM platform contract) must NOT become the version.
        assert_ne!(coord.version, "2025-04");
    }

    #[test]
    fn app_without_name_is_skipped() {
        assert!(parse_app("client_id = \"abc\"\n").is_none());
        assert!(parse_app("name = \"\"\n").is_none());
        // Malformed TOML -> None, never panics.
        assert!(parse_app("name = = oops").is_none());
    }
}
