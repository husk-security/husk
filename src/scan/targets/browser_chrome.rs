//! Chromium browser extensions (Chrome / Edge / Brave / Chromium / Opera /
//! Vivaldi) -> ecosystem `chrome-extension`.
//!
//! Inventory-only: no OSV/GHSA ecosystem covers browser extensions; the
//! `name@version` (+ `[a-p]{32}` extension id) inventory matches against
//! curated malicious-extension IoC lists.
//!
//! Two independent detection paths, unioned by the walker:
//! 1. On-disk manifest:
//!    `.../<Profile>/Extensions/<[a-p]{32}-id>/<version>_<rev>/manifest.json`.
//!    Detection checks the `[a-p]{32}` grandparent id plus an `Extensions`
//!    ancestor (the version dir name is not validated), which disambiguates
//!    from unrelated `manifest.json` files (PWA manifests, npm web-ext
//!    projects).
//! 2. `Preferences` / `Secure Preferences` profile JSON: the
//!    `extensions.settings` map is the authoritative installed set.
//!
//! Localized names (`__MSG_<key>__`) are resolved from
//! `_locales/<default_locale>/messages.json` with a case-insensitive key
//! lookup (Chrome i18n), falling back to the raw placeholder or the ext id.

use super::support::{Emitter, LineFinder, read_text};
use super::{ScanTarget, file_name};
use serde_json::Value as JsonValue;
use std::fs;
use std::path::Path;

const ECOSYSTEM: &str = "chrome-extension";

pub struct BrowserChromeTarget;

impl ScanTarget for BrowserChromeTarget {
    fn ecosystem_id(&self) -> &'static str {
        ECOSYSTEM
    }

    fn detects(&self, path: &Path) -> bool {
        match file_name(path) {
            Some("manifest.json") => is_extension_manifest(path),
            Some("Preferences") | Some("Secure Preferences") => true,
            _ => false,
        }
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        match file_name(path) {
            Some("manifest.json") => parse_manifest(&contents, path, out),
            // "Preferences" / "Secure Preferences" share the same JSON shape.
            _ => parse_preferences(&contents, out),
        }
    }
}

/// True when the grandparent dir is a valid `[a-p]{32}` extension id and
/// some ancestor segment is exactly `Extensions` (case-sensitive). The
/// intermediate `<version>_<rev>` dir name is not validated.
fn is_extension_manifest(path: &Path) -> bool {
    let grandparent = path.parent().and_then(Path::parent);
    let Some(id) = grandparent
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
    else {
        return false;
    };
    if !is_extension_id(id) {
        return false;
    }
    grandparent
        .and_then(Path::parent)
        .map(|p| p.components().any(|c| c.as_os_str() == "Extensions"))
        .unwrap_or(false)
}

/// A Chromium extension id is exactly 32 chars from the mpdecimal alphabet
/// `a..=p` (NOT hex; validating as hex rejects every real id).
fn is_extension_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

fn parse_manifest(contents: &str, path: &Path, out: &mut Emitter<'_>) {
    let Ok(JsonValue::Object(manifest)) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("extension manifest.json is not valid JSON");
        return;
    };

    let ext_id = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let version = manifest
        .get("version")
        .and_then(JsonValue::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| {
            path.parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .map(version_from_dir_name)
        })
        .unwrap_or_default();

    if version.is_empty() {
        return;
    }

    let raw_name = manifest.get("name").and_then(JsonValue::as_str);
    let default_locale = manifest.get("default_locale").and_then(JsonValue::as_str);
    let ext_dir = path.parent();
    let name = raw_name
        .map(|n| resolve_name(n, default_locale, ext_dir).unwrap_or_else(|| n.to_string()))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| ext_id.to_string());

    out.pkg(&name, &version, super::find_line(contents, "\"version\""));
}

/// Walks `extensions.settings` -> `<ext_id> -> { manifest: { name, version } }`.
fn parse_preferences(contents: &str, out: &mut Emitter<'_>) {
    let Ok(root) = serde_json::from_str::<JsonValue>(contents) else {
        return; // profile files are frequently mid-write; not worth a warning
    };
    // Borrow, don't clone: Secure Preferences can be megabytes.
    let Some(settings) = root
        .get("extensions")
        .and_then(|e| e.get("settings"))
        .and_then(JsonValue::as_object)
    else {
        return;
    };

    let mut lines = LineFinder::new(contents);
    for (ext_id, entry) in settings {
        let manifest = entry.get("manifest");
        let version = manifest
            .and_then(|m| m.get("version"))
            .and_then(JsonValue::as_str)
            .filter(|v| !v.is_empty());
        let Some(version) = version else {
            continue;
        };

        // No ext dir to walk here, so a `__MSG_` name stays raw.
        let name = manifest
            .and_then(|m| m.get("name"))
            .and_then(JsonValue::as_str)
            .filter(|n| !n.is_empty())
            .unwrap_or(ext_id.as_str());

        out.pkg(name, version, lines.find(ext_id));
    }
}

/// Strip the profile-local `_<revision>` suffix from a version dir name
/// (`"1.2.3_0"` -> `"1.2.3"`). The `_<n>` is NOT part of the version.
fn version_from_dir_name(dir: &str) -> String {
    match dir.rsplit_once('_') {
        Some((version, _rev)) if !version.is_empty() => version.to_string(),
        _ => dir.to_string(),
    }
}

/// Resolve a `__MSG_<key>__` i18n placeholder name via
/// `<ext_dir>/_locales/<default_locale|en|en_US>/messages.json`
/// (case-insensitive key, per Chrome). `None` if not a placeholder or
/// unresolvable.
fn resolve_name(
    name: &str,
    default_locale: Option<&str>,
    ext_dir: Option<&Path>,
) -> Option<String> {
    let key = message_key(name)?;
    let ext_dir = ext_dir?;
    let mut locales: Vec<&str> = Vec::new();
    if let Some(loc) = default_locale {
        locales.push(loc);
    }
    locales.push("en");
    locales.push("en_US");

    for locale in locales {
        let messages_path = ext_dir.join("_locales").join(locale).join("messages.json");
        if let Ok(text) = fs::read_to_string(&messages_path)
            && let Some(message) = lookup_message(&text, key)
        {
            return Some(message);
        }
    }
    None
}

fn message_key(name: &str) -> Option<&str> {
    name.strip_prefix("__MSG_")?.strip_suffix("__")
}

fn lookup_message(messages_json: &str, key: &str) -> Option<String> {
    let JsonValue::Object(map) = serde_json::from_str::<JsonValue>(messages_json).ok()? else {
        return None;
    };
    for (k, entry) in &map {
        if k.eq_ignore_ascii_case(key) {
            return entry
                .get("message")
                .and_then(JsonValue::as_str)
                .filter(|m| !m.is_empty())
                .map(str::to_string);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use std::path::PathBuf;

    fn collect_manifest(contents: &str, path: &Path) -> Vec<PackageRef> {
        let mut pkgs = Vec::new();
        let mut warnings = Vec::new();
        let mut emitter = Emitter::new(ECOSYSTEM, path, &mut pkgs, &mut warnings);
        parse_manifest(contents, path, &mut emitter);
        pkgs
    }

    fn collect_preferences(contents: &str) -> Vec<PackageRef> {
        let mut pkgs = Vec::new();
        let mut warnings = Vec::new();
        let path = PathBuf::from("Default/Secure Preferences");
        let mut emitter = Emitter::new(ECOSYSTEM, &path, &mut pkgs, &mut warnings);
        parse_preferences(contents, &mut emitter);
        pkgs
    }

    #[test]
    fn validates_extension_id_alphabet() {
        // Real uBlock Origin id: 32 chars, all in a..=p.
        assert!(is_extension_id("cjpalhdlnbpafiamejdnhcphjbkeiagm"));
        // Hex-looking ids contain chars outside a..=p (e.g. 'z', digits).
        assert!(!is_extension_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_extension_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
        // Wrong length.
        assert!(!is_extension_id("abc"));
    }

    #[test]
    fn strips_revision_suffix_from_dir_name() {
        assert_eq!(version_from_dir_name("1.2.3_0"), "1.2.3");
        assert_eq!(version_from_dir_name("2.10.3.4567_12"), "2.10.3.4567");
        // No suffix -> verbatim.
        assert_eq!(version_from_dir_name("1.0"), "1.0");
    }

    #[test]
    fn extracts_and_looks_up_message_key() {
        assert_eq!(message_key("__MSG_appName__"), Some("appName"));
        assert_eq!(message_key("uBlock Origin"), None);

        let messages = r#"{
            "appName": { "message": "Google Translate", "description": "name" }
        }"#;
        // Case-insensitive key match per Chrome i18n.
        assert_eq!(
            lookup_message(messages, "APPNAME"),
            Some("Google Translate".to_string())
        );
        assert_eq!(lookup_message(messages, "missing"), None);
    }

    #[test]
    fn parses_on_disk_manifest() {
        let json = r#"{
            "manifest_version": 3,
            "name": "uBlock Origin",
            "version": "1.62.0",
            "default_locale": "en"
        }"#;
        let path = PathBuf::from(
            "Default/Extensions/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.62.0_0/manifest.json",
        );
        let pkgs = collect_manifest(json, &path);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "uBlock Origin");
        assert_eq!(pkgs[0].version, "1.62.0");
        assert_eq!(pkgs[0].ecosystem, "chrome-extension");
    }

    #[test]
    fn falls_back_to_dir_name_version_when_manifest_lacks_one() {
        let json = r#"{ "manifest_version": 3, "name": "Some Ext" }"#;
        let path = PathBuf::from(
            "Default/Extensions/abcdefghijklmnopabcdefghijklmnop/3.4.5_2/manifest.json",
        );
        let pkgs = collect_manifest(json, &path);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version, "3.4.5");
    }

    #[test]
    fn parses_preferences_settings_map() {
        let json = r#"{
            "extensions": {
                "settings": {
                    "cjpalhdlnbpafiamejdnhcphjbkeiagm": {
                        "manifest": { "name": "uBlock Origin", "version": "1.62.0" },
                        "state": 1, "from_webstore": true
                    },
                    "abcdefghijklmnopabcdefghijklmnop": {
                        "manifest": { "name": "Sketchy Side-Loaded Tool", "version": "0.1" },
                        "state": 1, "location": 4, "from_webstore": false
                    }
                }
            },
            "super_mac": "deadbeef"
        }"#;
        let pkgs = collect_preferences(json);
        assert_eq!(pkgs.len(), 2);
        // serde_json object maps are unordered: look up by name.
        let ublock = pkgs.iter().find(|p| p.name == "uBlock Origin").unwrap();
        assert_eq!(ublock.version, "1.62.0");
        let sketchy = pkgs
            .iter()
            .find(|p| p.name == "Sketchy Side-Loaded Tool")
            .unwrap();
        assert_eq!(sketchy.version, "0.1");
        assert!(pkgs.iter().all(|p| p.ecosystem == "chrome-extension"));
    }

    #[test]
    fn tolerates_malformed_json() {
        assert!(collect_preferences("{ truncated").is_empty());
        assert!(
            collect_manifest(
                "{ truncated",
                &PathBuf::from(
                    "Default/Extensions/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.0_0/manifest.json"
                )
            )
            .is_empty()
        );
    }
}
