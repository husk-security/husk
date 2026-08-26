//! Scoop (Windows package manager): distro/system-package inventory.
//!
//! Scoop installs each app into a versioned directory under its root:
//! `<SCOOP>/apps/<name>/<version>/`, where `<SCOOP>` defaults to
//! `%USERPROFILE%\scoop` (user) or `%ProgramData%\scoop` (global, via
//! `$SCOOP`/`$SCOOP_GLOBAL`). At install time Scoop copies the bucket's
//! `manifest.json` verbatim into that directory (carrying the canonical pinned
//! `version` string) and writes a companion `install.json` (`bucket`,
//! `architecture`, `hold`, ...). The strongest proof that `name@version` is
//! installed is therefore the existence of
//! `<SCOOP>/apps/<name>/<version>/manifest.json`.
//!
//! Scoop is **not** a language ecosystem and has **no OSV / advisory
//! ecosystem id**: versions are free-form upstream strings (e.g. `2.54.0`,
//! `2.10.2.windows.1`, `nightly`), so this target is **inventory-only**:
//! coordinates are recorded, never advisory-matched.
//!
//! Pitfalls handled here:
//! - `apps/<name>/current` is an NTFS junction duplicating the active version
//!   dir; we never treat a `current` dir as a version, so we never double-count.
//! - `buckets/**` is the *catalog* (available, not installed) and is excluded
//!   by anchoring detection on the `apps` grandparent directory.
//! - `install.json` and its fields are optional; we degrade gracefully.
//! - If `manifest.json` is missing/corrupt we fall back to the directory name
//!   as the version (Scoop itself treats the dir name as authoritative).

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name};
use serde_json::Value as JsonValue;
use std::path::Path;

pub struct ScoopTarget;

impl ScanTarget for ScoopTarget {
    fn ecosystem_id(&self) -> &'static str {
        "scoop"
    }

    fn detects(&self, path: &Path) -> bool {
        // Only the per-install manifest copied under `apps/<name>/<version>/`.
        // Anchor on the layout so we exclude the `buckets/` catalog (which is
        // full of identically-named manifest.json files) and any stray JSON.
        if !matches!(file_name(path), Some("manifest.json")) {
            return false;
        }
        let Some(version_dir) = path.parent() else {
            return false;
        };
        // `current` is a junction duplicating the active version; skip it so we
        // never count the same install twice.
        if matches!(file_name(version_dir), Some("current")) {
            return false;
        }
        let Some(name_dir) = version_dir.parent() else {
            return false;
        };
        // The grandparent's parent must be `apps` (i.e. .../apps/<name>/<ver>/).
        matches!(name_dir.parent().and_then(file_name), Some("apps"))
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        // path = .../apps/<name>/<version>/manifest.json
        let version_dir = path.parent();
        let name_dir = version_dir.and_then(Path::parent);

        // App names are case-insensitive on Windows; store lowercase
        // (manifests/dirs are conventionally lowercase already).
        let dir_name = name_dir
            .and_then(file_name)
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if dir_name.is_empty() {
            return;
        }
        let dir_version = version_dir.and_then(file_name).unwrap_or("");

        let Some(contents) = read_text(path, out) else {
            return;
        };

        // Prefer the in-manifest `version`; fall back to the directory name
        // (Scoop's authoritative installed version) when absent/unparseable.
        let manifest_version = manifest_version(&contents);
        let version = manifest_version
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or(dir_version);
        let version = if version.is_empty() {
            "unknown"
        } else {
            version
        };

        // Fall back to line 1 rather than None so the finding still anchors.
        let line = super::find_line(&contents, "\"version\"").or(Some(1));
        out.pkg(&dir_name, version, line);
    }
}

/// Extract the top-level `version` string from a Scoop `manifest.json`.
/// Returns `None` if the JSON is malformed, has no `version`, or `version` is
/// not a string (rare real-world manifests); callers then fall back to the
/// version directory name.
fn manifest_version(contents: &str) -> Option<String> {
    let value: JsonValue = serde_json::from_str(contents).ok()?;
    value
        .get("version")
        .and_then(JsonValue::as_str)
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_top_level_version_string() {
        let manifest = r#"{
            "version": "2.54.0",
            "homepage": "https://gitforwindows.org/",
            "license": "GPL-2.0-only",
            "architecture": {
                "64bit": { "url": "https://example/dl.7z", "hash": "abc" }
            }
        }"#;
        assert_eq!(manifest_version(manifest).as_deref(), Some("2.54.0"));
    }

    #[test]
    fn preserves_non_semver_versions_verbatim() {
        // Scoop versions are free-form (4-segment, suffixed, or literal words).
        assert_eq!(
            manifest_version(r#"{"version":"2.10.2.windows.1"}"#).as_deref(),
            Some("2.10.2.windows.1")
        );
        assert_eq!(
            manifest_version(r#"{"version":"nightly"}"#).as_deref(),
            Some("nightly")
        );
    }

    #[test]
    fn missing_or_malformed_yields_none() {
        // No version key -> None (caller falls back to dir name).
        assert_eq!(manifest_version(r#"{"homepage":"https://x"}"#), None);
        assert_eq!(manifest_version(r#"{"version": 42}"#), None);
        // Broken JSON does not panic the scan.
        assert_eq!(manifest_version("{not json"), None);
    }
}
