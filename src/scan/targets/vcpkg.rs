//! vcpkg (C/C++): manifest `vcpkg.json` and the resolved install DB
//! `vcpkg_installed/vcpkg/status` (Debian-control text). vcpkg has **no OSV
//! ecosystem**, so coordinates are inventory-only (no advisory-key matches);
//! port names are vcpkg-specific slugs, not upstream names.
//!
//! Two targets:
//!   * [`VcpkgStatusTarget`], the lockfile-equivalent: `vcpkg/status` lists
//!     every installed direct + transitive package with an exact `Version`
//!     (+ optional `Port-Version`) and the triplet `Architecture`.
//!   * [`VcpkgManifestTarget`], the declared `vcpkg.json`. Dependencies there
//!     are usually unpinned (`version>=` floors), so we only emit pinned data:
//!     the top-level `overrides[]` array, plus a port self-manifest's own
//!     `name` + version when present.

use super::ScanTarget;
use super::support::{Emitter, path_ends_with, read_text};
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::path::Path;

/// Resolved coordinates from `vcpkg_installed/vcpkg/status` (best source).
pub struct VcpkgStatusTarget;

impl ScanTarget for VcpkgStatusTarget {
    fn ecosystem_id(&self) -> &'static str {
        "vcpkg"
    }

    /// Matches the install DB at `.../vcpkg/status` component-wise (separator-
    /// agnostic, never mid-component). The `vcpkg/` parent disambiguates it
    /// from e.g. a dpkg `status` file.
    fn detects(&self, path: &Path) -> bool {
        path_ends_with(path, &["vcpkg", "status"])
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        // Dedupe by (name, triplet): feature sub-paragraphs repeat the package
        // name, and distinct triplets legitimately produce the same name twice.
        let mut seen: HashSet<(String, String)> = HashSet::new();
        for (name, version, triplet) in parse_status(&contents) {
            if seen.insert((name.clone(), triplet)) {
                out.pkg(&name, &version, None);
            }
        }
    }
}

/// Declared/pinned coordinates from a `vcpkg.json` manifest (overrides + self).
/// `vcpkg.json` is an unambiguous vcpkg marker; no other C/C++ manager uses
/// that name (Conan: `conanfile.*`; CMake: `CMakeLists.txt`).
pub(super) fn vcpkg_json(contents: &str, out: &mut Emitter<'_>) {
    // Strict JSON (no `//` comments / trailing commas). A hand-edited file
    // with comments is invalid JSON; tolerate it by reporting nothing.
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("vcpkg.json is not valid JSON");
        return;
    };
    // First-wins by name: a port self-manifest beats an override of itself.
    let mut seen: HashSet<String> = HashSet::new();
    for (name, version) in parse_manifest(&json) {
        if seen.insert(name.clone()) {
            out.pkg(&name, &version, None);
        }
    }
}

/// Parse the Debian-control `vcpkg/status` DB into `(name, version, triplet)`.
///
/// Paragraphs are separated by blank lines; each `Field: value` field name
/// starts at column 0. We only keep packages whose `Status` ends in
/// `ok installed`, and fold a nonzero `Port-Version` into the version as
/// `<version>#<port-version>`.
fn parse_status(contents: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for paragraph in contents.split("\n\n") {
        let mut package_name: Option<String> = None;
        let mut version: Option<String> = None;
        let mut port_version: u64 = 0;
        let mut triplet = String::new();
        let mut status: Option<String> = None;

        for line in paragraph.lines() {
            // Continuation lines (Debian-style) begin with whitespace and belong
            // to the previous field; none of our fields are multi-line, so skip.
            if line.starts_with(' ') || line.starts_with('\t') {
                continue;
            }
            let Some((field, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match field {
                "Package" => package_name = Some(value.to_string()),
                "Version" => version = Some(value.to_string()),
                "Port-Version" => port_version = value.parse().unwrap_or(0),
                "Architecture" => triplet = value.to_string(),
                "Status" => status = Some(value.to_string()),
                _ => {}
            }
        }

        let Some(name) = package_name else { continue };
        let Some(ver) = version else { continue };
        if !status.is_some_and(|s| s.ends_with("ok installed")) {
            continue;
        }
        out.push((name, format_version(&ver, port_version), triplet));
    }
    out
}

/// Pinned/self coordinates from a parsed `vcpkg.json` `(name, version)`.
///
/// Sources, in order: a port self-manifest's own `name` + version field, then
/// the top-level `overrides[]` exact pins. Bare `dependencies` / `version>=`
/// floors are deliberately ignored; they are not resolved versions.
fn parse_manifest(json: &JsonValue) -> Vec<(String, String)> {
    let mut out = Vec::new();

    // Port self-manifest: a top-level `name` plus a version-scheme field that
    // describes THIS package. (A consumer/project manifest has no self version.)
    if let Some(name) = json.get("name").and_then(|v| v.as_str())
        && let Some(version) = manifest_version(json)
    {
        out.push((name.to_string(), version));
    }

    // Top-level `overrides[]`: each `{ "name", "version" }` is an exact pin.
    if let Some(overrides) = json.get("overrides").and_then(|v| v.as_array()) {
        for entry in overrides {
            let Some(name) = entry.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(version) = manifest_version(entry) else {
                continue;
            };
            out.push((name.to_string(), version));
        }
    }

    out
}

/// Read whichever of vcpkg's four version-scheme keys is present and fold in an
/// optional `port-version`. Returns `None` if no version field is present.
fn manifest_version(obj: &JsonValue) -> Option<String> {
    let raw = [
        "version",
        "version-semver",
        "version-date",
        "version-string",
    ]
    .iter()
    .find_map(|key| obj.get(*key).and_then(|v| v.as_str()))?;
    // The override form may already carry `#N`; otherwise read `port-version`.
    if raw.contains('#') {
        return Some(raw.to_string());
    }
    let port_version = obj
        .get("port-version")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    Some(format_version(raw, port_version))
}

/// vcpkg-canonical textual version: `<version>#<port-version>`, omitting the
/// `#N` suffix when the port-version is 0.
fn format_version(version: &str, port_version: u64) -> String {
    if port_version > 0 {
        format!("{version}#{port_version}")
    } else {
        version.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_db() {
        let input = "Package: zlib\nVersion: 1.3.1\nArchitecture: x64-linux\nStatus: install ok installed\n\nPackage: fmt\nVersion: 10.1.1\nPort-Version: 1\nDepends: vcpkg-cmake\nArchitecture: x64-linux\nStatus: install ok installed\n\nPackage: oldpkg\nVersion: 0.9.0\nArchitecture: x64-linux\nStatus: purge ok not-installed\n";
        let parsed = parse_status(input);
        // oldpkg is not-installed → dropped; port-version folded into fmt.
        assert_eq!(
            parsed,
            vec![
                (
                    "zlib".to_string(),
                    "1.3.1".to_string(),
                    "x64-linux".to_string()
                ),
                (
                    "fmt".to_string(),
                    "10.1.1#1".to_string(),
                    "x64-linux".to_string()
                ),
            ]
        );
    }

    #[test]
    fn manifest_overrides_pin_versions() {
        let json: JsonValue = serde_json::from_str(
            r#"{
                "dependencies": ["zlib", { "name": "fmt", "version>=": "10.0.0" }, "openssl"],
                "builtin-baseline": "3426db05b996481ca31e95fff3734cf23e0f51bc",
                "overrides": [
                    { "name": "zlib", "version": "1.3.1" },
                    { "name": "fmt",  "version": "10.1.1#1" }
                ]
            }"#,
        )
        .unwrap();
        let parsed = parse_manifest(&json);
        // Only overrides are pinned; bare deps / version>= floors are skipped.
        assert_eq!(
            parsed,
            vec![
                ("zlib".to_string(), "1.3.1".to_string()),
                ("fmt".to_string(), "10.1.1#1".to_string()),
            ]
        );
    }

    #[test]
    fn port_self_manifest_emits_itself() {
        let json: JsonValue =
            serde_json::from_str(r#"{ "name": "fmt", "version": "10.1.1", "port-version": 2 }"#)
                .unwrap();
        assert_eq!(
            parse_manifest(&json),
            vec![("fmt".to_string(), "10.1.1#2".to_string())]
        );
    }
}
