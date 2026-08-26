//! VS Code / Cursor / Windsurf / VSCodium / code-server editor extensions
//! (`<extensions-dir>/extensions.json` installed registry -> ecosystem
//! `vscode-extension`).
//!
//! OSV covers this ecosystem: both the VS Code Marketplace and Open VSX are
//! filed under a single `VSCode` name, mapped in `PackageRef::osv_ecosystem`.
//! OSV matches `publisher.name` **case-sensitively**, so coordinates are
//! emitted exactly as published (see `parse_registry`). Exact *pinned* versions
//! matter: a malicious coordinate is a specific `publisher.name@version`
//! (attackers upload a benign version to pass vetting, then push a malicious
//! update).
//!
//! Detection target is the per-editor installed registry that VS Code and its
//! forks maintain:
//!   - `~/.vscode/extensions/extensions.json`
//!   - `~/.vscode-insiders/extensions/extensions.json`
//!   - `~/.vscode-server*/extensions/extensions.json` (remote / SSH / WSL)
//!   - `~/.vscode-oss/extensions/extensions.json` (VSCodium / code-oss)
//!   - `~/.cursor/extensions/extensions.json`
//!   - `~/.windsurf*/extensions/extensions.json`
//!   - `~/.local/share/code-server/extensions/extensions.json`
//!
//! The file is a strict-JSON **array** of installed-extension objects, each
//! carrying `identifier.id` (canonical `publisher.name`) and an exact
//! `version`. We deliberately do NOT treat a `<project>/.vscode/extensions.json`
//! (the workspace *recommendations* file: a JSON *object* with
//! `recommendations`/`unwantedRecommendations`, no versions) as installed
//! inventory: it shares the basename but has a different parent dir and a
//! different root type, so we disambiguate by JSON root shape (array => parse,
//! object => skip).

use super::support::{Emitter, LineFinder, read_text};
use super::{ScanTarget, file_name};
use serde_json::Value as JsonValue;
use std::path::Path;

pub struct VsCodeExtensionTarget;

impl ScanTarget for VsCodeExtensionTarget {
    fn ecosystem_id(&self) -> &'static str {
        "vscode-extension"
    }

    /// Cheap path check: the file must be named `extensions.json` AND sit
    /// directly inside a directory named `extensions` (the per-editor
    /// installed-registry layout `<editor>/extensions/extensions.json`). This
    /// avoids hijacking a workspace `<project>/.vscode/extensions.json`
    /// recommendations file, whose parent dir is `.vscode`, not `extensions`.
    fn detects(&self, path: &Path) -> bool {
        file_name(path) == Some("extensions.json")
            && path.parent().and_then(file_name) == Some("extensions")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(contents) = read_text(path, out) {
            parse_registry(&contents, out);
        }
    }
}

/// Parse an `extensions.json` installed registry into coordinates.
///
/// The root MUST be a JSON array (the installed registry). If the root is an
/// object (the workspace *recommendations* file) we emit nothing (silently:
/// it is a different, valid file type, not a parse failure) rather than
/// reporting suggestions as installs. Malformed/truncated JSON warns.
fn parse_registry(contents: &str, out: &mut Emitter<'_>) {
    let entries = match serde_json::from_str::<JsonValue>(contents) {
        Ok(JsonValue::Array(entries)) => entries,
        Ok(_) => return, // recommendations file or other non-registry JSON
        Err(_) => {
            out.warn("extensions.json is not valid JSON");
            return;
        }
    };

    let mut lines = LineFinder::new(contents);
    for entry in &entries {
        // name = identifier.id, already canonical "publisher.name".
        let Some(id) = entry
            .get("identifier")
            .and_then(|i| i.get("id"))
            .and_then(JsonValue::as_str)
        else {
            continue;
        };
        if id.is_empty() {
            continue;
        }

        let rel = entry.get("relativeLocation").and_then(JsonValue::as_str);
        let version = match entry.get("version").and_then(JsonValue::as_str) {
            Some(v) if !v.is_empty() => normalize_version(v),
            _ => match rel.and_then(|r| version_from_dir_name(id, r)) {
                Some(v) => v,
                None => continue, // no pinned version recoverable -> skip
            },
        };

        // Canonical coordinate: `publisher.name` exactly as published. The
        // marketplace and OpenVSX resolve identifiers case-insensitively, but
        // OSV's `VSCode` ecosystem does not: querying
        // `codeinklingon.git-worktree-menu` returns nothing while
        // `CodeInKlingon.git-worktree-menu` returns MAL-2025-191158. Lowercasing
        // here would silently drop every VSCode advisory. Case-insensitive
        // consumers lowercase at comparison time instead.
        let line = lines.find(id);

        out.pkg(id, &version, line);
    }
}

/// Normalize a version string: strip a leading `v` if present (rare). Platform
/// suffixes never appear in `extensions.json.version`, so nothing else to do;
/// pre-release / build metadata is kept as-is for exact IoC matching.
fn normalize_version(raw: &str) -> String {
    raw.strip_prefix('v').unwrap_or(raw).to_string()
}

/// Recover the version from a `publisher.name-version[-platform]` directory /
/// relativeLocation name, given the known `id` (`publisher.name`).
///
/// Splitting on the FIRST dash is wrong because publisher and name routinely
/// contain dashes (e.g. `ms-vscode.remote-explorer-0.4.3`). We know the id, so
/// we strip the `"<id>-"` prefix and then drop any trailing known-platform
/// suffix from what remains.
///
/// The prefix match is case-insensitive: the editor lowercases the on-disk
/// directory, so a case-sensitive strip would fail for every mixed-case
/// publisher and drop the extension entirely.
fn version_from_dir_name(id: &str, dir: &str) -> Option<String> {
    if !dir.get(..id.len())?.eq_ignore_ascii_case(id) {
        return None;
    }
    let rest = dir[id.len()..].strip_prefix('-')?;
    if rest.is_empty() {
        return None;
    }
    // Drop a trailing known target-platform suffix (`-<plat>`) if present.
    const PLATFORMS: &[&str] = &[
        "win32-x64",
        "win32-arm64",
        "linux-x64",
        "linux-arm64",
        "linux-armhf",
        "darwin-x64",
        "darwin-arm64",
        "alpine-x64",
        "alpine-arm64",
        "web",
        "universal",
    ];
    let mut version = rest;
    for plat in PLATFORMS {
        if let Some(stripped) = version.strip_suffix(plat).and_then(|v| v.strip_suffix('-')) {
            version = stripped;
            break;
        }
    }
    if version.is_empty() {
        return None;
    }
    Some(normalize_version(version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str) -> Vec<PackageRef> {
        run_parser("vscode-extension", contents, parse_registry)
    }

    #[test]
    fn parses_installed_registry_array() {
        let json = r#"[
            { "identifier": { "id": "ms-python.python" }, "version": "2024.4.1",
              "relativeLocation": "ms-python.python-2024.4.1" },
            { "identifier": { "id": "esbenp.prettier-vscode" }, "version": "10.4.0",
              "relativeLocation": "esbenp.prettier-vscode-10.4.0" }
        ]"#;
        let pkgs = parse(json);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "ms-python.python");
        assert_eq!(pkgs[0].version, "2024.4.1");
        assert_eq!(pkgs[1].name, "esbenp.prettier-vscode");
        assert_eq!(pkgs[1].version, "10.4.0");
        assert!(pkgs.iter().all(|p| p.ecosystem == "vscode-extension"));
    }

    #[test]
    fn skips_recommendations_object() {
        // Workspace recommendations file: object root, not an installed registry.
        let json = r#"{ "recommendations": ["ms-python.python"],
                        "unwantedRecommendations": [] }"#;
        assert!(parse(json).is_empty());
    }

    #[test]
    fn preserves_id_case_and_strips_leading_v() {
        // Case must survive: OSV's `VSCode` ecosystem matches exactly, so a
        // lowercased coordinate finds nothing. Verified against the live API:
        // `CodeInKlingon.git-worktree-menu` returns MAL-2025-191158, the
        // lowercased form returns `{}`.
        let json = r#"[{ "identifier": { "id": "Foo.Bar-Baz" }, "version": "v1.2.3" }]"#;
        let pkgs = parse(json);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "Foo.Bar-Baz");
        assert_eq!(pkgs[0].version, "1.2.3");
    }

    #[test]
    fn known_malicious_extension_maps_to_the_osv_vscode_ecosystem() {
        // Regression guard for the whole chain: a real GlassWorm coordinate has
        // to reach OSV in the exact shape the advisory is filed under, or the
        // mapping is a silent no-op.
        let json = r#"[{ "identifier": { "id": "CodeInKlingon.git-worktree-menu" },
                         "version": "1.0.9" }]"#;
        let pkgs = parse(json);
        assert_eq!(pkgs[0].name, "CodeInKlingon.git-worktree-menu");
        assert_eq!(
            pkgs[0].osv_ecosystem().as_deref(),
            Some("VSCode"),
            "vscode-extension must map to OSV's VSCode ecosystem"
        );
    }

    #[test]
    fn recovers_version_from_relative_location_with_platform_suffix() {
        // No top-level "version"; recover it from relativeLocation, dropping the platform.
        let json = r#"[{ "identifier": { "id": "ms-vscode.remote-explorer" },
                         "relativeLocation": "ms-vscode.remote-explorer-0.4.3-linux-x64" }]"#;
        let pkgs = parse(json);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "ms-vscode.remote-explorer");
        assert_eq!(pkgs[0].version, "0.4.3");
    }

    #[test]
    fn recovers_version_from_a_lowercased_directory_for_a_mixed_case_id() {
        // The editor lowercases the on-disk directory, so version recovery has
        // to match the id case-insensitively while the emitted coordinate keeps
        // the published case OSV indexes it under.
        let json = r#"[{ "identifier": { "id": "GitHub.vscode-pull-request-github" },
                         "relativeLocation": "github.vscode-pull-request-github-0.92.0" }]"#;
        let pkgs = parse(json);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "GitHub.vscode-pull-request-github");
        assert_eq!(pkgs[0].version, "0.92.0");
    }

    #[test]
    fn tolerates_malformed_json() {
        assert!(parse("[ { truncated").is_empty());
    }
}
