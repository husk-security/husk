//! Vim/Neovim plugins (`lazy-lock.json` -> inventory-only, ecosystem
//! `vim-plugin`).
//!
//! lazy.nvim is the dominant Neovim plugin manager; its lockfile
//! `lazy-lock.json` is the only reliably machine-parseable, version-pinned
//! artifact in this ecosystem. It is a flat top-level JSON object mapping a
//! plugin *name* (the repo's last path segment, e.g. `nvim-treesitter`,
//! `telescope.nvim`, `LuaSnip`) to an entry object:
//!
//! ```json
//! { "branch": "master", "commit": "<40-hex-sha>", "version": "v3.2.1" }
//! ```
//!
//! Canonical pinned version = the git `commit` SHA (immutable). `branch` is a
//! moving ref and is NOT used as a version. `version` (a semver tag) is an
//! optional secondary label, used only when no `commit` is present.
//!
//! Users commit this file into their dotfiles repos, so it appears anywhere on
//! disk, not just at `~/.config/nvim/lazy-lock.json`; we detect by file name.
//!
//! There is **no OSV / GitHub-advisory ecosystem** for vim/neovim plugins, so
//! this is purely an inventory coordinate (see `model::PackageRef::osv_ecosystem`,
//! which returns `None` for it). The lockfile also drops the repo owner, so the
//! recorded name is ambiguous-by-design (two different `config.nvim` repos
//! collide). Even so, a pinned-commit inventory lets us flag known-bad
//! commits/repos retroactively absent a vuln DB; plugins run arbitrary
//! Lua/Vimscript on load (a large RCE surface) and editor-extension ecosystems
//! are actively targeted (the 2025 GlassWorm OpenVSX worm), hence the AI
//! category.
//!
//! packer.nvim (`packer_compiled.lua`), vim-plug, and the lazy install root's
//! clone dirs are presence-only signals with no serde-parseable pinned
//! coordinates, so they are intentionally NOT handled here.

use super::support::{Emitter, LineFinder};
use serde_json::Value as JsonValue;

/// The entry shape is read defensively (object OR bare string) so hand-edited
/// or forked-writer files still yield records.
pub(super) fn lazy_lock(contents: &str, out: &mut Emitter<'_>) {
    let root = match serde_json::from_str::<JsonValue>(contents) {
        Ok(JsonValue::Object(root)) => root,
        _ => {
            out.warn("lazy-lock.json is not valid JSON");
            return;
        }
    };
    // Anchor report lines on the plugin name keys; entries are in file order,
    // so the finder scans the file once.
    let mut lines = LineFinder::new(contents);
    for (name, entry) in &root {
        let Some(version) = entry_version(entry) else {
            continue;
        };
        let line = lines.find(&format!("\"{name}\""));
        out.pkg(name, &version, line);
    }
}

/// Resolve the canonical pinned version of one lockfile entry.
///
/// Preference order: the git `commit` SHA (exact, immutable) > the semver
/// `version` tag (a secondary human label). The `branch` field is deliberately
/// ignored; it is a moving ref like `main`/`master`. The current lazy.nvim
/// writer always emits an object, but we also accept a bare-string value and
/// treat it as the commit SHA (guards against hand edits / older forks).
fn entry_version(entry: &JsonValue) -> Option<String> {
    match entry {
        // Hand-edited / forked-writer shorthand: the value is the SHA itself.
        JsonValue::String(sha) if !sha.is_empty() => Some(sha.clone()),
        JsonValue::Object(map) => {
            if let Some(commit) = map.get("commit").and_then(JsonValue::as_str)
                && !commit.is_empty()
            {
                return Some(commit.to_string());
            }
            map.get("version")
                .and_then(JsonValue::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str) -> Vec<PackageRef> {
        run_parser("vim-plugin", contents, lazy_lock)
    }

    #[test]
    fn entry_version_prefers_commit_over_branch_and_tag() {
        let entry: JsonValue = serde_json::from_str(
            r#"{ "branch": "master", "commit": "538e37ba87284942c1d76ed38dd497e54e65b891", "version": "v0.9.2" }"#,
        )
        .expect("valid json");
        assert_eq!(
            entry_version(&entry).as_deref(),
            Some("538e37ba87284942c1d76ed38dd497e54e65b891")
        );
    }

    #[test]
    fn entry_version_accepts_bare_string_and_tag_fallback() {
        // Hand-edited bare-string value == commit sha.
        let bare = JsonValue::String("abc1234".to_string());
        assert_eq!(entry_version(&bare).as_deref(), Some("abc1234"));

        // No commit: fall back to the semver tag.
        let tag_only: JsonValue =
            serde_json::from_str(r#"{ "branch": "main", "version": "v3.2.1" }"#).expect("json");
        assert_eq!(entry_version(&tag_only).as_deref(), Some("v3.2.1"));

        // Neither commit nor version, and null entries -> skipped.
        let branch_only: JsonValue = serde_json::from_str(r#"{ "branch": "main" }"#).expect("json");
        assert_eq!(entry_version(&branch_only), None);
        assert_eq!(entry_version(&JsonValue::Null), None);
    }

    #[test]
    fn parses_sample_lockfile() {
        let body = r#"{
  "LuaSnip": { "branch": "master", "commit": "8ae1dedd988eb56441b7858bd1e8554dfadaa46d" },
  "nvim-treesitter": { "branch": "master", "commit": "538e37ba87284942c1d76ed38dd497e54e65b891", "version": "v0.9.2" },
  "telescope.nvim": { "branch": "0.1.x", "commit": "d90956833d7c27e73c621a61f20b29fdb7122709" }
}"#;
        let pkgs = parse(body);
        assert_eq!(pkgs.len(), 3);
        // serde_json maps are unordered: look up by name.
        let find = |name: &str| pkgs.iter().find(|p| p.name == name);
        assert_eq!(
            find("LuaSnip").map(|p| p.version.as_str()),
            Some("8ae1dedd988eb56441b7858bd1e8554dfadaa46d")
        );
        // commit wins over the version tag.
        assert_eq!(
            find("nvim-treesitter").map(|p| p.version.as_str()),
            Some("538e37ba87284942c1d76ed38dd497e54e65b891")
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == "vim-plugin"));
        assert!(pkgs.iter().all(|p| p.line.is_some()));
    }

    #[test]
    fn empty_object_and_malformed_yield_empty() {
        assert!(parse("{}").is_empty());
        assert!(parse("{ not json").is_empty());
    }
}
