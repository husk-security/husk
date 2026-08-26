//! PureScript / Spago (`spago.lock` → no OSV ecosystem; inventory-only).
//!
//! Modern Spago ("Spago Next", the PureScript rewrite, 0.93.x+ / package 0.21+)
//! writes `spago.lock` as **strict JSON** (despite the project manifest
//! `spago.yaml` being YAML). The lock's top-level `packages` object is the
//! fully-resolved, flat transitive dependency graph; each entry carries a
//! `type` discriminator (`registry` | `git` | `local`). Registry entries pin an
//! exact SemVer `version`; git entries pin a commit `rev`; local entries are
//! first-party workspace source and are skipped.
//!
//! PureScript is not a supported OSV.dev / GitHub-Advisory ecosystem, so these
//! coordinates are surfaced for inventory/SBOM purposes only; there is no
//! advisory feed to match against yet.

use super::support::{Emitter, LineFinder};
use serde_json::Value as JsonValue;

/// spago.lock: walk the flat `packages` map into coordinates.
///
/// `registry` → (name=key, version=`version`); `git` → (name=key,
/// version=`rev`); `local` (first-party workspace source) is skipped.
pub(super) fn spago_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("spago.lock is not valid JSON");
        return;
    };
    let Some(map) = json.get("packages").and_then(|v| v.as_object()) else {
        return;
    };
    let mut lines = LineFinder::new(contents);
    for (name, entry) in map {
        let Some(version) = coordinate_version(entry) else {
            continue;
        };
        out.pkg(name, &version, lines.find(&format!("\"{name}\"")));
    }
}

fn coordinate_version(entry: &JsonValue) -> Option<String> {
    match entry.get("type").and_then(|t| t.as_str()) {
        Some("registry") => entry.get("version").and_then(|v| v.as_str()).map(normalize),
        // Git deps have no semantic version: use the pinned commit SHA.
        Some("git") => entry.get("rev").and_then(|v| v.as_str()).map(normalize),
        _ => None,
    }
}

/// PureScript Registry versions are strict SemVer (no leading `v`), but strip a
/// leading `v`/`V` and trim defensively. (Deliberately unconditional, unlike
/// [`super::support::strip_v`], and it also trims whitespace.)
fn normalize(raw: &str) -> String {
    raw.trim()
        .strip_prefix(['v', 'V'])
        .unwrap_or(raw.trim())
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    const SAMPLE: &str = r#"{
  "workspace": {
    "packages": {
      "my-app": { "path": "./", "core": { "dependencies": ["aff"] } }
    },
    "package_set": { "address": { "registry": "75.3.0" } }
  },
  "packages": {
    "aff": { "type": "registry", "version": "8.0.0", "dependencies": ["prelude"] },
    "prelude": { "type": "registry", "version": "6.0.1", "dependencies": [] },
    "my-git-lib": {
      "type": "git",
      "url": "https://github.com/example/purescript-my-git-lib.git",
      "rev": "035a51d02ba9f8b70c3ffd9fe31a3f5bed19941c"
    },
    "my-local": { "type": "local", "path": "../local" }
  }
}"#;

    #[test]
    fn parses_registry_git_and_skips_local() {
        let pkgs = run_parser("purescript", SAMPLE, spago_lock);

        // Three external deps (registry x2 + git); the `local` entry is skipped.
        assert_eq!(pkgs.len(), 3);

        let aff = pkgs.iter().find(|p| p.name == "aff").unwrap();
        assert_eq!(aff.version, "8.0.0");
        assert_eq!(aff.ecosystem, "purescript");

        let git = pkgs.iter().find(|p| p.name == "my-git-lib").unwrap();
        assert_eq!(git.version, "035a51d02ba9f8b70c3ffd9fe31a3f5bed19941c");

        assert!(pkgs.iter().all(|p| p.name != "my-local"));
        // Canonical names carry no historical `purescript-` prefix.
        assert!(pkgs.iter().all(|p| !p.name.starts_with("purescript-")));
    }

    #[test]
    fn normalize_strips_leading_v() {
        assert_eq!(normalize(" v8.0.0 "), "8.0.0");
        assert_eq!(normalize("6.0.1"), "6.0.1");
    }

    #[test]
    fn tolerates_missing_packages_map() {
        assert!(run_parser("purescript", "{\"workspace\": {}}", spago_lock).is_empty());
    }
}
