//! Bun (`bun.lock` -> OSV `npm`).
//!
//! Since Bun v1.2 the default lockfile is the text-based `bun.lock`, a JSONC
//! document (JSON with `//` / `/* */` comments and trailing commas, like
//! `tsconfig.json`). The interesting section is `"packages"`, a map whose
//! values are arrays whose first element is the resolution key `"name@version"`
//! (e.g. `["lodash@4.17.21", ...]`). Bun packages resolve against the npm
//! registry, so we emit OSV ecosystem `npm`. The legacy binary `bun.lockb` is
//! deliberately ignored; it is not parseable statically.

use super::support::{Emitter, LineFinder, split_scoped_at, strip_jsonc};
use serde_json::Value as JsonValue;

/// Extract `name@version` coordinates from a `bun.lock` body.
pub(super) fn bun_lock(contents: &str, out: &mut Emitter<'_>) {
    let cleaned = strip_jsonc(contents);
    let root = match serde_json::from_str::<JsonValue>(&cleaned) {
        Ok(JsonValue::Object(root)) => root,
        _ => {
            out.warn("bun.lock is not valid JSON");
            return;
        }
    };
    let Some(JsonValue::Object(pkgs)) = root.get("packages") else {
        return;
    };
    // Locate lines in the ORIGINAL (uncleaned) text so reports point at the
    // source; entries are in file order, so the finder scans the file once.
    let mut lines = LineFinder::new(contents);
    for entry in pkgs.values() {
        let Some(key) = entry
            .as_array()
            .and_then(|a| a.first())
            .and_then(JsonValue::as_str)
        else {
            continue;
        };
        let Some((name, version)) = split_scoped_at(key) else {
            continue;
        };
        // Non-registry locators (workspace/root/link/file/git/tarball) are
        // first-party and would poison npm advisory matching.
        if !is_registry_version(version) {
            continue;
        }
        let line = lines.find(key);
        out.pkg(name, version, line);
    }
}

/// Bun encodes the resolution type in the version part: a locator prefix
/// marks a first-party or non-registry source with no OSV `npm` coverage;
/// a bare semver is a registry release.
fn is_registry_version(version: &str) -> bool {
    const LOCATOR_PREFIXES: [&str; 8] = [
        "workspace:",
        "link:",
        "file:",
        "git+",
        "github:",
        "root:",
        "http://",
        "https://",
    ];
    !LOCATOR_PREFIXES.iter().any(|p| version.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str) -> Vec<PackageRef> {
        run_parser("npm", contents, bun_lock)
    }

    #[test]
    fn parses_packages_with_comments_and_trailing_commas() {
        let body = r#"{
  // Bun text lockfile
  "lockfileVersion": 1,
  "packages": {
    "lodash": ["lodash@4.17.21", "", {}, "sha512-abc"],
    "@scope/util": ["@scope/util@1.2.3", "", {}, "sha512-def"], /* scoped */
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-ghi"],
  },
}"#;
        let pkgs = parse(body);
        assert_eq!(pkgs.len(), 3);
        // serde_json maps are unordered, so look coordinates up by name.
        let find = |name: &str| pkgs.iter().find(|p| p.name == name);
        assert_eq!(find("lodash").map(|p| p.version.as_str()), Some("4.17.21"));
        assert_eq!(
            find("@scope/util").map(|p| p.version.as_str()),
            Some("1.2.3")
        );
        assert_eq!(find("left-pad").map(|p| p.version.as_str()), Some("1.3.0"));
        assert!(pkgs.iter().all(|p| p.ecosystem == "npm"));
        assert!(pkgs.iter().all(|p| p.line.is_some()));
    }

    #[test]
    fn skips_workspace_and_root_locators() {
        let body = r#"{
  "lockfileVersion": 1,
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-abc"],
    "my-app": ["my-app@root:", { "bin": {} }],
    "@scoped/local": ["@scoped/local@workspace:packages/local"],
  }
}"#;
        let pkgs = parse(body);
        // Only the registry release survives; locator tuples are dropped.
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "left-pad");
        assert_eq!(pkgs[0].version, "1.3.0");
    }

    #[test]
    fn registry_version_classification() {
        assert!(is_registry_version("7.20.12"));
        assert!(is_registry_version("7.0.0-beta.55"));
        assert!(!is_registry_version("workspace:packages/local"));
        assert!(!is_registry_version("root:"));
        assert!(!is_registry_version("git+https://example.com/x.git"));
        assert!(!is_registry_version("github:user/repo"));
    }

    #[test]
    fn split_handles_scoped_names() {
        assert_eq!(
            split_scoped_at("lodash@4.17.21"),
            Some(("lodash", "4.17.21"))
        );
        assert_eq!(split_scoped_at("@a/b@1.0.0"), Some(("@a/b", "1.0.0")));
        assert_eq!(split_scoped_at("noversion"), None);
    }

    #[test]
    fn malformed_input_yields_empty() {
        assert!(parse("{ not valid").is_empty());
    }
}
