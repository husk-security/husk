//! npm / Node.js. Covers npm, pnpm, and yarn (classic + berry) lockfiles.
//! All resolve to OSV ecosystem `npm`.

use super::support::{Emitter, LineFinder};
use serde_json::Value as JsonValue;

/// package-lock.json / npm-shrinkwrap.json: the v2/v3 `packages` map (keyed by
/// `node_modules/...` path) plus the legacy v1 recursive `dependencies` tree
/// (also present in hybrid v2 lockfiles).
pub(super) fn package_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("npm lockfile is not valid JSON");
        return;
    };

    if let Some(entries) = json.get("packages").and_then(|value| value.as_object()) {
        let mut lines = LineFinder::new(contents);
        for (lock_path, entry) in entries {
            if lock_path.is_empty() {
                continue;
            }
            let Some(version) = entry.get("version").and_then(|value| value.as_str()) else {
                continue;
            };
            let name = entry
                .get("name")
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .or_else(|| npm_name_from_lock_path(lock_path));
            if let Some(name) = name {
                let line = lines.find(&name);
                out.pkg(&name, version, line);
            }
        }
    }

    if let Some(dependencies) = json.get("dependencies").and_then(|value| value.as_object()) {
        collect_npm_v1_deps(dependencies, &mut LineFinder::new(contents), out);
    }
}

fn collect_npm_v1_deps(
    dependencies: &serde_json::Map<String, JsonValue>,
    lines: &mut LineFinder<'_>,
    out: &mut Emitter<'_>,
) {
    for (name, entry) in dependencies {
        if let Some(version) = entry.get("version").and_then(|value| value.as_str()) {
            let line = lines.find(name);
            out.pkg(name, version, line);
        }
        if let Some(children) = entry
            .get("dependencies")
            .and_then(|value| value.as_object())
        {
            collect_npm_v1_deps(children, lines, out);
        }
    }
}

fn npm_name_from_lock_path(lock_path: &str) -> Option<String> {
    let marker = "node_modules/";
    let index = lock_path.rfind(marker)?;
    Some(lock_path[index + marker.len()..].to_string())
}

/// yarn.lock (classic v1 + berry). Blocks are headed by one or more
/// `"name@range":` descriptors followed by an indented `version "1.2.3"`
/// (classic) or `version: 1.2.3` (berry).
pub(super) fn yarn_lock(contents: &str, out: &mut Emitter<'_>) {
    let mut current_names: Vec<String> = Vec::new();
    let mut header_line = 0usize;
    for (idx, raw) in contents.lines().enumerate() {
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        let indented = raw.starts_with(' ') || raw.starts_with('\t');
        if !indented && raw.trim_end().ends_with(':') {
            // Block header: comma-separated `"name@range"` descriptors.
            current_names = raw
                .trim_end()
                .trim_end_matches(':')
                .split(',')
                .filter_map(|spec| yarn_name(spec.trim()))
                .collect();
            header_line = idx + 1;
        } else if indented {
            let trimmed = raw.trim();
            if let Some(rest) = trimmed.strip_prefix("version") {
                let version = rest
                    .trim_start_matches(':')
                    .trim()
                    .trim_matches('"')
                    .to_string();
                if !version.is_empty() {
                    for name in &current_names {
                        out.pkg(name, &version, Some(header_line));
                    }
                    current_names.clear();
                }
            }
        }
    }
}

/// Extract the package name from a yarn descriptor like `"@scope/pkg@^1.0.0"`
/// or `lodash@^4.0.0`. The version range is everything after the last `@`
/// that is not the scope-leading `@`.
fn yarn_name(spec: &str) -> Option<String> {
    let spec = spec.trim().trim_matches('"');
    if spec.is_empty() {
        return None;
    }
    let (scope, rest) = if let Some(stripped) = spec.strip_prefix('@') {
        ("@", stripped)
    } else {
        ("", spec)
    };
    let name = rest.split('@').next().unwrap_or(rest);
    if name.is_empty() {
        None
    } else {
        Some(format!("{scope}{name}"))
    }
}

/// pnpm-lock.yaml. Versions live in the `packages:` (and `snapshots:`) maps
/// keyed by `/name@1.2.3` (v6) or `name@1.2.3` (v9). v5's slash-separated
/// `/name/1.2.3` keys carry no `@` and are NOT parsed: a known coverage gap
/// (pnpm 7 EOL'd lockfiles), not an oversight in the key splitter.
pub(super) fn pnpm_lock(contents: &str, out: &mut Emitter<'_>) {
    let mut in_packages = false;
    for (idx, raw) in contents.lines().enumerate() {
        // pnpm separates every entry with a blank line, including one directly
        // after `packages:`. A blank line continues the block, it never ends it.
        if raw.trim().is_empty() {
            continue;
        }
        if !raw.starts_with(' ') {
            in_packages = matches!(raw.trim_end(), "packages:" | "snapshots:");
            continue;
        }
        if !in_packages {
            continue;
        }
        // Package entry keys are indented two spaces and end with `:`.
        let trimmed = raw.trim();
        if !trimmed.ends_with(':') || raw.chars().take_while(|c| *c == ' ').count() != 2 {
            continue;
        }
        let key = trimmed
            .trim_end_matches(':')
            .trim_matches('\'')
            .trim_matches('"');
        if let Some((name, version)) = pnpm_key(key) {
            out.pkg(name, version, Some(idx + 1));
        }
    }
}

/// Parse a pnpm package key into (name, version). Handles a leading `/`, the
/// scope `@`, and a trailing peer-dependency suffix `(react@18.0.0)`.
fn pnpm_key(key: &str) -> Option<(&str, &str)> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split('(').next().unwrap_or(key); // drop peer-deps suffix
    super::support::split_scoped_at(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn extracts_nested_npm_name() {
        assert_eq!(
            npm_name_from_lock_path("node_modules/foo/node_modules/@scope/pkg"),
            Some("@scope/pkg".to_string())
        );
    }

    #[test]
    fn parses_yarn_names() {
        assert_eq!(
            yarn_name("\"@scope/pkg@^1.0.0\""),
            Some("@scope/pkg".into())
        );
        assert_eq!(yarn_name("lodash@^4.0.0"), Some("lodash".into()));
    }

    #[test]
    fn parses_pnpm_keys() {
        assert_eq!(pnpm_key("/lodash@4.17.21"), Some(("lodash", "4.17.21")));
        assert_eq!(
            pnpm_key("@scope/pkg@1.2.3(react@18.0.0)"),
            Some(("@scope/pkg", "1.2.3"))
        );
    }

    #[test]
    fn parses_v3_package_lock_with_line_numbers() {
        let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "my-app" },
    "node_modules/lodash": { "version": "4.17.21" },
    "node_modules/@scope/pkg": { "version": "1.2.3" }
  }
}"#;
        let found: Vec<(String, String, Option<usize>)> = run_parser("npm", lock, package_lock)
            .into_iter()
            .map(|p| (p.name, p.version, p.line))
            .collect();
        assert_eq!(
            found,
            vec![
                ("lodash".to_string(), "4.17.21".to_string(), Some(5)),
                ("@scope/pkg".to_string(), "1.2.3".to_string(), Some(6)),
            ]
        );
    }

    #[test]
    fn parses_v1_nested_dependencies() {
        let lock = r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "left-pad": {
      "version": "1.3.0",
      "dependencies": {
        "inner-dep": { "version": "0.1.0" }
      }
    }
  }
}"#;
        let found: Vec<(String, String)> = run_parser("npm", lock, package_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![
                ("left-pad".to_string(), "1.3.0".to_string()),
                ("inner-dep".to_string(), "0.1.0".to_string()),
            ]
        );
    }

    #[test]
    fn parses_yarn_blocks_classic_and_berry() {
        let lock = "# yarn lockfile v1\n\n\"@scope/pkg@^1.0.0\", \"@scope/pkg@~1.1.0\":\n  version \"1.1.2\"\n\nlodash@^4.0.0:\n  version: 4.17.21\n";
        let found: Vec<(String, String)> = run_parser("npm", lock, yarn_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![
                ("@scope/pkg".to_string(), "1.1.2".to_string()),
                ("@scope/pkg".to_string(), "1.1.2".to_string()),
                ("lodash".to_string(), "4.17.21".to_string()),
            ]
        );
    }

    /// Verbatim `pnpm install --lockfile-only` output: pnpm puts a blank line
    /// after `packages:`/`snapshots:` and between every entry, so a parser that
    /// treats a blank line as the end of the block yields nothing at all.
    #[test]
    fn parses_pnpm_v9_lockfile_with_blank_lines_between_entries() {
        let lock = "\
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21
    devDependencies:
      '@types/minimist':
        specifier: 1.2.5
        version: 1.2.5

packages:

  '@types/minimist@1.2.5':
    resolution: {integrity: sha512-hov8bU==}

  lodash@4.17.21:
    resolution: {integrity: sha512-v2kDEe==}

snapshots:

  '@types/minimist@1.2.5': {}

  lodash@4.17.21: {}
";
        let found: Vec<(String, String)> = run_parser("npm", lock, pnpm_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![
                ("@types/minimist".to_string(), "1.2.5".to_string()),
                ("lodash".to_string(), "4.17.21".to_string()),
            ]
        );
    }

    #[test]
    fn parses_pnpm_v6_keys_and_peer_suffixes() {
        let lock = "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n  '@scope/pkg@1.2.3(react@18.0.0)':\n    dependencies: {}\n";
        let found: Vec<(String, String)> = run_parser("npm", lock, pnpm_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![
                ("lodash".to_string(), "4.17.21".to_string()),
                ("@scope/pkg".to_string(), "1.2.3".to_string()),
            ]
        );
    }

    #[test]
    fn malformed_package_lock_yields_nothing() {
        assert!(run_parser("npm", "{ not json", package_lock).is_empty());
    }
}
