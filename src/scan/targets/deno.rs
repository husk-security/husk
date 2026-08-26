//! Deno (`deno.lock` -> OSV `npm`).
//!
//! Deno records its fully-resolved dependency graph in a machine-generated
//! `deno.lock` JSON file (maintained by the `deno_lockfile` crate). The
//! top-level string `"version"` field selects the schema:
//!
//! * **v3/v4/v5** (the common case; v4 is the Deno 2.0 default, v5 ships with
//!   Deno 2.6+): a top-level `"specifiers"` map of `request -> resolved`
//!   pins, plus parallel `"npm"` and `"jsr"` maps keyed by `name@version`.
//! * **v2**: npm pins live under `"npm"."packages"` keyed by `name@version`.
//! * **v1**: a flat `{url: hash}` map of remote modules only; no npm/jsr
//!   coordinates to recover.
//!
//! npm dependencies resolve against the npm registry, so we emit them under
//! the OSV ecosystem `npm` (versioned npm advisories match Deno-installed code
//! even though Deno does not run npm lifecycle scripts). JSR packages have no
//! broad OSV coverage today, so they are inventory-only and emitted under the
//! `jsr` registry for visibility. The `"remote"`, `"redirects"` and
//! `"workspace"` sections carry no pinned package coordinates and are skipped.
//!
//! The same pin routinely appears both as a specifier and as an `npm`/`jsr`
//! map key; the duplicates are collapsed by discovery's global
//! per-(coordinate, manifest) dedup, not here.

use super::find_line;
use super::support::Emitter;
use serde_json::Value as JsonValue;

pub(super) fn deno_lock(contents: &str, out: &mut Emitter<'_>) {
    let root = match serde_json::from_str::<JsonValue>(contents) {
        Ok(JsonValue::Object(root)) => root,
        _ => {
            out.warn("deno.lock is not valid JSON");
            return;
        }
    };

    let mut emit = |eco: &str, name: &str, version: &str| {
        if name.is_empty() || version.is_empty() {
            return;
        }
        // Point reports at the resolved coordinate's first appearance.
        let needle = format!("{name}@{version}");
        let line = find_line(contents, &needle).or_else(|| find_line(contents, name));
        out.pkg_in(eco, name, version, line);
    };

    // The "version" field is a STRING, e.g. "4" (quoted); never assume an int.
    let version = root
        .get("version")
        .and_then(JsonValue::as_str)
        .unwrap_or("");

    match version {
        // v1: flat {url: hash} remote-module map. No npm/jsr coordinates.
        "1" => {}
        // v2: npm pins under "npm"."packages" keyed by name@version.
        "2" => {
            if let Some(pkgs) = root
                .get("npm")
                .and_then(|n| n.get("packages"))
                .and_then(JsonValue::as_object)
            {
                for key in pkgs.keys() {
                    if let Some((name, ver)) = split_key_name_version(key) {
                        emit("npm", name, &ver);
                    }
                }
            }
        }
        // v3/v4/v5 (and unknown future versions): "specifiers" is the
        // primary source; the "npm"/"jsr" key maps catch transitives not
        // surfaced as a specifier.
        _ => {
            if let Some(specs) = root.get("specifiers").and_then(JsonValue::as_object) {
                for (request, resolved) in specs {
                    let Some(resolved) = resolved.as_str() else {
                        continue;
                    };
                    let Some((eco, name)) = specifier_eco_name(request) else {
                        continue;
                    };
                    let ver = normalize_version(resolved);
                    emit(eco, name, &ver);
                }
            }

            if let Some(npm) = root.get("npm").and_then(JsonValue::as_object) {
                for key in npm.keys() {
                    if let Some((name, ver)) = split_key_name_version(key) {
                        emit("npm", name, &ver);
                    }
                }
            }
            if let Some(jsr) = root.get("jsr").and_then(JsonValue::as_object) {
                for key in jsr.keys() {
                    if let Some((name, ver)) = split_key_name_version(key) {
                        emit("jsr", name, &ver);
                    }
                }
            }
        }
    }
}

/// Resolve a specifier request key (e.g. `npm:chalk@^5`, `jsr:@std/assert@^1`)
/// into `(ecosystem, name)`. The trailing `@<range>` is dropped; only the
/// bare package name is kept. Returns `None` for unknown prefixes.
fn specifier_eco_name(request: &str) -> Option<(&'static str, &str)> {
    let (prefix, rest) = request.split_once(':')?;
    let eco = match prefix {
        "npm" => "npm",
        "jsr" => "jsr",
        _ => return None,
    };
    Some((eco, strip_range(rest)))
}

/// Strip a trailing `@<range>` from a specifier name. Scoped names start with
/// `@scope/...`, so the range delimiter is the LAST `@` that is not at index 0
/// (deliberately not `support::split_scoped_at`, which splits at the FIRST `@`
/// after the scope).
fn strip_range(rest: &str) -> &str {
    match rest.rfind('@') {
        Some(0) | None => rest, // leading '@' is the scope, or no range present
        Some(idx) => &rest[..idx],
    }
}

/// Split a map key of the form `name@version` (npm/jsr maps) into
/// `(name, normalized_version)`. The boundary is the FIRST `@` after an
/// optional leading scope `@` (`@scope/name@1.2.3`); everything after it,
/// including a Deno `_peer@ver` suffix, is treated as the version.
fn split_key_name_version(key: &str) -> Option<(&str, String)> {
    let (name, raw_version) = super::support::split_scoped_at(key)?;
    let version = normalize_version(raw_version);
    if version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Normalize a resolved version string: strip Deno's `_peer@ver` suffix
/// (everything from the first `_`) and a leading `v` if present. The result is
/// a bare semver string matching OSV npm version keys.
fn normalize_version(raw: &str) -> String {
    let core = raw.split('_').next().unwrap_or(raw);
    core.strip_prefix('v').unwrap_or(core).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str) -> Vec<PackageRef> {
        run_parser("npm", contents, deno_lock)
    }

    fn names_versions(pkgs: &[PackageRef]) -> Vec<(String, String, String)> {
        pkgs.iter()
            .map(|p| (p.ecosystem.clone(), p.name.clone(), p.version.clone()))
            .collect()
    }

    #[test]
    fn parses_v5_specifiers_and_keys() {
        let contents = r#"{
          "version": "5",
          "specifiers": {
            "jsr:@std/assert@^1.0.4": "1.0.5",
            "npm:chalk@^5": "5.3.0",
            "npm:marked-alert@2": "2.1.2_marked@12.0.2",
            "npm:@std/encoding@^1": "1.0.10"
          },
          "jsr": { "@std/assert@1.0.5": { "integrity": "x" } },
          "npm": {
            "chalk@5.3.0": { "integrity": "y" },
            "marked@12.0.2": { "integrity": "z" },
            "marked-alert@2.1.2_marked@12.0.2": { "integrity": "w" }
          },
          "remote": { "https://deno.land/std/x.ts": "deadbeef" }
        }"#;
        let pkgs = parse(contents);
        let got = names_versions(&pkgs);

        // npm coordinates, peer suffix stripped, scoped name preserved.
        assert!(got.contains(&("npm".into(), "chalk".into(), "5.3.0".into())));
        assert!(got.contains(&("npm".into(), "marked".into(), "12.0.2".into())));
        assert!(got.contains(&("npm".into(), "marked-alert".into(), "2.1.2".into())));
        assert!(got.contains(&("npm".into(), "@std/encoding".into(), "1.0.10".into())));
        // jsr is inventory-only but still surfaced.
        assert!(got.contains(&("jsr".into(), "@std/assert".into(), "1.0.5".into())));
        // No remote-URL noise leaked in.
        assert!(!got.iter().any(|(_, n, _)| n.contains("deno.land")));
        // marked-alert appears in both specifiers and npm keys; the raw parse
        // emits both and discovery's global dedup collapses them per manifest.
        assert_eq!(
            got.iter().filter(|(_, n, _)| n == "marked-alert").count(),
            2
        );
    }

    #[test]
    fn parses_v2_nested_packages() {
        let contents = r#"{
          "version": "2",
          "npm": {
            "packages": {
              "left-pad@1.3.0": { "integrity": "z" },
              "@scope/pkg@1.4.0": { "integrity": "q" }
            }
          }
        }"#;
        let got = names_versions(&parse(contents));
        assert!(got.contains(&("npm".into(), "left-pad".into(), "1.3.0".into())));
        assert!(got.contains(&("npm".into(), "@scope/pkg".into(), "1.4.0".into())));
    }

    #[test]
    fn v1_yields_no_coordinates() {
        let contents = r#"{
          "version": "1",
          "https://deno.land/std@0.224.0/assert/assert.ts": "abcd"
        }"#;
        assert!(parse(contents).is_empty());
    }

    #[test]
    fn malformed_returns_empty() {
        assert!(parse("not json").is_empty());
    }

    #[test]
    fn strip_range_handles_scoped_and_unscoped() {
        assert_eq!(strip_range("chalk@^5"), "chalk");
        assert_eq!(strip_range("@std/assert@^1.0.4"), "@std/assert");
        assert_eq!(strip_range("@scope/name"), "@scope/name");
        assert_eq!(strip_range("lone"), "lone");
    }

    #[test]
    fn split_key_handles_peer_suffix() {
        assert_eq!(
            split_key_name_version("marked-alert@2.1.2_marked@12.0.2"),
            Some(("marked-alert", "2.1.2".to_string()))
        );
        assert_eq!(
            split_key_name_version("@scope/pkg@1.4.0"),
            Some(("@scope/pkg", "1.4.0".to_string()))
        );
        assert_eq!(split_key_name_version("@scopeonly"), None);
    }
}
