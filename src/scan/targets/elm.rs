//! Elm (`elm.json` -> inventory-only; no OSV/GHSA ecosystem).
//!
//! `elm.json` is Elm 0.19+'s single manifest+lockfile, dispatched on `type`:
//! * `"application"`: fully-resolved EXACT pins under
//!   `dependencies.{direct,indirect}` and `test-dependencies.{direct,indirect}`.
//! * `"package"`: only ranges (`"1.0.0 <= v < 2.0.0"`) under flat maps, plus
//!   the package's own exact `name` + `version`; ranges are normalized to
//!   their lower bound (the installed version is decided by the consuming
//!   application).
//!
//! Names keep the full `<author>/<project>` string. The legacy 0.18
//! `elm-package.json` has no top-level `type`, so it structurally yields
//! nothing.

use super::find_line;
use super::support::Emitter;
use serde_json::Value as JsonValue;

/// Foreign JSON that happens to be named `elm.json` (no recognised `type` +
/// `dependencies` pair) yields nothing.
pub(super) fn elm_json(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("elm.json is not valid JSON");
        return;
    };

    // `exposed-modules` is polymorphic (array vs object), so never
    // deserialize into a rigid struct; only the keys we need.
    if json.get("dependencies").is_none() {
        return;
    }

    match json.get("type").and_then(JsonValue::as_str) {
        Some("application") => {
            for (root, bucket) in [
                ("dependencies", "direct"),
                ("dependencies", "indirect"),
                ("test-dependencies", "direct"),
                ("test-dependencies", "indirect"),
            ] {
                let Some(map) = json
                    .get(root)
                    .and_then(|v| v.get(bucket))
                    .and_then(JsonValue::as_object)
                else {
                    continue;
                };
                for (name, version) in map {
                    let Some(version) = version.as_str() else {
                        continue;
                    };
                    if !is_exact_semver(version) {
                        continue;
                    }
                    out.pkg(name, version, find_line(contents, &format!("\"{name}\"")));
                }
            }
        }
        Some("package") => {
            if let (Some(name), Some(version)) = (
                json.get("name").and_then(JsonValue::as_str),
                json.get("version").and_then(JsonValue::as_str),
            ) && is_exact_semver(version)
            {
                let line = find_line(contents, &format!("\"{version}\""));
                out.pkg(name, version, line);
            }
            for root in ["dependencies", "test-dependencies"] {
                let Some(map) = json.get(root).and_then(JsonValue::as_object) else {
                    continue;
                };
                for (name, range) in map {
                    let Some(range) = range.as_str() else {
                        continue;
                    };
                    let Some(lower) = lower_bound(range) else {
                        continue;
                    };
                    out.pkg(name, lower, find_line(contents, &format!("\"{name}\"")));
                }
            }
        }
        _ => {}
    }
}

/// An Elm version is strict 3-part semver with integer-only segments and no
/// pre-release/build suffix or leading `v`.
fn is_exact_semver(version: &str) -> bool {
    let mut parts = version.split('.');
    let three_parts = matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), None)
            if !a.is_empty() && !b.is_empty() && !c.is_empty()
    );
    three_parts
        && version
            .split('.')
            .all(|p| p.bytes().all(|d| d.is_ascii_digit()))
}

/// Extract the lower-bound semver from a range like `"1.0.0 <= v < 2.0.0"`:
/// the leftmost whitespace-delimited token, validated as exact semver.
fn lower_bound(range: &str) -> Option<&str> {
    let token = range.split_whitespace().next()?;
    is_exact_semver(token).then_some(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    const APP: &str = r#"{
        "type": "application",
        "source-directories": ["src"],
        "elm-version": "0.19.1",
        "dependencies": {
            "direct": { "elm/browser": "1.0.2", "elm/core": "1.0.5" },
            "indirect": { "elm/virtual-dom": "1.0.3" }
        },
        "test-dependencies": {
            "direct": { "elm-explorations/test": "2.1.1" },
            "indirect": {}
        }
    }"#;

    const PKG: &str = r#"{
        "type": "package",
        "name": "elm/json",
        "summary": "Encode and decode JSON values",
        "version": "1.1.3",
        "exposed-modules": ["Json.Decode", "Json.Encode"],
        "elm-version": "0.19.0 <= v < 0.20.0",
        "dependencies": { "elm/core": "1.0.0 <= v < 2.0.0" },
        "test-dependencies": {}
    }"#;

    #[test]
    fn parses_application_pins_all_buckets() {
        let pkgs = run_parser("elm", APP, elm_json);
        let mut coords: Vec<String> = pkgs
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        coords.sort();
        assert_eq!(
            coords,
            vec![
                "elm-explorations/test@2.1.1",
                "elm/browser@1.0.2",
                "elm/core@1.0.5",
                "elm/virtual-dom@1.0.3",
            ]
        );
        assert!(pkgs.iter().all(|p| p.ecosystem == "elm"));
    }

    #[test]
    fn parses_package_lower_bounds_and_self() {
        let pkgs = run_parser("elm", PKG, elm_json);
        let mut coords: Vec<String> = pkgs
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        coords.sort();
        assert_eq!(coords, vec!["elm/core@1.0.0", "elm/json@1.1.3"]);
    }

    #[test]
    fn ignores_foreign_json() {
        // A `package.json`-shaped file has no Elm `type`/`dependencies` pair.
        let pkgs = run_parser("elm", r#"{"type": "module", "name": "x"}"#, elm_json);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn tolerates_malformed() {
        assert!(run_parser("elm", "not json", elm_json).is_empty());
    }

    #[test]
    fn lower_bound_and_semver_validation() {
        assert_eq!(lower_bound("1.0.0 <= v < 2.0.0"), Some("1.0.0"));
        assert_eq!(lower_bound("garbage"), None);
        assert!(is_exact_semver("1.0.5"));
        assert!(!is_exact_semver("1.0"));
        assert!(!is_exact_semver("1.0.0-beta"));
        assert!(!is_exact_semver("v1.0.0"));
    }
}
