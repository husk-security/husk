//! Hackage via Cabal's `dist-newstyle/cache/plan.json` install plan.
//!
//! Unlike the `.cabal` manifest (ranges) or `cabal.project.freeze`, this
//! build-cache artifact is the fully-resolved, exact-pinned closure of the
//! project. The top-level object carries `cabal-version` and an
//! `install-plan` *array* (the canonical `cabal-plan` Haskell type exposes a
//! map, but the JSON is an array). Versions are Haskell PVP strings, emitted
//! verbatim; names are case-sensitive on Hackage and kept verbatim. Both
//! `configured` and `pre-existing` units are emitted; boot libraries like
//! `process`/`text`/`Cabal` do carry Hackage/HSEC advisories.
use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name, find_line};
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::path::Path;

pub struct CabalPlanTarget;

impl ScanTarget for CabalPlanTarget {
    fn ecosystem_id(&self) -> &'static str {
        "hackage"
    }

    fn detects(&self, path: &Path) -> bool {
        // `plan.json` is a generic filename, so gate on the `dist-newstyle`
        // path segment; the `cabal-version` JSON signature confirms in parse.
        file_name(path) == Some("plan.json")
            && path.components().any(|c| c.as_os_str() == "dist-newstyle")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(contents) = read_text(path, out) {
            parse_plan_json(&contents, out);
        }
    }
}

fn parse_plan_json(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        return;
    };

    // Confirm this is genuinely a cabal install plan, not some other tool's
    // `plan.json` that happened to live under a `dist-newstyle` path.
    if json.get("cabal-version").is_none() {
        return;
    }
    let Some(units) = json.get("install-plan").and_then(JsonValue::as_array) else {
        return;
    };

    // The same package recurs across components and setup-deps.
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for unit in units {
        match unit.get("type").and_then(JsonValue::as_str) {
            Some("configured") | Some("pre-existing") => {}
            _ => continue,
        }
        let (Some(name), Some(version)) = (
            unit.get("pkg-name").and_then(JsonValue::as_str),
            unit.get("pkg-version").and_then(JsonValue::as_str),
        ) else {
            continue;
        };
        if !seen.insert((name, version)) {
            continue;
        }

        // Anchor the line on the unit's `id` (unique per unit) when present.
        let needle = unit
            .get("id")
            .and_then(JsonValue::as_str)
            .map(|id| format!("\"{id}\""))
            .unwrap_or_else(|| format!("\"{name}\""));
        out.pkg(name, version, find_line(contents, &needle));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    const PLAN: &str = r#"{
        "cabal-version": "3.10.2.1",
        "cabal-lib-version": "3.10.2.1",
        "compiler-id": "ghc-9.6.4",
        "os": "linux",
        "arch": "x86_64",
        "install-plan": [
            {
                "type": "pre-existing",
                "id": "base-4.18.2.0",
                "pkg-name": "base",
                "pkg-version": "4.18.2.0",
                "depends": ["ghc-prim-0.10.0"]
            },
            {
                "type": "configured",
                "id": "aeson-2.2.3.0-inplace",
                "pkg-name": "aeson",
                "pkg-version": "2.2.3.0",
                "style": "global"
            },
            {
                "type": "configured",
                "id": "aeson-2.2.3.0-inplace-aeson-exe",
                "pkg-name": "aeson",
                "pkg-version": "2.2.3.0",
                "style": "global"
            },
            {
                "type": "configured",
                "id": "text-2.0.2",
                "pkg-name": "text",
                "pkg-version": "2.0.2"
            }
        ]
    }"#;

    #[test]
    fn parses_and_dedups_units() {
        let pkgs = run_parser("hackage", PLAN, parse_plan_json);
        let mut coords: Vec<String> = pkgs
            .iter()
            .map(|p| format!("{}@{}", p.name, p.version))
            .collect();
        coords.sort();
        // `aeson@2.2.3.0` appears twice but is deduplicated; `base`
        // (pre-existing) is kept.
        assert_eq!(coords, vec!["aeson@2.2.3.0", "base@4.18.2.0", "text@2.0.2"]);
        assert!(pkgs.iter().all(|p| p.ecosystem == "hackage"));
    }

    #[test]
    fn ignores_foreign_plan_json() {
        // A Terraform/webpack-style `plan.json` lacks `cabal-version`.
        assert!(
            run_parser(
                "hackage",
                r#"{"format_version": "1.0", "planned_values": {}}"#,
                parse_plan_json
            )
            .is_empty()
        );
    }

    #[test]
    fn tolerates_malformed() {
        assert!(run_parser("hackage", "{ partial wri", parse_plan_json).is_empty());
    }
}
