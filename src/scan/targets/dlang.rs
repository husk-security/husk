//! D / Dub (`dub.selections.json`). Dub packages come from `code.dlang.org`
//! and are resolved by the DUB package manager. There is no OSV/GitHub advisory
//! ecosystem for DUB yet, so its coordinates are **inventory-only**: recorded
//! for manual cross-reference, not automated advisory matching.

use super::find_line;
use super::support::Emitter;
use serde_json::Value as JsonValue;

/// Strip a leading `v`; deliberately unconditional (unlike
/// [`super::support::strip_v`]): DUB itself treats any leading `v` as a tag
/// prefix. Build metadata and prerelease are preserved verbatim.
fn normalize_version(v: &str) -> &str {
    v.strip_prefix('v').unwrap_or(v)
}

/// Parse the `versions` object of a `dub.selections.json`:
///
/// ```json
/// { "fileVersion": 1, "versions": { "vibe-d": "0.9.5", ... } }
/// ```
///
/// Keys are `code.dlang.org` registry names, kept verbatim (subpackages keep
/// their colon, e.g. `vibe-d:http`). Values: a plain version string or
/// `{ "version": .. }` -> pinned (`v` stripped); `{ "path": .. }` -> local
/// dep, path recorded as the (non-semver) version; `{ "repository": "git+..",
/// "version": "<sha>" }` -> git dep, commit SHA as version; `"~branch"` ->
/// mutable ref, recorded UNPINNED. `serde_json` rejects comments / trailing
/// commas that DUB's lenient parser accepts; those degrade to zero deps with
/// a visible warning.
pub(super) fn dub_selections(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("dub.selections.json is not valid JSON");
        return;
    };
    let Some(versions) = json.get("versions").and_then(|v| v.as_object()) else {
        return;
    };
    for (name, value) in versions {
        if name.is_empty() {
            continue;
        }
        let line = find_line(contents, &format!("\"{name}\""));

        match value {
            JsonValue::String(s) => {
                if s.is_empty() {
                    continue;
                }
                if s.starts_with('~') {
                    out.pkg(name, "", line);
                } else {
                    out.pkg(name, normalize_version(s), line);
                }
            }
            JsonValue::Object(obj) => {
                if let Some(p) = obj.get("path").and_then(|v| v.as_str()) {
                    out.pkg(name, p, line);
                } else if obj.get("repository").and_then(|v| v.as_str()).is_some() {
                    if let Some(sha) = obj.get("version").and_then(|v| v.as_str()) {
                        out.pkg(name, sha, line);
                    } else {
                        out.pkg(name, "", line);
                    }
                } else if let Some(ver) = obj.get("version").and_then(|v| v.as_str())
                    && !ver.is_empty()
                {
                    out.pkg(name, normalize_version(ver), line);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_pinned_versions() {
        let contents = r#"{
            "fileVersion": 1,
            "versions": {
                "vibe-d": "0.10.3",
                "botan": "1.13.8",
                "openssl-static": "1.0.5+3.0.8"
            }
        }"#;
        let mut pkgs = run_parser("dub", contents, dub_selections);
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "botan");
        assert_eq!(pkgs[0].version, "1.13.8");
        assert_eq!(pkgs[0].ecosystem, "dub");
        // Build metadata must survive verbatim.
        assert_eq!(pkgs[1].name, "openssl-static");
        assert_eq!(pkgs[1].version, "1.0.5+3.0.8");
        assert_eq!(pkgs[2].name, "vibe-d");
        assert_eq!(pkgs[2].version, "0.10.3");
    }

    #[test]
    fn parses_object_version_and_strips_v_prefix() {
        let contents = r#"{
            "versions": {
                "taggedalgebraic": { "version": "v1.0.1" }
            }
        }"#;
        let pkgs = run_parser("dub", contents, dub_selections);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "taggedalgebraic");
        assert_eq!(pkgs[0].version, "1.0.1");
    }

    #[test]
    fn records_path_and_git_and_branch_deps() {
        let contents = r#"{
            "versions": {
                "my-local-lib": { "path": "../my-local-lib" },
                "branch-dep": "~master",
                "windows-headers": {
                    "repository": "git+https://github.com/kinke/windows-headers.git",
                    "version": "6fd8e2dd19de59755b5531ccd7e481fd1df8967d"
                },
                "pinned": "2.0.1"
            }
        }"#;
        let mut pkgs = run_parser("dub", contents, dub_selections);
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        // All four are recorded; path/branch are unpinned, git keeps the SHA.
        assert_eq!(pkgs.len(), 4);
        let branch = pkgs.iter().find(|p| p.name == "branch-dep").unwrap();
        assert_eq!(branch.version, "");
        let git = pkgs.iter().find(|p| p.name == "windows-headers").unwrap();
        assert_eq!(git.version, "6fd8e2dd19de59755b5531ccd7e481fd1df8967d");
        let local = pkgs.iter().find(|p| p.name == "my-local-lib").unwrap();
        assert_eq!(local.version, "../my-local-lib");
        let pinned = pkgs.iter().find(|p| p.name == "pinned").unwrap();
        assert_eq!(pinned.version, "2.0.1");
    }

    #[test]
    fn keeps_subpackage_colon_verbatim() {
        let contents = r#"{ "versions": { "vibe-d:http": "0.9.5" } }"#;
        let pkgs = run_parser("dub", contents, dub_selections);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "vibe-d:http");
        assert_eq!(pkgs[0].version, "0.9.5");
    }

    #[test]
    fn tolerates_malformed_input() {
        assert!(run_parser("dub", "not json", dub_selections).is_empty());
        assert!(run_parser("dub", "{}", dub_selections).is_empty());
        // `versions` present but a non-object -> zero deps, no panic.
        assert!(run_parser("dub", r#"{ "versions": [] }"#, dub_selections).is_empty());
    }
}
