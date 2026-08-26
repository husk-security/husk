//! Haxe / haxelib (`haxelib.json` + `hmm.json` + `*.hxml` + `.haxelib/` repo).
//! Inventory-only (no OSV advisory feed for Haxe yet).
//!
//! Sources:
//! 1. `haxelib.json` - project manifest: top-level `{"name","version"}` is
//!    the project's OWN coordinate (a real pin); the `dependencies` map's
//!    values are mostly empty (`""` = "any/latest").
//! 2. `hmm.json` - lockfile: `dependencies` ARRAY of `{name, type,
//!    version|ref|path}`. Only `type="haxelib"` carries a SemVer pin;
//!    `git`/`hg` carry a `ref`, `dev` a local path; all unpinned.
//! 3. `*.hxml` - compiler build files: `-lib name` / `--library name`,
//!    optionally pinned as `-lib name:version`.
//! 4. `.haxelib/<lib>/.current` - installed-state repo: `.current` holds the
//!    active version; a sibling `.dev` marks a dev checkout (unpinned).
//!    On-disk names/versions are `safe()`-escaped (dots -> commas).
//!
//! Versions are used verbatim. The literal tokens `git`/`dev` are NOT
//! versions; emitted unpinned.

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name, find_line};
use serde_json::Value as JsonValue;
use std::path::Path;

pub struct HaxeTarget;

impl ScanTarget for HaxeTarget {
    fn ecosystem_id(&self) -> &'static str {
        "haxelib"
    }

    fn detects(&self, path: &Path) -> bool {
        match file_name(path) {
            Some("haxelib.json") | Some("hmm.json") => true,
            // Require the `.haxelib` grandparent so an unrelated `.current`
            // elsewhere does not match.
            Some(".current") => path
                .parent()
                .and_then(Path::parent)
                .and_then(file_name)
                .is_some_and(|p| p == ".haxelib"),
            _ => path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("hxml")),
        }
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        match file_name(path) {
            Some("haxelib.json") => haxelib_json(&contents, out),
            Some("hmm.json") => hmm_json(&contents, out),
            Some(".current") => current_marker(&contents, out),
            _ => hxml(&contents, out),
        }
    }
}

/// Emit the project self-coordinate plus dependency pins. Parsed untyped
/// because fields are optional/mixed-type.
fn haxelib_json(contents: &str, out: &mut Emitter<'_>) {
    let Ok(root) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("haxelib.json is not valid JSON");
        return;
    };

    if let (Some(name), Some(version)) = (str_field(&root, "name"), str_field(&root, "version"))
        && is_valid_name(name)
        && !version.is_empty()
    {
        let line = find_line(contents, "\"name\"");
        out.pkg(name, version, line);
    }

    // Empty dep values mean "any/latest": recorded UNPINNED (version ""),
    // never as a bogus version.
    if let Some(deps) = root.get("dependencies").and_then(JsonValue::as_object) {
        for (dep_name, ver_val) in deps {
            if !is_valid_name(dep_name) {
                continue;
            }
            let version = ver_val.as_str().unwrap_or("").trim();
            let line = find_line(contents, &format!("\"{dep_name}\""));
            out.pkg(dep_name, version, line);
        }
    }
}

/// Only `type=haxelib` entries carry a real pin; git/hg/dev are unpinned.
fn hmm_json(contents: &str, out: &mut Emitter<'_>) {
    let Ok(root) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("hmm.json is not valid JSON");
        return;
    };
    let Some(deps) = root.get("dependencies").and_then(JsonValue::as_array) else {
        return;
    };

    for entry in deps {
        let Some(name) = str_field(entry, "name") else {
            continue;
        };
        if !is_valid_name(name) {
            continue;
        }
        let kind = str_field(entry, "type").unwrap_or("");
        let version = if kind == "haxelib" {
            str_field(entry, "version").unwrap_or("")
        } else {
            ""
        };
        let line = find_line(contents, &format!("\"{name}\""));
        out.pkg(name, version, line);
    }
}

/// `-lib name` / `--library name` declares a library; `-lib name:version`
/// pins it. All other compiler flags are ignored.
fn hxml(contents: &str, out: &mut Emitter<'_>) {
    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // hxml allows multiple flags on one line.
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if (tok == "-lib" || tok == "--library")
                && let Some(value) = tokens.next()
            {
                let (name, version) = split_lib_value(value);
                if is_valid_name(name) {
                    out.pkg(name, version, Some(idx + 1));
                }
            }
        }
    }
}

/// The containing directory name encodes the library; the file body is the
/// active version. Both are `safe()`-escaped on disk.
fn current_marker(contents: &str, out: &mut Emitter<'_>) {
    let Some(dir_name) = out
        .path()
        .parent()
        .and_then(file_name)
        .map(unescape_haxelib)
    else {
        return;
    };
    if !is_valid_name(&dir_name) {
        return;
    }

    // A sibling `.dev` marker overrides `.current` and points at a local
    // checkout; treat the lib as dev/unpinned.
    if out.path().with_file_name(".dev").exists() {
        out.pkg(&dir_name, "", None);
        return;
    }

    let raw = contents.trim();
    let version = if raw.is_empty() || raw == "git" || raw == "dev" {
        String::new()
    } else {
        unescape_haxelib(raw)
    };
    out.pkg(&dir_name, &version, None);
}

fn split_lib_value(value: &str) -> (&str, &str) {
    match value.split_once(':') {
        Some((name, version)) => (name, version),
        None => (value, ""),
    }
}

/// Recover an on-disk `safe()`-escaped string: haxelib stores names and
/// versions as directory names with dots replaced by commas.
fn unescape_haxelib(s: &str) -> String {
    s.replace(',', ".")
}

fn str_field<'a>(value: &'a JsonValue, key: &str) -> Option<&'a str> {
    value.get(key).and_then(JsonValue::as_str)
}

/// haxelib name constraint: `[A-Za-z0-9_\-.]`, at least 3 chars.
fn is_valid_name(name: &str) -> bool {
    name.len() >= 3
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn haxelib_json_self_and_pinned_deps() {
        let contents = r#"{
  "name": "my_game",
  "version": "2.3.1",
  "classPath": "src/",
  "dependencies": {
    "tink_macro": "0.10.4",
    "hxnodejs": "12.1.0",
    "nme": ""
  },
  "main": "Main"
}"#;
        let pkgs = run_parser("haxelib", contents, haxelib_json);
        let by: Vec<(&str, &str)> = pkgs
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        // Project self-coordinate is a real pin.
        assert!(by.contains(&("my_game", "2.3.1")));
        assert!(by.contains(&("tink_macro", "0.10.4")));
        assert!(by.contains(&("hxnodejs", "12.1.0")));
        // Empty dep version => unpinned (version ""), never a bogus version.
        assert!(by.contains(&("nme", "")));
        assert!(pkgs.iter().all(|p| p.ecosystem == "haxelib"));
    }

    #[test]
    fn hmm_json_only_haxelib_type_pins() {
        let contents = r#"{
  "dependencies": [
    { "name": "tink_macro", "type": "haxelib", "version": "0.10.4" },
    { "name": "hxnodejs",   "type": "haxelib", "version": "12.1.0" },
    { "name": "thx.promise", "type": "git", "ref": "ae94bdc" }
  ]
}"#;
        let pkgs = run_parser("haxelib", contents, hmm_json);
        let by: Vec<(&str, &str)> = pkgs
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert!(by.contains(&("tink_macro", "0.10.4")));
        assert!(by.contains(&("hxnodejs", "12.1.0")));
        // git entry: name kept (dots are part of the id), version unpinned.
        assert!(by.contains(&("thx.promise", "")));
    }

    #[test]
    fn hxml_only_colon_form_is_pinned() {
        let contents = r#"# build file
-lib tink_macro:0.10.4
--library hxnodejs
-cp src
-main Main
--next
-lib heaps:1.10.0"#;
        let pkgs = run_parser("haxelib", contents, hxml);
        let by: Vec<(&str, &str)> = pkgs
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert!(by.contains(&("tink_macro", "0.10.4")));
        assert!(by.contains(&("hxnodejs", ""))); // no colon => unpinned
        assert!(by.contains(&("heaps", "1.10.0")));
        // -cp/-main are not libraries.
        assert!(!by.iter().any(|(n, _)| *n == "src" || *n == "Main"));
    }

    #[test]
    fn split_and_unescape_helpers() {
        assert_eq!(split_lib_value("heaps:1.10.0"), ("heaps", "1.10.0"));
        assert_eq!(split_lib_value("heaps"), ("heaps", ""));
        // First-colon split keeps the rest of the version intact.
        assert_eq!(split_lib_value("lib:1.0.0-rc.1"), ("lib", "1.0.0-rc.1"));
        // safe() escaping uses commas for dots; unsafe() restores them.
        assert_eq!(unescape_haxelib("my,lib"), "my.lib");
        assert_eq!(unescape_haxelib("1,0,0"), "1.0.0");
        assert!(is_valid_name("thx.core"));
        assert!(!is_valid_name("ab")); // too short
        assert!(!is_valid_name("bad name")); // space
    }
}
