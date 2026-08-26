//! Bower components (`.bower.json`): inventory-only (no OSV ecosystem;
//! Bower was deprecated in 2017, so its presence is itself a posture signal).
//!
//! Bower has no lockfile; the authoritative pinned source is the
//! `<install-dir>/<component>/.bower.json` metadata Bower writes at install
//! time; one file == one pinned component. Version resolution order:
//! `_resolution.tag` -> `_release` -> top-level `version` (leading `v`
//! stripped); a branch/commit resolution has no SemVer, so the 40-hex
//! `_resolution.commit` SHA is recorded instead. The root `bower.json` /
//! `component.json` manifests carry only ranges and are deliberately not
//! parsed. Spec: <https://github.com/bower/spec/blob/master/json.md>.

use super::find_line;
use super::support::{Emitter, strip_v};
use serde_json::Value as JsonValue;
use std::path::Path;

/// One pinned component per `.bower.json`. Falls back to the containing
/// directory name (Bower installs each component into a dir named after it)
/// when `name` is missing or the file hits the double-concatenated
/// `.bower.json` bug (bower/bower#2067).
pub(super) fn bower_json(contents: &str, out: &mut Emitter<'_>) {
    let dir_name = out
        .path()
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .map(String::from);
    let Some((name, version)) = parse_component(contents, dir_name.as_deref()) else {
        return;
    };
    let line = find_line(contents, &version).or_else(|| find_line(contents, &name));
    out.pkg(&name, &version, line);
}

/// Extract the pinned `(name, version)` from a `.bower.json` body. If strict
/// parsing fails, recover the first valid top-level object (the
/// double-concatenated bug); if even that fails, emit the component by
/// directory name with version `0.0.0` so it is counted as present rather
/// than silently dropped.
fn parse_component(contents: &str, dir_name: Option<&str>) -> Option<(String, String)> {
    let json = serde_json::from_str::<JsonValue>(contents)
        .ok()
        .or_else(|| recover_first_object(contents));

    let Some(obj) = json.as_ref().and_then(JsonValue::as_object) else {
        let name = non_empty_opt(dir_name)?.to_ascii_lowercase();
        return Some((name, "0.0.0".to_string()));
    };

    let name = obj
        .get("name")
        .and_then(JsonValue::as_str)
        .and_then(non_empty)
        .or(non_empty_opt(dir_name))?
        .to_ascii_lowercase();

    let resolution = obj.get("_resolution").and_then(JsonValue::as_object);
    let tag = resolution
        .and_then(|r| r.get("tag"))
        .and_then(JsonValue::as_str)
        .and_then(non_empty);
    let release = obj
        .get("_release")
        .and_then(JsonValue::as_str)
        .and_then(non_empty);
    let embedded = obj
        .get("version")
        .and_then(JsonValue::as_str)
        .and_then(non_empty);
    let commit = resolution
        .and_then(|r| r.get("commit"))
        .and_then(JsonValue::as_str)
        .and_then(non_empty);

    let version = match tag.or(release).or(embedded) {
        Some(v) => strip_v(v).to_string(),
        None => commit
            .map(str::to_string)
            .unwrap_or_else(|| "0.0.0".to_string()),
    };

    Some((name, version))
}

/// Recover the first valid top-level JSON object from a body that fails strict
/// parsing (the double-concatenated `.bower.json` bug writes `{..}{..}`).
fn recover_first_object(contents: &str) -> Option<JsonValue> {
    let start = contents.find('{')?;
    let bytes = contents.as_bytes();
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return serde_json::from_str::<JsonValue>(&contents[start..=idx]).ok();
                }
            }
            _ => {}
        }
    }
    None
}

fn non_empty(s: &str) -> Option<&str> {
    let t = s.trim();
    (!t.is_empty()).then_some(t)
}

fn non_empty_opt(s: Option<&str>) -> Option<&str> {
    s.and_then(non_empty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::is_commit_sha;

    // jQuery: a clean `version`-type resolution; tag preferred over _release/version.
    const JQUERY: &str = r#"{
  "name": "jquery",
  "version": "3.4.1",
  "main": "dist/jquery.js",
  "license": "MIT",
  "_release": "3.4.1",
  "_resolution": {
    "type": "version",
    "tag": "3.4.1",
    "commit": "97c5ff0456cccc8ce5e5e22bb7df9319b8a9adb9"
  },
  "_source": "https://github.com/jquery/jquery-dist.git",
  "_target": "^3.4.0"
}"#;

    // Bootstrap: tag carries a leading `v` that must be stripped.
    const BOOTSTRAP: &str = r#"{
  "name": "bootstrap",
  "version": "3.3.7",
  "_release": "3.3.7",
  "_resolution": {
    "type": "version",
    "tag": "v3.3.7",
    "commit": "0b9c4a4007c44201dce9a6cc1a38407005c26c86"
  },
  "_source": "https://github.com/twbs/bootstrap.git"
}"#;

    #[test]
    fn parses_pinned_tag_and_prefers_it() {
        let (name, version) = parse_component(JQUERY, Some("jquery")).expect("parsed");
        assert_eq!(name, "jquery");
        assert_eq!(version, "3.4.1");
    }

    #[test]
    fn strips_leading_v_from_tag() {
        let (name, version) = parse_component(BOOTSTRAP, Some("bootstrap")).expect("parsed");
        assert_eq!(name, "bootstrap");
        assert_eq!(version, "3.3.7");
    }

    #[test]
    fn branch_pin_records_commit_sha() {
        let input = r#"{
  "name": "legacy-widget",
  "_resolution": {
    "type": "commit",
    "commit": "abcdef0123456789abcdef0123456789abcdef01"
  }
}"#;
        let (name, version) = parse_component(input, None).expect("parsed");
        assert_eq!(name, "legacy-widget");
        assert_eq!(version, "abcdef0123456789abcdef0123456789abcdef01");
    }

    #[test]
    fn falls_back_to_directory_name_when_name_missing() {
        let input = r#"{ "_release": "1.2.3" }"#;
        let (name, version) = parse_component(input, Some("MyComponent")).expect("parsed");
        assert_eq!(name, "mycomponent");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn recovers_from_double_concatenated_object() {
        // bower/bower#2067: two top-level objects concatenated. Recover the first.
        let input = r#"{"name":"jquery","_resolution":{"tag":"2.2.4"}}{"name":"dupe"}"#;
        let (name, version) = parse_component(input, Some("jquery")).expect("recovered");
        assert_eq!(name, "jquery");
        assert_eq!(version, "2.2.4");
    }

    #[test]
    fn unparseable_still_counted_by_dir_name() {
        let (name, version) = parse_component("}}}not json{{{", Some("ghost")).expect("present");
        assert_eq!(name, "ghost");
        assert_eq!(version, "0.0.0");
    }

    #[test]
    fn version_normalization_helpers() {
        assert_eq!(strip_v("v1.0.0"), "1.0.0");
        assert_eq!(strip_v("1.0.0"), "1.0.0");
        assert_eq!(strip_v("v"), "v"); // not a version; left as-is
        assert!(is_commit_sha("abcdef0123456789abcdef0123456789abcdef01"));
        assert!(!is_commit_sha("3.4.1"));
    }
}
