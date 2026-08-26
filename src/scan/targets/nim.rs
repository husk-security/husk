//! Nim (`nimble.lock` -> inventory-only; OSV has no Nimble ecosystem).
//!
//! `nimble.lock` is JSON: `{"version": 1, "packages": {"<name>": {"version": ...}}}`.

use super::support::{Emitter, LineFinder};
use serde_json::Value as JsonValue;

pub(super) fn nimble_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(root) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("nimble.lock is not valid JSON");
        return;
    };
    let Some(map) = root.get("packages").and_then(JsonValue::as_object) else {
        return;
    };
    let mut lines = LineFinder::new(contents);
    for (name, entry) in map {
        let Some(version) = entry.get("version").and_then(JsonValue::as_str) else {
            continue;
        };
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.pkg(name, version, lines.find(&format!("\"{name}\"")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_packages_and_versions() {
        let body = r#"{
  "version": 1,
  "packages": {
    "chronos": {
      "version": "3.0.2",
      "vcsRevision": "aab1e30a726bb47c5d3f4a75a826981836cde9e2",
      "url": "https://github.com/status-im/nim-chronos",
      "downloadMethod": "git"
    },
    "stew": {
      "version": "0.1.0",
      "vcsRevision": "deadbeef"
    }
  }
}"#;
        let mut pkgs = run_parser("nimble", body, nimble_lock);
        pkgs.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "chronos");
        assert_eq!(pkgs[0].version, "3.0.2");
        assert_eq!(pkgs[0].ecosystem, "nimble");
        assert_eq!(pkgs[1].name, "stew");
        assert_eq!(pkgs[1].version, "0.1.0");
    }

    #[test]
    fn tolerates_malformed_json() {
        assert!(run_parser("nimble", "{ not json", nimble_lock).is_empty());
        assert!(run_parser("nimble", "{}", nimble_lock).is_empty());
    }
}
