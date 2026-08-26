//! Spack (HPC / C++ source package manager) -> inventory-only.
//!
//! Ecosystem id: `spack`. Lockfile: `spack.lock` (the concretized environment
//! lockfile, JSON). There is **no** OSV/GitHub advisory database and no
//! canonical `pkg:spack` purl for Spack recipes, so this connector is
//! deliberately inventory-only: it surfaces `(recipe_name, version)`
//! coordinates for manual cross-referencing against upstream-ecosystem
//! advisories. Spack's own supply-chain integrity mechanism is GPG-signed
//! binary buildcaches, not a registry-style advisory feed.
//!
//! We parse the high-reliability `spack.lock` only. The human-authored
//! `spack.yaml` manifest is YAML (no YAML parser is available here) and its
//! specs are usually abstract/unpinned, so it is a poor version source and is
//! intentionally not parsed.
//!
//! `spack.lock` shape (lockfile-version 1..=5): a JSON object with `_meta`
//! (gated on `file-type == "spack-lockfile"`), `roots` (abstract top-level
//! specs, skipped), and `concrete_specs`: an object keyed by opaque 32-char
//! base32 DAG hashes whose VALUES carry the exact pinned `(name, version)`.
use super::support::Emitter;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;

// Detection is the literal basename `spack.lock`; this also covers the
// hidden `.spack-env/spack.lock` written when an environment is activated,
// since both share the same basename and JSON format. The
// `_meta.file-type == "spack-lockfile"` gate in [`spack_lock`] disambiguates
// a real Spack lockfile from any unrelated `spack.lock`.

/// Extract `(name, version)` from one `concrete_specs` VALUE, tolerating both
/// modern and legacy layouts (version-agnostic by structure, not by the
/// declared `lockfile-version`):
///
/// * FLAT (lockfile-version >= 3): the value is the spec node directly, with
///   top-level string fields `name` and `version`.
/// * LEGACY NESTED (lockfile-version <= 2): the value is a 1-key object whose
///   sole key is the package name and whose inner object holds `version`.
///
/// Returns `None` for partial/malformed nodes (missing name or version, or a
/// non-string version) so a single bad node never fails the whole scan.
fn extract_spec(value: &JsonValue) -> Option<(String, String)> {
    if let Some(name) = value.get("name").and_then(JsonValue::as_str) {
        let version = value.get("version").and_then(JsonValue::as_str)?;
        let (name, version) = (name.trim(), version.trim());
        if name.is_empty() || version.is_empty() {
            return None;
        }
        return Some((name.to_string(), version.to_string()));
    }

    let obj = value.as_object()?;
    if obj.len() != 1 {
        return None;
    }
    let (name, inner) = obj.iter().next()?;
    let version = inner.get("version").and_then(JsonValue::as_str)?;
    let (name, version) = (name.trim(), version.trim());
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Walk one `concrete_specs` object, collecting deduped `(name, version)`
/// pairs into `out` (the same pair recurs under many hashes for build
/// variants).
fn collect_concrete_specs(specs: &JsonValue, out: &mut BTreeSet<(String, String)>) {
    let Some(map) = specs.as_object() else {
        return;
    };
    // Keys are opaque DAG hashes, NOT names; always iterate over the values.
    for value in map.values() {
        if let Some(pair) = extract_spec(value) {
            out.insert(pair);
        }
    }
}

/// Parse a `spack.lock` string into deduped Spack coordinates. Emits nothing
/// for anything that is not a valid `spack-lockfile` (wrong/absent
/// `_meta.file-type`, non-object root, missing `concrete_specs`); graceful
/// degrade, never panic. Versions are preserved verbatim (Spack versions are
/// free-form recipe versions: dotted numerics, git refs, dates, dev tags).
/// (A UTF-8 BOM is already stripped by `read_text`.)
pub(super) fn spack_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(root) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("spack.lock is not valid JSON");
        return;
    };

    let is_lockfile = root
        .get("_meta")
        .and_then(|meta| meta.get("file-type"))
        .and_then(JsonValue::as_str)
        == Some("spack-lockfile");
    if !is_lockfile {
        return;
    }

    let mut pairs: BTreeSet<(String, String)> = BTreeSet::new();

    if let Some(specs) = root.get("concrete_specs") {
        collect_concrete_specs(specs, &mut pairs);
    }

    // v5 `include_concrete`: each included environment mirrors
    // {roots, concrete_specs}.
    if let Some(included) = root.get("include_concrete").and_then(JsonValue::as_object) {
        for env in included.values() {
            if let Some(specs) = env.get("concrete_specs") {
                collect_concrete_specs(specs, &mut pairs);
            }
        }
    }

    for (name, version) in pairs {
        let line = super::find_line(contents, &format!("\"{name}\""));
        out.pkg(&name, &version, line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    fn coords(contents: &str) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = run_parser("spack", contents, spack_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn parses_flat_modern_lockfile() {
        let lock = r#"{
  "_meta": { "file-type": "spack-lockfile", "lockfile-version": 5 },
  "roots": [ { "hash": "abc123", "spec": "hdf5@1.14.3 +mpi" } ],
  "concrete_specs": {
    "abc123def456ghi789jkl012mno345pq": {
      "name": "hdf5",
      "version": "1.14.3",
      "arch": { "platform": "linux" }
    },
    "zyx987wvu654tsr321qpo098nml765kj": {
      "name": "zlib",
      "version": "1.3.1",
      "dependencies": []
    }
  }
}"#;
        let got = coords(lock);
        assert!(got.contains(&("hdf5".to_string(), "1.14.3".to_string())));
        assert!(got.contains(&("zlib".to_string(), "1.3.1".to_string())));
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn parses_legacy_nested_layout() {
        let lock = r#"{
  "_meta": { "file-type": "spack-lockfile", "lockfile-version": 2 },
  "concrete_specs": {
    "hash1": { "openmpi": { "version": "4.1.5", "arch": {} } }
  }
}"#;
        assert_eq!(
            coords(lock),
            vec![("openmpi".to_string(), "4.1.5".to_string())]
        );
    }

    #[test]
    fn dedupes_same_name_version_across_hashes() {
        let lock = r#"{
  "_meta": { "file-type": "spack-lockfile", "lockfile-version": 4 },
  "concrete_specs": {
    "h1": { "name": "py-numpy", "version": "1.26.0" },
    "h2": { "name": "py-numpy", "version": "1.26.0" }
  }
}"#;
        assert_eq!(
            coords(lock),
            vec![("py-numpy".to_string(), "1.26.0".to_string())]
        );
    }

    #[test]
    fn rejects_non_spack_lockfile() {
        // Missing the `_meta.file-type` gate -> not a Spack lock.
        let lock = r#"{ "concrete_specs": { "h": { "name": "x", "version": "1" } } }"#;
        assert!(coords(lock).is_empty());
    }

    #[test]
    fn tolerates_malformed_and_missing_version() {
        let lock = r#"{
  "_meta": { "file-type": "spack-lockfile" },
  "concrete_specs": {
    "h1": { "name": "good", "version": "2.0" },
    "h2": { "name": "novers" },
    "h3": { "name": "numvers", "version": 3 }
  }
}"#;
        assert_eq!(coords(lock), vec![("good".to_string(), "2.0".to_string())]);
    }

    #[test]
    fn walks_include_concrete() {
        let lock = r#"{
  "_meta": { "file-type": "spack-lockfile", "lockfile-version": 5 },
  "concrete_specs": { "h1": { "name": "hdf5", "version": "1.14.3" } },
  "include_concrete": {
    "/path/to/env": {
      "concrete_specs": { "h2": { "name": "boost", "version": "1.84.0" } }
    }
  }
}"#;
        let got = coords(lock);
        assert!(got.contains(&("hdf5".to_string(), "1.14.3".to_string())));
        assert!(got.contains(&("boost".to_string(), "1.84.0".to_string())));
    }

    #[test]
    fn empty_for_garbage_input() {
        assert!(coords("not json at all").is_empty());
    }
}
