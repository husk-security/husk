//! Ollama local models (manifest files under
//! `<models>/manifests/<host>/<namespace>/<model>/<tag>` → inventory-only,
//! no OSV ecosystem or advisory feed).
//!
//! The manifest **file path** is the coordinate; the body pins the exact bytes
//! via `sha256:` layer digests. Manifests reuse the Docker Image Manifest V2
//! schema, so to avoid colliding with plain Docker/OCI manifests we require
//! (a) the path to live under a `.../models/manifests/...` tree and (b) at
//! least one layer `mediaType` prefixed `application/vnd.ollama.image.`.
//!
//! Modelfiles (`FROM ...` build recipes) are deliberately **not** parsed:
//! `FROM` is an unresolved request, not a resolved pin.

use super::ScanTarget;
use super::support::{Emitter, read_text};
use serde_json::Value as JsonValue;
use std::path::{Component, Path};

/// Default Ollama registry host, omitted from the canonical short name.
const DEFAULT_HOST: &str = "registry.ollama.ai";
/// Default namespace, omitted from the canonical short name.
const DEFAULT_NAMESPACE: &str = "library";
/// The Ollama-specific layer media-type prefix that disambiguates these
/// manifests from plain Docker/OCI image manifests.
const OLLAMA_MEDIA_PREFIX: &str = "application/vnd.ollama.image.";
/// The media-type of the immutable model weights layer (the true pin).
const MODEL_MEDIA_TYPE: &str = "application/vnd.ollama.image.model";

pub struct OllamaTarget;

impl ScanTarget for OllamaTarget {
    fn ecosystem_id(&self) -> &'static str {
        "ollama"
    }

    /// Manifest files have NO extension, so dispatch is purely on directory
    /// structure, never a `*.json` glob. The allocation-free shape prefilter
    /// runs on every walked file; the allocating coordinate parse only runs on
    /// the rare paths that pass it.
    fn detects(&self, path: &Path) -> bool {
        is_manifest_shaped(path) && manifest_coordinate(path).is_some()
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some((name, tag)) = manifest_coordinate(path) else {
            return;
        };
        let Some(contents) = read_text(path, out) else {
            return;
        };
        let Ok(json) = serde_json::from_str::<JsonValue>(&contents) else {
            out.warn("Ollama model manifest is not valid JSON");
            return;
        };
        let Some(digest) = ollama_model_digest(&json) else {
            return;
        };
        // The digest rides in the version so distinct builds of a moving tag
        // are distinguishable.
        let version = format!("{tag}@{digest}");
        out.pkg(&name, &version, None);
    }
}

/// Allocation-free prefilter for the manifest path shape: exactly four normal
/// components after a `models/manifests` directory pair. Mirrors the segment
/// arithmetic of [`manifest_coordinate`] (which requires the LAST such pair to
/// sit exactly four segments from the end) without collecting anything.
fn is_manifest_shaped(path: &Path) -> bool {
    let mut components = path.components().rev();
    for _ in 0..4 {
        if !matches!(components.next(), Some(Component::Normal(_))) {
            return false;
        }
    }
    components
        .next()
        .is_some_and(|c| c.as_os_str() == "manifests")
        && components.next().is_some_and(|c| c.as_os_str() == "models")
}

/// Derive `(canonical_name, tag)` from a manifest **file path**, or `None` if
/// `path` is not shaped like an Ollama model manifest.
///
/// The coordinate is the path relative to the `manifests/` directory, split on
/// the OS separator into exactly four segments (`host / namespace / model /
/// tag`), assigned from the right (model names may contain dots like
/// `qwen2.5`, but never slashes). We then build the canonical short name,
/// dropping the default host/namespace.
fn manifest_coordinate(path: &Path) -> Option<(String, String)> {
    let segments: Vec<&str> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();

    // Take the LAST `models/manifests` pair so deeply nested fixtures resolve.
    let manifests_idx = (1..segments.len()).rev().find(|&i| {
        segments.get(i) == Some(&"manifests") && segments.get(i - 1) == Some(&"models")
    })?;

    let coord = &segments[manifests_idx + 1..];
    if coord.len() != 4 {
        return None;
    }
    let host = coord[0];
    let namespace = coord[1];
    let model = coord[2];
    let tag = coord[3];
    if host.is_empty() || namespace.is_empty() || model.is_empty() || tag.is_empty() {
        return None;
    }

    Some((canonical_name(host, namespace, model), tag.to_string()))
}

/// Build the canonical display name, omitting the default host
/// (`registry.ollama.ai`) and default namespace (`library`). Names are
/// lowercased (Ollama compares case-insensitively) for a stable coordinate.
fn canonical_name(host: &str, namespace: &str, model: &str) -> String {
    let host = host.to_ascii_lowercase();
    let namespace = namespace.to_ascii_lowercase();
    let model = model.to_ascii_lowercase();

    let mut name = String::new();
    if host != DEFAULT_HOST {
        name.push_str(&host);
        name.push('/');
    }
    if namespace != DEFAULT_NAMESPACE {
        name.push_str(&namespace);
        name.push('/');
    }
    name.push_str(&model);
    name
}

/// Validate a parsed manifest and return its model-layer pin
/// (`sha256:<64hex>`, lowercased), or `None` if this is not an Ollama manifest
/// or carries no model layer.
fn ollama_model_digest(json: &JsonValue) -> Option<String> {
    if json.get("schemaVersion").and_then(JsonValue::as_i64) != Some(2) {
        return None;
    }
    let layers = json.get("layers").and_then(JsonValue::as_array)?;

    // Require at least one Ollama-specific layer to disambiguate from a plain
    // Docker/OCI image manifest sharing the same schema.
    let is_ollama = layers.iter().any(|layer| {
        layer
            .get("mediaType")
            .and_then(JsonValue::as_str)
            .is_some_and(|m| m.starts_with(OLLAMA_MEDIA_PREFIX))
    });
    if !is_ollama {
        return None;
    }

    // The model-weights layer digest is the immutable pin.
    layers
        .iter()
        .find(|layer| layer.get("mediaType").and_then(JsonValue::as_str) == Some(MODEL_MEDIA_TYPE))
        .and_then(|layer| layer.get("digest"))
        .and_then(JsonValue::as_str)
        .map(|d| d.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const LLAMA3: &str = r#"{
      "schemaVersion": 2,
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "config": { "mediaType": "application/vnd.docker.container.image.v1+json",
                  "digest": "sha256:3f8eb4da87fa7a3c9da615036b0dc418d31fef2a30b115ff33562588b32c691d", "size": 485 },
      "layers": [
        { "mediaType": "application/vnd.ollama.image.model",    "digest": "sha256:6a0746a1ec1aef3e7ec53868f220ff6e389f6f8ef87a01d77c96807de94ca2aa", "size": 4661211424 },
        { "mediaType": "application/vnd.ollama.image.license",  "digest": "sha256:4fa551d4f938f68b8c1e6afa9d28befb70e3f33f75d0753248d530364aeea40f", "size": 12403 }
      ]
    }"#;

    // A plain Docker image manifest (no ollama layers) must be rejected.
    const DOCKER: &str = r#"{
      "schemaVersion": 2,
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "layers": [ { "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:aaaa", "size": 100 } ]
    }"#;

    #[test]
    fn coordinate_from_path_uses_short_form_for_defaults() {
        let p =
            PathBuf::from("/home/u/.ollama/models/manifests/registry.ollama.ai/library/qwen2.5/7b");
        let (name, tag) = manifest_coordinate(&p).expect("ollama coordinate");
        assert_eq!(name, "qwen2.5"); // default host + namespace dropped
        assert_eq!(tag, "7b");
    }

    #[test]
    fn coordinate_keeps_private_registry_and_namespace() {
        let p = PathBuf::from(
            "/var/.ollama/models/manifests/myreg.example.com:5000/team/mixtral/latest",
        );
        let (name, tag) = manifest_coordinate(&p).expect("ollama coordinate");
        assert_eq!(name, "myreg.example.com:5000/team/mixtral");
        assert_eq!(tag, "latest");
    }

    #[test]
    fn prefilter_agrees_with_the_coordinate_parse() {
        for path in [
            "/home/u/.ollama/models/manifests/registry.ollama.ai/library/qwen2.5/7b",
            "/var/.ollama/models/manifests/myreg.example.com:5000/team/mixtral/latest",
            "/home/u/.ollama/models/blobs/sha256-6a0746a1",
            "/home/u/.ollama/models/manifests/registry.ollama.ai/library/llama3",
            "/x/y/z/llama3/latest",
        ] {
            let path = PathBuf::from(path);
            assert_eq!(
                is_manifest_shaped(&path),
                manifest_coordinate(&path).is_some(),
                "prefilter must agree for {}",
                path.display()
            );
        }
    }

    #[test]
    fn non_manifest_paths_are_rejected() {
        // Not under models/manifests, and a blob path; both must be None.
        assert!(manifest_coordinate(&PathBuf::from("/x/y/z/llama3/latest")).is_none());
        assert!(
            manifest_coordinate(&PathBuf::from(
                "/home/u/.ollama/models/blobs/sha256-6a0746a1"
            ))
            .is_none()
        );
        // Wrong segment count after manifests/.
        assert!(
            manifest_coordinate(&PathBuf::from(
                "/home/u/.ollama/models/manifests/registry.ollama.ai/library/llama3"
            ))
            .is_none()
        );
    }

    #[test]
    fn extracts_model_layer_digest() {
        let json: JsonValue = serde_json::from_str(LLAMA3).unwrap();
        assert_eq!(
            ollama_model_digest(&json).as_deref(),
            Some("sha256:6a0746a1ec1aef3e7ec53868f220ff6e389f6f8ef87a01d77c96807de94ca2aa")
        );
    }

    #[test]
    fn rejects_plain_docker_manifest() {
        let json: JsonValue = serde_json::from_str(DOCKER).unwrap();
        assert!(ollama_model_digest(&json).is_none());
    }

    #[test]
    fn tolerates_truncated_json() {
        assert!(serde_json::from_str::<JsonValue>("{ \"schemaVersion\": 2, \"lay").is_err());
    }
}
