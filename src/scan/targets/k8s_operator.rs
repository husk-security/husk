//! Kubernetes operators: OLM `*.clusterserviceversion.yaml` (CSV) manifests
//! -> ecosystem `"k8s-operator"`, plus an `"oci"` coordinate per container
//! image the bundle references. Both are inventory-only (no OSV namespace;
//! operators ship as OCI images; the image coordinates' value comes from
//! image-scanning intel and registry reputation).
//!
//! Detection anchors on the `.clusterserviceversion.yaml` suffix, an OLM
//! hard convention enforced by `operator-sdk`/`opm`, near-zero false
//! positives. A bare `manifests/*.yaml` path is deliberately not used (it
//! collides with Kustomize, Helm output, plain k8s manifests).
//!
//! Operator name resolution: the sibling `metadata/annotations.yaml` bundle
//! package name (authoritative) when present, else `metadata.name` with the
//! trailing version stripped. Version: `spec.version`, else the
//! `metadata.name` suffix, else `unknown`. Image refs come from a global
//! `image:`/`containerImage:` line sweep (more robust than walking the deep
//! deployment path); a `sha256:` digest wins over a tag as the pin.
//!
//! The CSV is YAML and no YAML crate is allowed, so the parse is hand-rolled,
//! line-oriented, and tolerant of quotes, comments, CRLF, a BOM, flow-style
//! sequences and multi-doc files (only the `ClusterServiceVersion` doc is
//! parsed).

use super::support::{Emitter, clean_value, indent_of, read_text, strip_v};
use super::{ScanTarget, file_name, find_line};
use std::path::Path;

const CSV_SUFFIX: &str = ".clusterserviceversion.yaml";

pub struct K8sOperatorTarget;

impl ScanTarget for K8sOperatorTarget {
    fn ecosystem_id(&self) -> &'static str {
        "k8s-operator"
    }

    fn detects(&self, path: &Path) -> bool {
        // Require at least one char of operator name before the suffix; a
        // bare hidden `.clusterserviceversion.yaml` is not a real bundle CSV.
        match file_name(path) {
            Some(name) => name.len() > CSV_SUFFIX.len() && name.ends_with(CSV_SUFFIX),
            None => false,
        }
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };

        let package_override = sibling_package_name(path, out);

        let csv = parse_csv(&contents);

        let name = package_override
            .or(csv.name)
            .unwrap_or_else(|| "unknown".to_string());
        let version = csv.version.unwrap_or_else(|| "unknown".to_string());
        out.pkg(&name, &version, find_line(&contents, "version"));

        // Identical canonical coordinates from different raw refs are deduped
        // globally by discovery.
        for img in csv.images {
            let oci = parse_image_ref(&img);
            out.pkg_in("oci", &oci.repo, &oci.pin, find_line(&contents, &img));
        }
    }
}

/// Read the bundle package name from `<bundle>/metadata/annotations.yaml`
/// (the CSV lives in `<bundle>/manifests/`). Best-effort: flattened
/// `registry+v1` catalogs may not ship it on disk; absence is normal, never
/// a warning.
fn sibling_package_name(csv_path: &Path, out: &mut Emitter<'_>) -> Option<String> {
    let manifests_dir = csv_path.parent()?;
    let bundle_dir = manifests_dir.parent()?;
    let annotations = bundle_dir.join("metadata").join("annotations.yaml");
    if !annotations.is_file() {
        return None;
    }
    let contents = read_text(&annotations, out)?;
    parse_bundle_package(&contents)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Csv {
    name: Option<String>,
    version: Option<String>,
    images: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct OciRef {
    /// Full repository path including any registry host.
    repo: String,
    /// A `sha256:…` digest when present (preferred), else the tag, else
    /// `latest`.
    pin: String,
}

fn clean_line(raw: &str) -> &str {
    let line = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    line.strip_suffix('\r').unwrap_or(line)
}

/// Split `key: value` at the first colon, tolerating an optional leading
/// `- ` list marker.
fn split_kv(line: &str) -> Option<(&str, &str)> {
    let body = line.trim_start();
    let body = body.strip_prefix("- ").unwrap_or(body);
    let idx = body.find(':')?;
    let key = body[..idx].trim();
    if key.is_empty() {
        return None;
    }
    Some((key, body[idx + 1..].trim()))
}

fn normalize_operator_version(raw: &str) -> String {
    strip_v(clean_value(raw)).to_string()
}

/// Split a trailing version suffix off a `metadata.name`
/// (`memcached-operator.v0.10.0` -> name + version): scan for a `.`/`-`
/// boundary followed by an optional `v` and a SemVer-ish `D.D.D`.
fn split_name_version(name: &str) -> (String, Option<String>) {
    let chars: Vec<char> = name.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if i == 0 || (c != '.' && c != '-') {
            continue;
        }
        let mut j = i + 1;
        if j < chars.len() && (chars[j] == 'v' || chars[j] == 'V') {
            j += 1;
        }
        let rest: String = chars[j..].iter().collect();
        if looks_like_semver(&rest) {
            let base: String = chars[..i].iter().collect();
            return (base, Some(rest));
        }
    }
    (name.to_string(), None)
}

/// `1.2.3`, `1.2.3-alpha.1`, `1.2.3+build`, etc.: at least `D.D.D` up front.
fn looks_like_semver(s: &str) -> bool {
    let core = s.split(['-', '+']).next().unwrap_or(s);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() >= 3
        && parts[..3]
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Parse a CSV body. Multi-doc files only honour the document whose `kind`
/// is `ClusterServiceVersion` (metadata AND image collection both), so an
/// unrelated later document's `image:` never leaks into the bundle's
/// coordinates. The current top-level block is tracked so the captured
/// `name:` is `metadata.name` (not a maintainer or relatedImage name) and
/// `version:` is `spec.version`.
fn parse_csv(contents: &str) -> Csv {
    let doc = select_csv_document(contents);
    let mut csv = Csv::default();
    let mut top_block: Option<String> = None;

    for raw in doc.lines() {
        let line = clean_line(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = indent_of(line);

        if indent == 0 {
            if let Some((k, _)) = split_kv(trimmed) {
                top_block = Some(k.to_string());
            }
            continue;
        }

        if indent == 2
            && let Some((k, v)) = split_kv(trimmed)
        {
            match (top_block.as_deref(), k) {
                (Some("metadata"), "name") if !v.is_empty() && csv.name.is_none() => {
                    csv.name = Some(clean_value(v).to_string());
                }
                (Some("spec"), "version") if !v.is_empty() => {
                    csv.version = Some(normalize_operator_version(v));
                }
                _ => {}
            }
        }
    }

    if let Some(name) = csv.name.clone() {
        let (base, ver) = split_name_version(&name);
        csv.name = Some(base);
        if csv.version.is_none() {
            csv.version = ver;
        }
    }

    csv.images = collect_images(doc);

    csv
}

/// The one document this parser reads: the first `---`-separated document
/// whose top-level `kind` is `ClusterServiceVersion`, else the first document
/// with no `kind` at all (a kind-less fragment is assumed to be the CSV; the
/// filename convention already vouched for it).
fn select_csv_document(contents: &str) -> &str {
    let docs = split_documents(contents);
    docs.iter()
        .copied()
        .find(|doc| doc_kind(doc).as_deref() == Some("ClusterServiceVersion"))
        .or_else(|| docs.into_iter().find(|doc| doc_kind(doc).is_none()))
        .unwrap_or("")
}

fn split_documents(contents: &str) -> Vec<&str> {
    let mut docs = Vec::new();
    let mut start = 0;
    let mut pos = 0;
    for line in contents.split_inclusive('\n') {
        if clean_line(line.trim_end_matches('\n')).trim() == "---" {
            docs.push(&contents[start..pos]);
            start = pos + line.len();
        }
        pos += line.len();
    }
    docs.push(&contents[start..]);
    docs
}

/// The document's top-level `kind:` value, if any.
fn doc_kind(doc: &str) -> Option<String> {
    for raw in doc.lines() {
        let line = clean_line(raw);
        if indent_of(line) != 0 {
            continue;
        }
        if let Some((k, v)) = split_kv(line.trim())
            && k == "kind"
        {
            return Some(clean_value(v).to_string());
        }
    }
    None
}

/// Collect every OCI image reference (block `image:`/`containerImage:` keys
/// plus inline flow-style occurrences), preserving first-seen order.
fn collect_images(contents: &str) -> Vec<String> {
    let mut images: Vec<String> = Vec::new();
    let push = |val: &str, images: &mut Vec<String>| {
        let v = clean_value(val);
        // Reject obvious non-refs (empty, list/map openers).
        if v.is_empty() || v == "[]" || v.starts_with('{') {
            return;
        }
        images.push(v.to_string());
    };

    for raw in contents.lines() {
        let line = clean_line(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((k, v)) = split_kv(trimmed)
            && (k == "image" || k == "containerImage")
            && !v.is_empty()
        {
            push(v, &mut images);
            continue;
        }

        if let Some(found) = scan_flow_images(trimmed) {
            for img in found {
                push(&img, &mut images);
            }
        }
    }

    images
}

/// Find `image:` tokens inside a flow-style line, e.g.
/// `relatedImages: [{name: a, image: quay.io/x@sha256:..}]`. Re-capturing a
/// `containerImage:` here is harmless; identical coordinates collapse
/// downstream.
fn scan_flow_images(line: &str) -> Option<Vec<String>> {
    if !line.contains("image:") {
        return None;
    }
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(pos) = rest.find("image:") {
        let after = &rest[pos + "image:".len()..];
        let end = after.find([',', '}', ']']).unwrap_or(after.len());
        let val = after[..end].trim();
        if !val.is_empty() {
            out.push(val.to_string());
        }
        rest = &after[end..];
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Parse an OCI image reference into `repo` + a single `pin`. A digest may
/// coexist with a tag (`repo:tag@sha256:...`); the digest wins and the tag
/// is dropped. Never strips a leading `v` from a tag (tags are opaque).
fn parse_image_ref(raw: &str) -> OciRef {
    let s = clean_value(raw);

    let (before_digest, digest) = match s.split_once('@') {
        Some((repo_tag, dig)) => (repo_tag, Some(dig.to_string())),
        None => (s, None),
    };

    // A tag colon is only the LAST colon and only after the final `/`;
    // otherwise `host:port/repo` would be misread.
    let last_slash = before_digest.rfind('/');
    let tag = match before_digest.rfind(':') {
        Some(colon) if last_slash.map(|s| colon > s).unwrap_or(true) => {
            Some(before_digest[colon + 1..].to_string())
        }
        _ => None,
    };
    let repo = match (tag.as_ref(), before_digest.rfind(':')) {
        (Some(_), Some(colon)) => before_digest[..colon].to_string(),
        _ => before_digest.to_string(),
    };

    let pin = match (digest, tag) {
        (Some(d), _) => d,
        (None, Some(t)) => t,
        (None, None) => "latest".to_string(),
    };

    OciRef { repo, pin }
}

/// Read `operators.operatorframework.io.bundle.package.v1` from a
/// `metadata/annotations.yaml` body.
fn parse_bundle_package(contents: &str) -> Option<String> {
    const KEY: &str = "operators.operatorframework.io.bundle.package.v1";
    for raw in contents.lines() {
        let line = clean_line(raw);
        let trimmed = line.trim();
        if let Some((k, v)) = split_kv(trimmed)
            && k == KEY
            && !v.is_empty()
        {
            let name = clean_value(v);
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = r#"apiVersion: operators.coreos.com/v1alpha1
kind: ClusterServiceVersion
metadata:
  name: memcached-operator.v0.10.0
  namespace: placeholder
  annotations:
    capabilities: "Basic Install"
    containerImage: quay.io/example/memcached-operator:v0.10.0
    createdAt: "2024-09-01T00:00:00Z"
spec:
  displayName: Memcached Operator
  version: 0.10.0
  maturity: stable
  relatedImages:
    - name: manager
      image: quay.io/example/memcached-operator@sha256:7f3c9b2a4e5d6f7081920aabbccddeeff00112233445566778899aabbccddeeff
    - name: memcached
      image: docker.io/library/memcached@sha256:00112233445566778899aabbccddeeff7f3c9b2a4e5d6f7081920aabbccddeeff
  install:
    strategy: deployment
    spec:
      deployments:
        - name: memcached-operator
          spec:
            replicas: 1
            template:
              spec:
                containers:
                  - name: manager
                    image: quay.io/example/memcached-operator:v0.10.0
"#;

    #[test]
    fn csv_extracts_name_version_and_images() {
        let csv = parse_csv(CSV);
        assert_eq!(csv.name.as_deref(), Some("memcached-operator"));
        assert_eq!(csv.version.as_deref(), Some("0.10.0"));
        // containerImage + two relatedImages digests; the deployment container
        // tag-dups the containerImage (identical coordinates collapse in
        // discovery's global dedup).
        assert!(
            csv.images
                .contains(&"quay.io/example/memcached-operator:v0.10.0".to_string())
        );
        assert!(csv.images.iter().any(|i| i.contains("sha256:7f3c")));
        assert!(
            csv.images
                .iter()
                .any(|i| i.contains("docker.io/library/memcached"))
        );
    }

    #[test]
    fn operator_version_strips_leading_v_keeps_metadata() {
        assert_eq!(normalize_operator_version("v0.10.0"), "0.10.0");
        assert_eq!(normalize_operator_version("'0.10.0'"), "0.10.0");
        assert_eq!(
            normalize_operator_version("0.10.0+build.3"),
            "0.10.0+build.3"
        );
    }

    #[test]
    fn name_suffix_split() {
        assert_eq!(
            split_name_version("memcached-operator.v0.10.0"),
            ("memcached-operator".to_string(), Some("0.10.0".to_string()))
        );
        assert_eq!(
            split_name_version("foo-v0.10.0-1"),
            ("foo".to_string(), Some("0.10.0-1".to_string()))
        );
        assert_eq!(
            split_name_version("prometheus"),
            ("prometheus".to_string(), None)
        );
    }

    #[test]
    fn image_ref_digest_wins_over_tag() {
        let r = parse_image_ref("quay.io/x/op:v1.2.3@sha256:deadbeef");
        assert_eq!(r.repo, "quay.io/x/op");
        assert_eq!(r.pin, "sha256:deadbeef");
    }

    #[test]
    fn image_ref_tag_only() {
        let r = parse_image_ref("quay.io/example/memcached-operator:v0.10.0");
        assert_eq!(r.repo, "quay.io/example/memcached-operator");
        assert_eq!(r.pin, "v0.10.0"); // never strip leading v from a tag
    }

    #[test]
    fn image_ref_bare_implies_latest() {
        let r = parse_image_ref("docker.io/library/nginx");
        assert_eq!(r.repo, "docker.io/library/nginx");
        assert_eq!(r.pin, "latest");
    }

    #[test]
    fn image_ref_host_port_not_mistaken_for_tag() {
        let r = parse_image_ref("localhost:5000/team/app@sha256:abc");
        assert_eq!(r.repo, "localhost:5000/team/app");
        assert_eq!(r.pin, "sha256:abc");
    }

    #[test]
    fn flow_style_related_images_are_collected() {
        let body = r#"kind: ClusterServiceVersion
spec:
  version: 1.0.0
  relatedImages: [{name: a, image: quay.io/x@sha256:aa}, {name: b, image: docker.io/y:2.1}]
"#;
        let csv = parse_csv(body);
        assert!(csv.images.contains(&"quay.io/x@sha256:aa".to_string()));
        assert!(csv.images.contains(&"docker.io/y:2.1".to_string()));
    }

    #[test]
    fn bundle_package_name_parsed() {
        let body = r#"annotations:
  operators.operatorframework.io.bundle.mediatype.v1: registry+v1
  operators.operatorframework.io.bundle.package.v1: memcached-operator
  operators.operatorframework.io.bundle.channels.v1: alpha,stable
"#;
        assert_eq!(
            parse_bundle_package(body).as_deref(),
            Some("memcached-operator")
        );
    }

    #[test]
    fn multidoc_only_csv_doc_is_read() {
        let body = r#"apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: memcacheds.cache.example.com
spec:
  group: cache.example.com
  version: v9-not-the-operator
---
apiVersion: operators.coreos.com/v1alpha1
kind: ClusterServiceVersion
metadata:
  name: memcached-operator.v0.10.0
spec:
  version: 0.10.0
"#;
        let csv = parse_csv(body);
        assert_eq!(csv.name.as_deref(), Some("memcached-operator"));
        assert_eq!(csv.version.as_deref(), Some("0.10.0"));
    }

    #[test]
    fn images_in_non_csv_documents_are_ignored() {
        // An `image:` in an unrelated sibling document (a CRD, a Deployment)
        // must not be attributed to the operator bundle.
        let body = r#"apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - image: docker.io/unrelated/sidecar:9.9.9
---
apiVersion: operators.coreos.com/v1alpha1
kind: ClusterServiceVersion
metadata:
  name: memcached-operator.v0.10.0
spec:
  version: 0.10.0
  relatedImages:
    - name: manager
      image: quay.io/example/memcached-operator:v0.10.0
"#;
        let csv = parse_csv(body);
        assert_eq!(
            csv.images,
            vec!["quay.io/example/memcached-operator:v0.10.0".to_string()],
            "only the CSV document's images are collected"
        );
    }

    #[test]
    fn empty_and_malformed_tolerated() {
        assert_eq!(parse_csv(""), Csv::default());
        // kind CSV but no spec.version -> name kept, version None (caller -> unknown).
        let body = "kind: ClusterServiceVersion\nmetadata:\n  name: thing-operator\n";
        let csv = parse_csv(body);
        assert_eq!(csv.name.as_deref(), Some("thing-operator"));
        assert_eq!(csv.version, None);
    }
}
