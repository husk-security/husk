//! Shared OCI / Docker image-reference grammar.
//!
//! Targets that emit `oci` coordinates should canonicalize references here so
//! the same image gets the same coordinate from Dockerfiles, compose files, and
//! future image-bearing surfaces.

/// Parse a resolved image reference into `(canonical_name, version)`.
///
/// `canonical_name` is `<registry>/<repository>` with default Docker Hub
/// registry and `library/` namespace normalization. `version` is the
/// `algo:hex` digest when present and valid, otherwise the literal tag,
/// otherwise implicit `latest`.
pub(crate) fn parse_reference(reference: &str) -> Option<(String, String)> {
    let reference = reference.trim();
    if reference.is_empty() || reference.contains('$') {
        return None;
    }

    let (name_tag, digest) = match reference.rsplit_once('@') {
        Some((name_tag, digest)) if is_valid_digest(digest) => {
            (name_tag, Some(digest.to_ascii_lowercase()))
        }
        _ => (reference, None),
    };

    let last_slash = name_tag.rfind('/').map(|i| i as isize).unwrap_or(-1);
    let (name, tag) = match name_tag.rfind(':') {
        Some(colon) if (colon as isize) > last_slash => {
            (&name_tag[..colon], Some(&name_tag[colon + 1..]))
        }
        _ => (name_tag, None),
    };

    let canonical_name = canonical_name(name);
    if canonical_name.is_empty() {
        return None;
    }

    let version = match (&digest, tag) {
        (Some(digest), _) => digest.clone(),
        (None, Some(tag)) if !tag.is_empty() => tag.to_string(),
        _ => "latest".to_string(),
    };
    Some((canonical_name, version))
}

fn is_valid_digest(digest: &str) -> bool {
    let Some((algo, hex)) = digest.split_once(':') else {
        return false;
    };
    !algo.is_empty() && hex.len() >= 32 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

fn canonical_name(name: &str) -> String {
    let name = name.trim_matches('/');
    let (registry, repo) = match name.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            (normalize_registry(first), rest.to_string())
        }
        _ => ("docker.io".to_string(), name.to_string()),
    };
    let repo = repo.to_ascii_lowercase();
    if registry == "docker.io" && !repo.contains('/') {
        format!("{registry}/library/{repo}")
    } else {
        format!("{registry}/{repo}")
    }
}

fn normalize_registry(host: &str) -> String {
    let lower = host.to_ascii_lowercase();
    match lower.as_str() {
        "index.docker.io" | "registry-1.docker.io" | "docker.io" => "docker.io".to_string(),
        _ => lower,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_normalization() {
        assert_eq!(
            parse_reference("nginx"),
            Some(("docker.io/library/nginx".into(), "latest".into()))
        );
        assert_eq!(
            parse_reference("myorg/app:1.2.3"),
            Some(("docker.io/myorg/app".into(), "1.2.3".into()))
        );
        assert_eq!(
            parse_reference("localhost:5000/app"),
            Some(("localhost:5000/app".into(), "latest".into()))
        );
        assert_eq!(
            parse_reference("ghcr.io/org/app:v2"),
            Some(("ghcr.io/org/app".into(), "v2".into()))
        );
        assert_eq!(parse_reference("node:${TAG}"), None);
    }

    #[test]
    fn hub_aliases_fold_and_digests_validate() {
        assert_eq!(
            parse_reference("index.docker.io/library/nginx:1.27"),
            Some(("docker.io/library/nginx".into(), "1.27".into()))
        );
        let digest = "sha256:3d1d2c8e3f5b9a7c6e4d2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6";
        assert_eq!(
            parse_reference(&format!("gcr.io/distroless/static@{digest}")),
            Some(("gcr.io/distroless/static".into(), digest.into()))
        );
        assert!(!is_valid_digest("sha256:short"));
        assert!(!is_valid_digest("nocolon"));
    }
}
