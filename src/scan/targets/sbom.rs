//! SBOM ingestion: CycloneDX and SPDX JSON.
//!
//! Both formats carry **Package URLs** (`purl`s,
//! `pkg:<type>/<namespace>/<name>@<version>`) that map onto ecosystems Husk
//! already understands, so an upstream `syft`/`trivy`/`cdxgen` SBOM's
//! resolution work is inherited directly.
//!
//! - **CycloneDX** (`bomFormat: "CycloneDX"`): `components[].purl`.
//! - **SPDX** (`spdxVersion: …`): `packages[].externalRefs[]` where
//!   `referenceType == "purl"`.
//!
//! Coordinates whose `purl` type has no Husk ecosystem mapping are skipped
//! rather than guessed.

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name};
use serde_json::Value as JsonValue;
use std::path::Path;

pub struct SbomTarget;

impl ScanTarget for SbomTarget {
    fn ecosystem_id(&self) -> &'static str {
        // The SBOM is a container of many ecosystems; this id is only the
        // registry label. Emitted coordinates carry their real per-purl id.
        "sbom"
    }

    fn detects(&self, path: &Path) -> bool {
        let Some(name) = file_name(path) else {
            return false;
        };
        let lower = name.to_ascii_lowercase();
        // Conventional SBOM filenames across tools.
        lower.ends_with(".cdx.json")
            || lower.ends_with(".spdx.json")
            || lower == "sbom.json"
            || lower == "bom.json"
            || lower.ends_with(".cdx")
            || lower.ends_with("cyclonedx.json")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        let Ok(json) = serde_json::from_str::<JsonValue>(&contents) else {
            out.warn("SBOM is not valid JSON");
            return;
        };
        for purl in collect_purls(&json) {
            if let Some((ecosystem, name, version)) = parse_purl(&purl) {
                out.pkg_in(&ecosystem, &name, &version, None);
            }
        }
    }
}

/// Collect every `purl` string from either a CycloneDX or SPDX document.
fn collect_purls(json: &JsonValue) -> Vec<String> {
    let mut purls = Vec::new();

    // CycloneDX: components[].purl (components may nest via components[].components).
    fn walk_components(value: &JsonValue, out: &mut Vec<String>) {
        let Some(components) = value.get("components").and_then(|v| v.as_array()) else {
            return;
        };
        for component in components {
            if let Some(purl) = component.get("purl").and_then(|v| v.as_str())
                && !purl.is_empty()
            {
                out.push(purl.to_string());
            }
            walk_components(component, out);
        }
    }
    walk_components(json, &mut purls);

    // SPDX: packages[].externalRefs[] with referenceType == "purl".
    if let Some(spdx_packages) = json.get("packages").and_then(|v| v.as_array()) {
        for pkg in spdx_packages {
            let Some(refs) = pkg.get("externalRefs").and_then(|v| v.as_array()) else {
                continue;
            };
            for ext in refs {
                let ref_type = ext
                    .get("referenceType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if ref_type.eq_ignore_ascii_case("purl")
                    && let Some(locator) = ext.get("referenceLocator").and_then(|v| v.as_str())
                    && !locator.is_empty()
                {
                    purls.push(locator.to_string());
                }
            }
        }
    }

    purls
}

/// Parse a `pkg:type/namespace/name@version?qualifiers#subpath` Package URL into
/// `(husk_ecosystem, name, version)`. Returns `None` for purls without a
/// version or whose type has no Husk ecosystem mapping.
fn parse_purl(purl: &str) -> Option<(String, String, String)> {
    let rest = purl.strip_prefix("pkg:")?;
    // Split the coordinate from qualifiers (`?…`); drop the subpath (`#…`).
    let (coord, qualifiers) = match rest.split_once('?') {
        Some((coord, tail)) => (coord, tail.split('#').next().unwrap_or("")),
        None => (rest.split('#').next().unwrap_or(rest), ""),
    };
    let (type_and_path, version) = coord.rsplit_once('@')?;
    let version = pct_decode(version);
    if version.is_empty() {
        return None;
    }

    // OS-package purls carry the OSV release in a `distro=` qualifier
    // (`distro=debian-12`); without it those coordinates stay inventory-only.
    let distro = qualifiers
        .split('&')
        .find_map(|kv| kv.strip_prefix("distro="))
        .map(pct_decode);

    let mut segments = type_and_path.split('/');
    let purl_type = segments.next()?.to_ascii_lowercase();
    let path_parts: Vec<String> = segments.filter(|s| !s.is_empty()).map(pct_decode).collect();
    if path_parts.is_empty() {
        return None;
    }
    let name = path_parts.last()?.clone();
    let namespace = &path_parts[..path_parts.len() - 1];

    let (ecosystem, full_name) =
        map_purl_type(&purl_type, namespace, &name, distro.as_deref(), &version)?;
    Some((ecosystem, full_name, version))
}

/// Map a purl type + namespace/name to a Husk ecosystem id and the coordinate
/// name in that ecosystem's convention. `None` = unmapped type (skip). OS types
/// (`deb`/`apk`/`rpm`) become the **release-qualified** id (`debian:12`,
/// `alpine:v3.19`, `redhat`) the distro scan targets emit, so OSV can match;
/// a container SBOM's OS packages would otherwise be silently inventory-only.
fn map_purl_type(
    purl_type: &str,
    namespace: &[String],
    name: &str,
    distro: Option<&str>,
    version: &str,
) -> Option<(String, String)> {
    let joined = |sep: &str| {
        if namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}{sep}{name}", namespace.join("/"))
        }
    };
    let mapped: (String, String) = match purl_type {
        "npm" => ("npm".into(), joined("/")), // @scope/name
        "pypi" => ("pypi".into(), name.replace('_', "-").to_ascii_lowercase()),
        "cargo" => ("cargo".into(), name.to_string()),
        "golang" => ("go".into(), joined("/")),
        "maven" => ("maven".into(), joined(":")), // group:artifact
        "nuget" => ("nuget".into(), name.to_ascii_lowercase()),
        "gem" => ("rubygems".into(), name.to_string()),
        "composer" => ("packagist".into(), joined("/").to_ascii_lowercase()),
        "hex" => ("hex".into(), name.to_string()),
        "pub" => ("pub".into(), name.to_string()),
        "cran" => ("cran".into(), name.to_string()),
        "conan" => ("conan".into(), name.to_string()),
        "swift" => ("swift".into(), joined("/")),
        "cocoapods" => ("cocoapods".into(), name.to_string()),
        "hackage" => ("hackage".into(), name.to_string()),
        "deb" => (deb_ecosystem(distro), name.to_string()),
        "apk" => (apk_ecosystem(distro), name.to_string()),
        "rpm" => (rpm_ecosystem(version), name.to_string()),
        "oci" | "docker" => ("oci".into(), joined("/")),
        "githubactions" | "github-actions" => ("github-actions".into(), joined("/")),
        _ => return None,
    };
    Some(mapped)
}

/// Split a `distro=<id>-<version>` qualifier value into `(id, version)`, with a
/// numeric-leading version (OSV distro ecosystems key on the numeric release,
/// never a codename).
fn split_distro(distro: Option<&str>) -> Option<(String, String)> {
    let (id, version) = distro?.split_once('-')?;
    if !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some((id.to_ascii_lowercase(), version.to_string()))
}

/// `debian:<version>` / `ubuntu:<version>` from `distro=`; bare `debian`
/// (inventory-only) when the release is absent or unrecognized.
fn deb_ecosystem(distro: Option<&str>) -> String {
    if let Some((id, version)) = split_distro(distro)
        && (id == "debian" || id == "ubuntu")
    {
        return format!("{id}:{version}");
    }
    "debian".to_string()
}

/// `alpine:v<MAJOR.MINOR>` from `distro=alpine-3.19.1`; bare `alpine` otherwise.
fn apk_ecosystem(distro: Option<&str>) -> String {
    if let Some((id, version)) = split_distro(distro)
        && id == "alpine"
    {
        let parts: Vec<&str> = version.split('.').collect();
        // Every dot-separated piece must be a non-empty run of digits, and
        // there must be at least two of them (`3.19`, `3.19.1`); an empty
        // component anywhere (`3.19.`, `3..19`) falls back to the bare
        // `alpine` id rather than vacuously passing an all-digits check.
        if parts.len() >= 2
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        {
            return format!("alpine:v{}.{}", parts[0], parts[1]);
        }
    }
    "alpine".to_string()
}

/// RPM family (`redhat`/`suse`/`fedora`/`rpm`) inferred from the version's
/// RELEASE dist tag (`…-18.el9_2` → redhat), reusing the dist-tag classifier
/// the rpm scan targets use so OSV `Red Hat` / `openSUSE` can match.
fn rpm_ecosystem(version: &str) -> String {
    let release = version.rsplit_once('-').map_or(version, |(_, r)| r);
    super::rpm_manifest::rpm_family(release).to_string()
}

/// Minimal percent-decoding for the bytes that appear in real purls (`%40`→`@`,
/// `%2F`→`/`, etc.). Leaves malformed escapes verbatim.
fn pct_decode(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_purls() {
        assert_eq!(
            parse_purl("pkg:npm/%40angular/core@13.0.1"),
            Some(("npm".into(), "@angular/core".into(), "13.0.1".into()))
        );
        assert_eq!(
            parse_purl("pkg:pypi/Django@4.2.1"),
            Some(("pypi".into(), "django".into(), "4.2.1".into()))
        );
        assert_eq!(
            parse_purl("pkg:maven/com.google.guava/guava@31.1-jre"),
            Some((
                "maven".into(),
                "com.google.guava:guava".into(),
                "31.1-jre".into()
            ))
        );
        assert_eq!(
            parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.0?type=module"),
            Some((
                "go".into(),
                "github.com/gin-gonic/gin".into(),
                "v1.9.0".into()
            ))
        );
        // Unmapped type and version-less purls are skipped.
        assert_eq!(parse_purl("pkg:generic/foo@1.0"), None);
        assert_eq!(parse_purl("pkg:npm/left-pad"), None);
    }

    #[test]
    fn os_purls_carry_the_release_qualified_ecosystem() {
        // A container SBOM's OS packages must map to the release-qualified id
        // (via the `distro=` qualifier) so OSV can match, not a bare
        // inventory-only `debian`/`alpine`/`rpm`.
        assert_eq!(
            parse_purl("pkg:deb/debian/bash@5.1-2+deb12u1?arch=amd64&distro=debian-12"),
            Some(("debian:12".into(), "bash".into(), "5.1-2+deb12u1".into()))
        );
        assert_eq!(
            parse_purl("pkg:deb/ubuntu/curl@7.81.0-1?distro=ubuntu-22.04"),
            Some(("ubuntu:22.04".into(), "curl".into(), "7.81.0-1".into()))
        );
        assert_eq!(
            parse_purl("pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.19.1"),
            Some(("alpine:v3.19".into(), "musl".into(), "1.2.4-r2".into()))
        );
        assert_eq!(
            parse_purl("pkg:rpm/rhel/openssl@3.0.7-18.el9_2?arch=x86_64&distro=rhel-9"),
            Some(("redhat".into(), "openssl".into(), "3.0.7-18.el9_2".into()))
        );

        // Missing/codename distro → bare inventory-only id (unchanged, no
        // false release qualification).
        assert_eq!(
            parse_purl("pkg:deb/debian/bash@5.1"),
            Some(("debian".into(), "bash".into(), "5.1".into()))
        );
        assert_eq!(
            parse_purl("pkg:deb/debian/bash@5.1?distro=debian-bookworm"),
            Some(("debian".into(), "bash".into(), "5.1".into()))
        );

        // A malformed alpine release with an empty version component (`3.` /
        // `3..19`) must NOT vacuously qualify; it falls back to bare `alpine`.
        assert_eq!(
            apk_ecosystem(Some("alpine-3.")),
            "alpine",
            "a trailing-dot release must not produce `alpine:v3.`"
        );
        assert_eq!(
            apk_ecosystem(Some("alpine-3..19")),
            "alpine",
            "an empty middle component must not qualify"
        );
        // An empty component PAST the first two pieces must also be rejected.
        assert_eq!(
            apk_ecosystem(Some("alpine-3.19.")),
            "alpine",
            "a trailing dot after MAJOR.MINOR must not produce `alpine:v3.19`"
        );
        assert_eq!(
            apk_ecosystem(Some("alpine-3.19..1")),
            "alpine",
            "an empty component after MAJOR.MINOR must not produce `alpine:v3.19`"
        );
        // A well-formed release still qualifies.
        assert_eq!(apk_ecosystem(Some("alpine-3.19.1")), "alpine:v3.19");
    }

    #[test]
    fn reads_cyclonedx_and_spdx() {
        let cdx = r#"{
            "bomFormat": "CycloneDX",
            "components": [
                { "type": "library", "name": "lodash", "purl": "pkg:npm/lodash@4.17.21" },
                { "type": "library", "name": "g", "purl": "pkg:cargo/serde@1.0.197" }
            ]
        }"#;
        let purls = collect_purls(&serde_json::from_str(cdx).unwrap());
        assert_eq!(purls.len(), 2);

        let spdx = r#"{
            "spdxVersion": "SPDX-2.3",
            "packages": [
                { "name": "requests", "externalRefs": [
                    { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                      "referenceLocator": "pkg:pypi/requests@2.31.0" } ] }
            ]
        }"#;
        let purls = collect_purls(&serde_json::from_str(spdx).unwrap());
        assert_eq!(purls, vec!["pkg:pypi/requests@2.31.0".to_string()]);
    }
}
