//! Helm charts (`Chart.lock` / `Chart.yaml` + legacy `requirements.*`) ->
//! ecosystem `"helm"`. Inventory-only: no OSV/GHSA ecosystem; advisories key
//! on the container *images* a chart deploys, not the chart package.
//!
//! Dependency sources, in priority order: `Chart.lock` (pinned) ->
//! `requirements.lock` (legacy, same schema) -> `Chart.yaml`'s
//! `dependencies:` block / `requirements.yaml` (versions are often ranges).
//! The chart's own self-coordinate from the root `Chart.yaml` is always
//! emitted too. The files are YAML but JSON-tag-shaped and shallow (Helm
//! deserializes via `sigs.k8s.io/yaml`), so a line-oriented reader suffices.
//!
//! `name` is verbatim (chart names are already lowercase DNS-1123); `version`
//! has a single leading `v` and quotes stripped, prerelease/build metadata
//! preserved. `repository` is provenance, never part of the coordinate.

use super::support::{Emitter, clean_value, indent_of, read_text, strip_v};
use super::{ScanTarget, file_name, find_line};
use std::path::Path;

/// One chart coordinate (the chart itself, or one of its dependencies).
#[derive(Debug, PartialEq, Eq)]
struct HelmCoord {
    name: String,
    version: String,
}

pub struct HelmLockTarget;

impl ScanTarget for HelmLockTarget {
    fn ecosystem_id(&self) -> &'static str {
        "helm"
    }

    fn detects(&self, path: &Path) -> bool {
        // `Chart.lock` is unambiguous; the more generic `requirements.lock`
        // is gated on a sibling `Chart.yaml`.
        match file_name(path) {
            Some("Chart.lock") => true,
            Some("requirements.lock") => path
                .parent()
                .map(|dir| dir.join("Chart.yaml").is_file())
                .unwrap_or(false),
            _ => false,
        }
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        for c in parse_lock(&contents) {
            let line = find_line(&contents, &c.name);
            out.pkg(&c.name, &c.version, line);
        }
    }
}

/// `Chart.yaml`: the chart's self-coordinate, plus its `dependencies:` only
/// when no lock file shadows this chart; otherwise the pinned lock entries
/// win and the ranges would duplicate them.
pub(super) fn chart_yaml(contents: &str, out: &mut Emitter<'_>) {
    let has_lock = out
        .path()
        .parent()
        .map(|dir| dir.join("Chart.lock").is_file() || dir.join("requirements.lock").is_file())
        .unwrap_or(false);
    for c in parse_chart_yaml(contents, !has_lock) {
        let line = find_line(contents, &c.name);
        out.pkg(&c.name, &c.version, line);
    }
}

fn clean_version(raw: &str) -> String {
    strip_v(clean_value(raw)).to_string()
}

/// Split a `key: value` line at the first colon, allowing an optional leading
/// `- ` list marker.
fn split_kv(line: &str) -> Option<(&str, &str)> {
    let body = line.trim_start();
    let body = body.strip_prefix("- ").unwrap_or(body);
    let idx = body.find(':')?;
    let key = body[..idx].trim();
    let value = body[idx + 1..].trim();
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Parse a `Chart.lock` / `requirements.lock` body: one coord per
/// `dependencies:` list item with a present `name` + `version` (keys arrive
/// in arbitrary order, helm#13245); `digest:`/`generated:` ignored.
fn parse_lock(contents: &str) -> Vec<HelmCoord> {
    let mut out = Vec::new();
    let mut in_deps = false;
    let mut cur_name: Option<String> = None;
    let mut cur_version: Option<String> = None;

    let flush =
        |out: &mut Vec<HelmCoord>, name: &mut Option<String>, version: &mut Option<String>| {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                if !n.is_empty() && !v.is_empty() {
                    out.push(HelmCoord {
                        name: n,
                        version: v,
                    });
                }
            } else {
                *name = None;
                *version = None;
            }
        };

    for raw in contents.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" {
            continue;
        }
        let indent = indent_of(line);

        if !in_deps {
            if indent == 0 && trimmed.starts_with("dependencies:") {
                in_deps = true;
            }
            continue;
        }

        // A column-0 top-level key (`digest:`, `generated:`) ends the block.
        if indent == 0 && !trimmed.starts_with('-') {
            flush(&mut out, &mut cur_name, &mut cur_version);
            in_deps = false;
            continue;
        }

        if trimmed.starts_with('-') {
            flush(&mut out, &mut cur_name, &mut cur_version);
            // A key may sit on the same line as the dash: `- name: redis`.
            if let Some((k, v)) = split_kv(trimmed) {
                record_kv(k, v, &mut cur_name, &mut cur_version);
            }
            continue;
        }

        if let Some((k, v)) = split_kv(trimmed) {
            record_kv(k, v, &mut cur_name, &mut cur_version);
        }
    }
    flush(&mut out, &mut cur_name, &mut cur_version);
    out
}

fn record_kv(key: &str, value: &str, name: &mut Option<String>, version: &mut Option<String>) {
    match key {
        "name" => *name = Some(clean_value(value).to_string()),
        "version" => *version = Some(clean_version(value)),
        _ => {}
    }
}

/// Parse a `Chart.yaml` body: the self-coordinate when the file looks like a
/// real chart (has top-level `apiVersion`), plus the `dependencies:` items
/// when `include_deps` (no lock present). Top-level `name:`,
/// `maintainers[].name:` and `dependencies[].name:` share the same key, so
/// scalars are anchored strictly to indentation.
fn parse_chart_yaml(contents: &str, include_deps: bool) -> Vec<HelmCoord> {
    let mut out = Vec::new();
    let mut self_name: Option<String> = None;
    let mut self_version: Option<String> = None;
    let mut has_api_version = false;

    for raw in contents.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if indent_of(line) != 0 {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // A dash at column 0 is a `dependencies:` list item (`- name: redis`),
        // not a top-level scalar; never treat it as the chart's self name.
        if trimmed.starts_with('-') {
            continue;
        }
        if let Some((k, v)) = split_kv(trimmed) {
            match k {
                "apiVersion" => has_api_version = true,
                "name" if !v.is_empty() => self_name = Some(clean_value(v).to_string()),
                "version" if !v.is_empty() => self_version = Some(clean_version(v)),
                _ => {}
            }
        }
    }

    if !has_api_version {
        return out;
    }
    if let (Some(n), Some(v)) = (self_name, self_version)
        && !n.is_empty()
        && !v.is_empty()
    {
        out.push(HelmCoord {
            name: n,
            version: v,
        });
    }

    if include_deps {
        // `dependencies:` here has the same item shape as the lock.
        out.extend(parse_lock(contents));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHART_LOCK: &str = "dependencies:\n\
        - name: redis\n  \
          repository: oci://registry-1.docker.io/bitnamicharts\n  \
          version: 18.0.0\n\
        - name: postgresql\n  \
          repository: https://charts.bitnami.com/bitnami\n  \
          version: \"12.5.6\"\n\
        digest: sha256:9f3a8c2b7e1d4a6f0c5b2e8d1a4f7c9b\n\
        generated: \"2026-02-14T09:31:22.481223Z\"\n";

    #[test]
    fn lock_parses_pinned_deps_ignoring_digest_and_generated() {
        let coords = parse_lock(CHART_LOCK);
        assert_eq!(
            coords,
            vec![
                HelmCoord {
                    name: "redis".into(),
                    version: "18.0.0".into()
                },
                HelmCoord {
                    name: "postgresql".into(),
                    version: "12.5.6".into()
                },
            ]
        );
    }

    #[test]
    fn lock_field_order_is_arbitrary() {
        // Helm has emitted non-deterministic field order (helm#13245).
        let body = "dependencies:\n\
            - version: 1.2.3\n  \
              name: foo\n";
        let coords = parse_lock(body);
        assert_eq!(
            coords,
            vec![HelmCoord {
                name: "foo".into(),
                version: "1.2.3".into()
            }]
        );
    }

    #[test]
    fn lock_strips_leading_v_and_quotes() {
        let body = "dependencies:\n- name: cert-manager\n  version: 'v1.14.0'\n";
        let coords = parse_lock(body);
        assert_eq!(coords[0].version, "1.14.0");
    }

    #[test]
    fn lock_keeps_prerelease_metadata() {
        let body = "dependencies:\n- name: app\n  version: 2.0.0-alpha.1+build5\n";
        let coords = parse_lock(body);
        assert_eq!(coords[0].version, "2.0.0-alpha.1+build5");
    }

    #[test]
    fn lock_tolerates_empty_and_null_deps() {
        assert!(parse_lock("").is_empty());
        assert!(parse_lock("dependencies: []\ndigest: sha256:x\n").is_empty());
        assert!(parse_lock("dependencies:\ndigest: sha256:x\n").is_empty());
    }

    #[test]
    fn lock_handles_crlf() {
        let body = "dependencies:\r\n- name: redis\r\n  version: 18.0.0\r\n";
        let coords = parse_lock(body);
        assert_eq!(
            coords,
            vec![HelmCoord {
                name: "redis".into(),
                version: "18.0.0".into()
            }]
        );
    }

    #[test]
    fn chart_yaml_emits_self_coord_and_skips_maintainer_names() {
        let body = "apiVersion: v2\n\
            name: my-umbrella-app\n\
            version: 1.4.2\n\
            appVersion: \"2.10.0\"\n\
            maintainers:\n  \
            - name: Erik\n    \
              email: e@example.com\n";
        // No deps requested: only the chart self-coordinate, never the
        // maintainer `name:`.
        let coords = parse_chart_yaml(body, false);
        assert_eq!(
            coords,
            vec![HelmCoord {
                name: "my-umbrella-app".into(),
                version: "1.4.2".into()
            }]
        );
    }

    #[test]
    fn chart_yaml_includes_dep_ranges_when_no_lock() {
        let body = "apiVersion: v2\n\
            name: my-umbrella-app\n\
            version: 1.4.2\n\
            dependencies:\n\
            - name: redis\n  \
              version: ^18.0.0\n  \
              repository: oci://registry-1.docker.io/bitnamicharts\n\
            - name: postgresql\n  \
              version: \"~12.5.0\"\n  \
              repository: https://charts.bitnami.com/bitnami\n";
        let coords = parse_chart_yaml(body, true);
        let names: Vec<&str> = coords.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["my-umbrella-app", "redis", "postgresql"]);
        // Ranges are passed through verbatim (marked unresolved by being a range).
        assert_eq!(coords[1].version, "^18.0.0");
        assert_eq!(coords[2].version, "~12.5.0");
    }

    #[test]
    fn chart_yaml_without_api_version_is_not_helm() {
        // A stray YAML file that happens to have name/version is not a chart.
        assert!(parse_chart_yaml("name: foo\nversion: 1.0.0\n", true).is_empty());
    }
}
