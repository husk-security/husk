//! Buf Schema Registry modules: `buf.lock` (and unpinned `buf.yaml`
//! fallback) -> ecosystem `"buf"`. Inventory-only: no OSV/GHSA ecosystem.
//!
//! `buf.lock` is the authoritative pinned lockfile (direct + transitive);
//! `buf.yaml`'s `deps:` (list of strings, usually unpinned) is parsed only
//! when no sibling lock exists. `buf.gen.yaml` / `buf.work.yaml` / `.proto`
//! are deliberately not parsed.
//!
//! Lockfile dep entry shapes (we branch on shape, not the declared
//! `version:` key, so version-less legacy files also parse):
//!   * v1 / v1beta1: `{remote, owner, repository, commit, digest}` ->
//!     name = `remote/owner/repository` (v1beta1's `branch`/`create_time`
//!     ignored).
//!   * v2: `{name, commit, digest}`.
//!
//! BSR versions are NOT semver: the pin is an opaque 32-char dashless hex
//! commit id, never parsed or ranged. Name casing and the remote host are
//! preserved (private BSR instances supported). The `digest`
//! (`b1:`/`b4:`/`b5:`) is integrity metadata, never the version. The files
//! are shallow machine-generated YAML, so a line-oriented reader suffices.

use super::find_line;
use super::support::{Emitter, clean_value, indent_of, is_hex_id};

/// Sentinel for a module with no pinned commit (labels are mutable pointers,
/// never a pinned coordinate): record presence without claiming a version.
const UNPINNED: &str = "UNPINNED";

#[derive(Debug, PartialEq, Eq)]
struct BufCoord {
    /// Full `remote/owner/repository` path (casing preserved).
    name: String,
    /// BSR commit id, or [`UNPINNED`].
    version: String,
}

/// `buf.lock`: the authoritative pinned lockfile.
pub(super) fn buf_lock(contents: &str, out: &mut Emitter<'_>) {
    for c in parse_lock(contents) {
        let line = find_line(contents, &c.name);
        out.pkg(&c.name, &c.version, line);
    }
}

/// `buf.yaml`: unpinned fallback. When a sibling `buf.lock` exists, defer
/// entirely to it rather than emit unpinned duplicates.
pub(super) fn buf_yaml(contents: &str, out: &mut Emitter<'_>) {
    let has_lock = out
        .path()
        .parent()
        .map(|dir| dir.join("buf.lock").is_file())
        .unwrap_or(false);
    if has_lock {
        return;
    }
    for c in parse_yaml_deps(contents) {
        let line = find_line(contents, &c.name);
        out.pkg(&c.name, &c.version, line);
    }
}

/// Split a `key: value` line at the first colon, ignoring an optional leading
/// list marker.
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

/// Accumulator for one `deps:` list item across the two possible shapes
/// (v2 `name`, or v1/v1beta1 `remote`+`owner`+`repository`).
#[derive(Default)]
struct DepItem {
    name: Option<String>,
    remote: Option<String>,
    owner: Option<String>,
    repository: Option<String>,
    commit: Option<String>,
}

impl DepItem {
    /// `digest`, `branch`, `create_time` and any other key are intentionally
    /// ignored.
    fn record(&mut self, key: &str, value: &str) {
        let field = match key {
            "name" => &mut self.name,
            "remote" => &mut self.remote,
            "owner" => &mut self.owner,
            "repository" => &mut self.repository,
            "commit" => &mut self.commit,
            _ => return,
        };
        *field = Some(clean_value(value).to_string());
    }

    /// Resolve the accumulated item into a coord (if it has any name material)
    /// and reset the accumulator for the next item.
    fn flush(&mut self, out: &mut Vec<BufCoord>) {
        let item = std::mem::take(self);
        let resolved_name = match item.name {
            Some(n) if !n.is_empty() => Some(n),
            _ => match (item.remote, item.owner, item.repository) {
                (Some(r), Some(o), Some(p)) if !r.is_empty() && !o.is_empty() && !p.is_empty() => {
                    Some(format!("{r}/{o}/{p}"))
                }
                _ => None,
            },
        };
        if let Some(name) = resolved_name {
            let version = match item.commit {
                Some(c) if !c.is_empty() => c,
                _ => UNPINNED.to_string(),
            };
            out.push(BufCoord { name, version });
        }
    }
}

/// Parse a `buf.lock` body: one coord per `deps:` list item, shape-tolerant
/// (see [`DepItem`]). A named item with no commit is emitted as [`UNPINNED`]
/// rather than dropped.
fn parse_lock(contents: &str) -> Vec<BufCoord> {
    let mut out = Vec::new();
    let mut in_deps = false;
    let mut item = DepItem::default();

    for raw in contents.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" {
            continue;
        }
        let indent = indent_of(line);

        if !in_deps {
            if indent == 0 && trimmed.starts_with("deps:") {
                in_deps = true;
            }
            continue;
        }

        // A column-0 key that is not a list item ends the deps block.
        if indent == 0 && !trimmed.starts_with('-') {
            item.flush(&mut out);
            in_deps = false;
            continue;
        }

        if trimmed.starts_with('-') {
            item.flush(&mut out);
            if let Some((k, v)) = split_kv(trimmed) {
                item.record(k, v);
            }
            continue;
        }

        if let Some((k, v)) = split_kv(trimmed) {
            item.record(k, v);
        }
    }
    item.flush(&mut out);
    out
}

/// Parse a `buf.yaml` `deps:` list of strings (`buf.build/owner/repo`,
/// optionally `:commit` or `:label`). Split on the LAST colon: a 32-char hex
/// right side is a pinned commit, anything else is [`UNPINNED`].
fn parse_yaml_deps(contents: &str) -> Vec<BufCoord> {
    let mut out = Vec::new();
    let mut in_deps = false;

    for raw in contents.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "---" {
            continue;
        }
        let indent = indent_of(line);

        if !in_deps {
            if indent == 0 && trimmed.starts_with("deps:") {
                in_deps = true;
            }
            continue;
        }

        if indent == 0 && !trimmed.starts_with('-') {
            in_deps = false;
            continue;
        }
        let Some(item) = trimmed.strip_prefix('-') else {
            continue;
        };
        let value = clean_value(item);
        if value.is_empty() {
            continue;
        }
        out.push(split_module_ref(value));
    }
    out
}

fn split_module_ref(value: &str) -> BufCoord {
    match value.rsplit_once(':') {
        Some((module, reference)) if is_hex_id(reference, 32) => BufCoord {
            name: module.to_string(),
            version: reference.to_string(),
        },
        Some((module, _label)) => BufCoord {
            name: module.to_string(),
            version: UNPINNED.to_string(),
        },
        None => BufCoord {
            name: value.to_string(),
            version: UNPINNED.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUF_LOCK_V2: &str = r#"# Code generated by buf. DO NOT EDIT.
version: v2
deps:
  - name: buf.build/googleapis/googleapis
    commit: 7a6bc1e3207144b38e9066861e1de0ff
    digest: b5:6d05bde5ed4cd22531d7ca6467feb828
  - name: buf.build/grpc-ecosystem/grpc-gateway
    commit: 3f42134f4c564983838425bc43c7a65f
    digest: b5:abc1234567890def1234567890abcdef
"#;

    const BUF_LOCK_V1: &str = r#"# Generated by buf. DO NOT EDIT.
version: v1
deps:
  - remote: buf.build
    owner: googleapis
    repository: googleapis
    commit: 7a6bc1e3207144b38e9066861e1de0ff
    digest: b4:4af5b88c9a1d9b36421ad84a2cff211f
  - remote: buf.build
    owner: grpc-ecosystem
    repository: grpc-gateway
    branch: main
    create_time: 2023-01-02T03:04:05.000000Z
    commit: 3f42134f4c564983838425bc43c7a65f
    digest: b4:9a877cf260e1488d869a31fce3bea26d
"#;

    #[test]
    fn v2_shape_uses_name_and_commit() {
        let coords = parse_lock(BUF_LOCK_V2);
        assert_eq!(coords.len(), 2);
        let g = coords
            .iter()
            .find(|c| c.name == "buf.build/googleapis/googleapis")
            .expect("googleapis present");
        assert_eq!(g.version, "7a6bc1e3207144b38e9066861e1de0ff");
        let gw = coords
            .iter()
            .find(|c| c.name == "buf.build/grpc-ecosystem/grpc-gateway")
            .expect("grpc-gateway present");
        assert_eq!(gw.version, "3f42134f4c564983838425bc43c7a65f");
    }

    #[test]
    fn v1_shape_assembles_name_and_ignores_branch_createtime() {
        let coords = parse_lock(BUF_LOCK_V1);
        assert_eq!(
            coords,
            vec![
                BufCoord {
                    name: "buf.build/googleapis/googleapis".into(),
                    version: "7a6bc1e3207144b38e9066861e1de0ff".into(),
                },
                BufCoord {
                    name: "buf.build/grpc-ecosystem/grpc-gateway".into(),
                    version: "3f42134f4c564983838425bc43c7a65f".into(),
                },
            ]
        );
    }

    #[test]
    fn private_remote_host_is_preserved() {
        let body = "version: v1\ndeps:\n  - remote: bsr.acme.com\n    owner: team\n    repository: api\n    commit: 00112233445566778899aabbccddeeff\n";
        let coords = parse_lock(body);
        assert_eq!(coords[0].name, "bsr.acme.com/team/api");
    }

    #[test]
    fn commit_without_digest_still_emitted() {
        // Hand-edited file (despite DO NOT EDIT): commit present, digest gone.
        let body = "version: v2\ndeps:\n  - name: buf.build/acme/payments\n    commit: 0123456789abcdef0123456789abcdef\n";
        let coords = parse_lock(body);
        assert_eq!(coords[0].version, "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn name_without_commit_is_unpinned() {
        let body = "version: v2\ndeps:\n  - name: buf.build/acme/payments\n";
        let coords = parse_lock(body);
        assert_eq!(coords[0].name, "buf.build/acme/payments");
        assert_eq!(coords[0].version, UNPINNED);
    }

    #[test]
    fn empty_or_missing_deps_emits_nothing() {
        assert!(parse_lock("").is_empty());
        assert!(parse_lock("version: v2\n").is_empty());
        assert!(parse_lock("version: v2\ndeps: []\n").is_empty());
        assert!(parse_lock("version: v2\ndeps:\n").is_empty());
    }

    #[test]
    fn handles_crlf_and_header_comment() {
        let body = "# Generated by buf. DO NOT EDIT.\r\nversion: v2\r\ndeps:\r\n  - name: buf.build/a/b\r\n    commit: aaaabbbbccccddddeeeeffff00001111\r\n";
        let coords = parse_lock(body);
        assert_eq!(
            coords,
            vec![BufCoord {
                name: "buf.build/a/b".into(),
                version: "aaaabbbbccccddddeeeeffff00001111".into(),
            }]
        );
    }

    #[test]
    fn yaml_deps_pins_commit_but_not_label() {
        let body = r#"version: v2
deps:
  - buf.build/googleapis/googleapis:7a6bc1e3207144b38e9066861e1de0ff
  - buf.build/acme/api:main
  - buf.build/acme/bare
"#;
        let coords = parse_yaml_deps(body);
        assert_eq!(
            coords,
            vec![
                BufCoord {
                    name: "buf.build/googleapis/googleapis".into(),
                    version: "7a6bc1e3207144b38e9066861e1de0ff".into(),
                },
                BufCoord {
                    name: "buf.build/acme/api".into(),
                    version: UNPINNED.into(),
                },
                BufCoord {
                    name: "buf.build/acme/bare".into(),
                    version: UNPINNED.into(),
                },
            ]
        );
    }

    #[test]
    fn commit_id_detection() {
        // A BSR commit id is a 32-char dashless hex string.
        assert!(is_hex_id("7a6bc1e3207144b38e9066861e1de0ff", 32));
        assert!(!is_hex_id("main", 32));
        assert!(!is_hex_id("v1.2.0", 32));
        assert!(!is_hex_id("7a6bc1e3", 32));
    }
}
