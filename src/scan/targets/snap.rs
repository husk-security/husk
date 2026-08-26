//! Snap (`meta/snap.yaml` under `/snap/<name>/<rev>/`). Linux distro-level
//! packages installed by snapd. Snap has **no OSV / advisory ecosystem** and
//! snap `version:` strings are explicitly opaque (no semantic meaning), so this
//! target is **inventory-only**: coordinates are recorded, never matched.
//!
//! The authoritative per-snap metadata file is `meta/snap.yaml` at the root of
//! each loop-mounted, read-only squashfs revision
//! (`/snap/<name>/<revision>/meta/snap.yaml`, with `/snap/<name>/current` a
//! symlink to the active revision). It carries the fully-resolved, pinned
//! `name:` and `version:` as top-level scalars. The revision (snapd's true
//! pinned identity) is the directory name, not a field in the file.
//!
//! We hand-roll a tiny line scanner rather than pulling a YAML crate: the keys
//! we need (`name`, `version`, and a few context fields) are always emitted as
//! flat, zero-indent scalars, so we read only column-0 `key: value` lines and
//! ignore everything indented (the `apps:`/`hooks:`/`plugs:` sub-maps).

use super::support::{Emitter, read_text, unquote};
use super::{ScanTarget, file_name};
use std::path::Path;

pub struct SnapTarget;

impl ScanTarget for SnapTarget {
    fn ecosystem_id(&self) -> &'static str {
        "snap"
    }

    fn detects(&self, path: &Path) -> bool {
        // A snap's metadata file is always named `snap.yaml` and lives directly
        // under a `meta/` directory (`.../meta/snap.yaml`). Requiring the parent
        // to be `meta` keeps us from hijacking the generic `snapcraft.yaml`
        // build recipe or unrelated `*.yaml` files.
        if !matches!(file_name(path), Some("snap.yaml")) {
            return false;
        }
        matches!(path.parent().and_then(file_name), Some("meta"))
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        let meta = parse_snap_yaml(&contents);

        let name = meta
            .name
            .filter(|n| !n.is_empty())
            .or_else(|| snap_name_from_path(path))
            .unwrap_or_default();
        if name.is_empty() {
            return;
        }

        // Version is an opaque string; record verbatim, falling back to a
        // placeholder when the snap declares none (adopt-info / unset).
        let version = meta.version.filter(|v| !v.is_empty());
        let version = version.as_deref().unwrap_or("unknown");

        // Fall back to line 1 rather than None so the finding still anchors.
        let line = meta.version_line.or(meta.name_line).or(Some(1));
        out.pkg(&name, version, line);
    }
}

/// The handful of top-level scalars we lift out of a `snap.yaml`.
#[derive(Default, Debug, PartialEq)]
struct SnapMeta {
    name: Option<String>,
    version: Option<String>,
    name_line: Option<usize>,
    version_line: Option<usize>,
}

/// Scan a `snap.yaml` for its top-level (column-0) `name:` and `version:`
/// scalars. Indented lines (sub-maps like `apps:`/`hooks:`) are ignored so an
/// indented `version:` inside an app block can never be mistaken for the snap's
/// own version. Values have surrounding single/double quotes stripped.
fn parse_snap_yaml(contents: &str) -> SnapMeta {
    let mut meta = SnapMeta::default();
    for (idx, raw) in contents.lines().enumerate() {
        // A document separator ends the first (and, for a real file, only) snap.
        if raw == "---" {
            break;
        }
        if raw.starts_with(|c: char| c.is_whitespace()) || raw.starts_with('#') {
            continue;
        }
        let Some((key, value)) = raw.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = unquote(value);
        match key {
            "name" if meta.name.is_none() => {
                meta.name = Some(value.to_string());
                meta.name_line = Some(idx + 1);
            }
            "version" if meta.version.is_none() => {
                meta.version = Some(value.to_string());
                meta.version_line = Some(idx + 1);
            }
            _ => {}
        }
    }
    meta
}

/// Recover the snap name from `.../snap/<name>/<revision>/meta/snap.yaml` by
/// taking the segment two levels above the `meta/` directory.
fn snap_name_from_path(path: &Path) -> Option<String> {
    // path = .../<name>/<revision>/meta/snap.yaml
    let meta_dir = path.parent()?; // .../<name>/<revision>/meta
    let revision_dir = meta_dir.parent()?; // .../<name>/<revision>
    let name_dir = revision_dir.parent()?; // .../<name>
    name_dir
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_top_level_name_and_version() {
        let yaml = "\
name: hello-world
version: '6.4'
summary: The 'hello-world' of snaps
type: app
base: core22
confinement: strict
apps:
  hello-world:
    command: bin/echo
    version: 99.99
";
        let meta = parse_snap_yaml(yaml);
        assert_eq!(meta.name.as_deref(), Some("hello-world"));
        // Quotes stripped; the indented `version: 99.99` inside `apps:` is ignored.
        assert_eq!(meta.version.as_deref(), Some("6.4"));
        assert_eq!(meta.version_line, Some(2));
    }

    #[test]
    fn handles_bare_and_distro_suffixed_versions() {
        let meta = parse_snap_yaml("name: firefox\nversion: 125.0.3-1\n");
        assert_eq!(meta.name.as_deref(), Some("firefox"));
        assert_eq!(meta.version.as_deref(), Some("125.0.3-1"));
    }

    #[test]
    fn strips_only_matching_quotes() {
        assert_eq!(unquote("'1.0'"), "1.0");
        assert_eq!(unquote("\"1.0\""), "1.0");
        assert_eq!(unquote("1.0"), "1.0");
        assert_eq!(unquote("'mismatch\""), "'mismatch\"");
    }
}
