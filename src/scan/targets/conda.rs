//! Conda / Mamba / Pixi (`conda-meta/*.json` records; `pixi.lock`) ->
//! inventory-only (no OSV ecosystem exists for `conda`; the `pypi:` entries in
//! a `pixi.lock` are real PyPI coordinates and route through the PyPI matcher).
//!
//! The primary, highest-reliability signal is a materialized environment's
//! `conda-meta/<name>-<version>-<build>.json` records: each file is one
//! installed, fully-resolved package whose unambiguous `name`/`version` JSON
//! fields beat any filename split (conda names contain hyphens, e.g.
//! `python-dateutil`). The secondary signal is Pixi's `pixi.lock`, which is
//! YAML but mechanically regular and hand-parsed line-by-line (no yaml crate).
use super::support::{Emitter, read_text, unquote};
use super::{ScanTarget, file_name, pep503_name};
use serde_json::Value as JsonValue;
use std::path::Path;

/// A `conda-meta/*.json` installed-package record: the most reliable proof
/// of a real conda/mamba/micromamba/pixi environment on disk.
pub struct CondaMetaTarget;

impl ScanTarget for CondaMetaTarget {
    fn ecosystem_id(&self) -> &'static str {
        "conda"
    }

    fn detects(&self, path: &Path) -> bool {
        // The extension check skips `history`, `*.json.lock`, `state`, markers.
        let is_json = path.extension().and_then(|e| e.to_str()) == Some("json");
        let in_conda_meta = path
            .parent()
            .and_then(file_name)
            .map(|dir| dir == "conda-meta")
            .unwrap_or(false);
        is_json && in_conda_meta
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(contents) = read_text(path, out) {
            parse_conda_meta(&contents, out);
        }
    }
}

/// One record -> one coordinate. Names are lowercased but NOT
/// PEP-503-normalized; conda treats `-`, `_` and `.` as distinct. Versions
/// (which may carry an epoch `N!` or `+local`) are preserved verbatim.
fn parse_conda_meta(contents: &str, out: &mut Emitter<'_>) {
    let Ok(obj) = serde_json::from_str::<JsonValue>(contents) else {
        return;
    };
    let (Some(name), Some(version)) = (
        obj.get("name").and_then(JsonValue::as_str).map(str::trim),
        obj.get("version")
            .and_then(JsonValue::as_str)
            .map(str::trim),
    ) else {
        return;
    };
    if name.is_empty() || version.is_empty() {
        return;
    }
    out.pkg(&name.to_lowercase(), version, None);
}

/// Pixi's lockfile (`pixi.lock`): fully pinned for both conda and pypi deps.
///
/// Anchors on the top-level `packages:` list; each item begins
/// `- conda: <url>` or `- pypi: <url>` (the discriminator decides the
/// ecosystem: conda inventory-only, pypi -> OSV `PyPI`) with indented
/// `name:`/`version:` keys. `name:`/`version:` inside a
/// `depends:`/`constrains:` block must never be read: a bare `key:` opens a
/// nested block whose children (including nested `- ` items) are ignored.
pub(super) fn pixi_lock(contents: &str, out: &mut Emitter<'_>) {
    let mut in_packages = false;
    let mut kind: Option<&'static str> = None; // "conda" | "pypi"
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut item_indent = 0usize; // indent of the `- ` marker
    let mut nested_indent: Option<usize> = None; // indent of an open `depends:`-style block key

    let flush = |kind: &mut Option<&'static str>,
                 name: &mut Option<String>,
                 version: &mut Option<String>,
                 out: &mut Emitter<'_>| {
        if let (Some(eco), Some(n), Some(v)) = (kind.take(), name.take(), version.take()) {
            let (ecosystem, canon) = normalize(eco, &n);
            out.pkg_in(ecosystem, &canon, &v, None);
        } else {
            *kind = None;
            *name = None;
            *version = None;
        }
    };

    for line in contents.lines() {
        if !in_packages {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        // A column-0 key other than a list item ends the `packages:` block.
        if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('-') {
            break;
        }
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();

        if let Some(rest) = trimmed.strip_prefix("- ") {
            // A list item deeper than the current item's marker belongs to a
            // nested block (`depends:` entries), never a new package.
            if kind.is_some() && indent > item_indent {
                continue;
            }
            flush(&mut kind, &mut name, &mut version, out);
            item_indent = indent;
            nested_indent = None;
            if rest.starts_with("conda:") {
                kind = Some("conda");
            } else if rest.starts_with("pypi:") {
                kind = Some("pypi");
            } else {
                kind = None;
            }
            continue;
        }

        if indent <= item_indent {
            continue;
        }
        // A nested block is skipped until a line returns to the key's own
        // indent; direct attributes written *after* the block still belong
        // to the item.
        if let Some(open_at) = nested_indent {
            if indent > open_at {
                continue;
            }
            nested_indent = None;
        }
        if trimmed.ends_with(':') && !trimmed.contains(' ') {
            // Bare `key:` with no inline value -> a nested block follows.
            nested_indent = Some(indent);
            continue;
        }
        if let Some(v) = trimmed.strip_prefix("name:") {
            name = Some(unquote(v.trim()).to_string());
        } else if let Some(v) = trimmed.strip_prefix("version:") {
            version = Some(unquote(v.trim()).to_string());
        }
    }
    flush(&mut kind, &mut name, &mut version, out);
}

/// `conda` names stay lowercase without PEP-503 collapsing; `pypi` names are
/// PEP-503 normalized (lowercase, runs of `-_.` -> `-`).
fn normalize(kind: &str, raw: &str) -> (&'static str, String) {
    if kind == "pypi" {
        ("pypi", pep503_name(raw))
    } else {
        ("conda", raw.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_conda_meta_record() {
        let json = r#"{
            "name": "python-dateutil",
            "version": "2.9.0",
            "build": "pyhd8ed1ab_0",
            "channel": "https://conda.anaconda.org/conda-forge/noarch"
        }"#;
        let pkgs = run_parser("conda", json, parse_conda_meta);
        // Hyphenated name proves the JSON fields are read, not the filename split.
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, "conda");
        assert_eq!(pkgs[0].name, "python-dateutil");
        assert_eq!(pkgs[0].version, "2.9.0");
    }

    #[test]
    fn conda_meta_requires_name_and_version() {
        assert!(run_parser("conda", r#"{"name":"numpy"}"#, parse_conda_meta).is_empty());
        assert!(run_parser("conda", r#"{"version":"1.0"}"#, parse_conda_meta).is_empty());
        assert!(run_parser("conda", r#"{"name":"","version":"1.0"}"#, parse_conda_meta).is_empty());
        assert!(run_parser("conda", "not json", parse_conda_meta).is_empty());
    }

    #[test]
    fn preserves_epoch_and_local_version() {
        let json = r#"{"name":"foo","version":"1!1.2.3+local"}"#;
        let pkgs = run_parser("conda", json, parse_conda_meta);
        assert_eq!(pkgs[0].version, "1!1.2.3+local");
    }

    #[test]
    fn parses_pixi_lock_conda_and_pypi() {
        // Raw literal: the YAML's leading whitespace is semantic.
        let lock = r#"version: 6
environments:
  default:
    packages:
      linux-64:
      - conda: https://conda.anaconda.org/conda-forge/linux-64/numpy-1.26.4-py312_0.conda
packages:
- conda: https://conda.anaconda.org/conda-forge/linux-64/numpy-1.26.4-py312_0.conda
  name: numpy
  version: 1.26.4
  build: py312h7d8d0a2_0
  subdir: linux-64
  depends:
  - name: not-a-package
  - version: not-a-version
- pypi: https://files.pythonhosted.org/packages/Flask_Login-0.6.tar.gz
  name: Flask_Login
  version: '0.6.3'
  requires_python: '>=3.7'
"#;
        let pkgs = run_parser("conda", lock, pixi_lock);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, "conda");
        assert_eq!(pkgs[0].name, "numpy");
        assert_eq!(pkgs[0].version, "1.26.4");
        // pypi names get PEP-503 normalization; the nested depends: block must
        // not have clobbered numpy's name/version.
        assert_eq!(pkgs[1].ecosystem, "pypi");
        assert_eq!(pkgs[1].name, "flask-login");
        assert_eq!(pkgs[1].version, "0.6.3");
    }

    #[test]
    fn attributes_after_a_nested_list_still_belong_to_the_item() {
        // The nested `depends:` list must not open a phantom item that
        // swallows later direct attributes.
        let lock = "packages:\n- conda: https://x/numpy.conda\n  depends:\n  - name: nested\n  name: numpy\n  version: 1.0.0\n";
        let pkgs = run_parser("conda", lock, pixi_lock);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "numpy");
        assert_eq!(pkgs[0].version, "1.0.0");
    }
}
