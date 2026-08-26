//! Chocolatey (Windows): inventory-only (no OSV ecosystem).
//!
//! Chocolatey has no lockfile: the install root's `lib\` tree *is* the
//! installed-state, one `*.nuspec` per package dir. The authoritative pin is
//! `<metadata><id>` + `<metadata><version>`, never the lib folder name (it
//! is lowercased on disk while id casing is preserved in the nuspec), never
//! the ambiguous `.chocolatey\<id>.<version>` state folder (ids and versions
//! both contain dots), and never `<dependency version>` (a range).
//! `packages.config` is a declared wish-list shared with plain NuGet, not
//! installed-state, so it is not attributed to Chocolatey.
//!
//! The nuspec's default xmlns URI varies by year (2010/07 | 2011/08 |
//! 2012/06), so elements are matched by local name, namespace ignored.
//! Detection anchors on the `chocolatey/lib/` path so a stray .NET nuspec
//! elsewhere is not mis-attributed.

use super::ScanTarget;
use super::support::{Emitter, read_text};
use std::path::Path;

/// Chocolatey per-package nuspec under the install root's `lib\` tree.
pub struct ChocolateyNuspecTarget;

impl ScanTarget for ChocolateyNuspecTarget {
    fn ecosystem_id(&self) -> &'static str {
        "chocolatey"
    }

    fn detects(&self, path: &Path) -> bool {
        // Case-insensitive with backslashes normalized (Windows paths on any
        // host); `path_ends_with` can't express either, hence the local idiom.
        let normalized = path
            .to_string_lossy()
            .replace('\\', "/")
            .to_ascii_lowercase();
        normalized.ends_with(".nuspec") && normalized.contains("/chocolatey/lib/")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };

        // A botched install can leave a malformed/empty nuspec: emit
        // nothing rather than a blank coordinate.
        let Some((id, raw_version)) = parse_nuspec(&contents) else {
            return;
        };

        let version = normalize_version(&raw_version);
        if id.is_empty() || version.is_empty() {
            return;
        }

        out.pkg(&id, &version, None);
    }
}

/// Extract `(id, version)` from a nuspec body. The first non-empty
/// `id`/`version` element is the `<metadata>` one; `<dependency>` carries
/// its version as an *attribute*, never a child element, so it cannot be
/// confused here.
fn parse_nuspec(contents: &str) -> Option<(String, String)> {
    let id = element_text(contents, "id")?;
    let version = element_text(contents, "version")?;
    if id.is_empty() || version.is_empty() {
        return None;
    }
    Some((id, version))
}

/// Trimmed text of the first element whose local name (any `prefix:`
/// stripped, namespace ignored) equals `local`. Self-closing/empty elements
/// (`<id />`, `<version></version>`) yield `None` so sentinel/blank metadata
/// is skipped.
fn element_text(contents: &str, local: &str) -> Option<String> {
    let bytes = contents.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let lt = contents[i..].find('<')? + i;
        let after = &contents[lt + 1..];
        // Skip closing tags, comments, processing instructions, declarations.
        if after.starts_with('/') || after.starts_with('!') || after.starts_with('?') {
            i = lt + 1;
            continue;
        }
        let name_end = after
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(after.len());
        let raw_name = &after[..name_end];
        let tag_local = raw_name.rsplit(':').next().unwrap_or(raw_name);

        let gt_rel = after.find('>')?;
        let gt = lt + 1 + gt_rel;
        let self_closing = contents[..gt].ends_with('/');

        if tag_local.eq_ignore_ascii_case(local) {
            if self_closing {
                i = gt + 1;
                continue;
            }
            let rest = &contents[gt + 1..];
            let text_end = rest.find('<').unwrap_or(rest.len());
            let text = rest[..text_end].trim();
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
        i = gt + 1;
    }
    None
}

/// Normalize to NuGet's canonical form
/// (`Major.Minor.Patch[.Revision][-prerelease][+build]`): strip `+build`
/// metadata (not identity), keep `-prerelease` (identity), strip leading
/// zeros per numeric segment (`1.00` -> `1.0`), drop a zero 4th revision
/// segment (`1.0.0.0` -> `1.0.0`, `1.2.3.4` stays). Non-numeric segments
/// pass through verbatim.
fn normalize_version(raw: &str) -> String {
    let raw = raw.trim();
    let raw = raw.split('+').next().unwrap_or(raw);
    let (numeric, prerelease) = match raw.split_once('-') {
        Some((num, pre)) => (num, Some(pre)),
        None => (raw, None),
    };

    let mut parts: Vec<String> = numeric
        .split('.')
        .map(|seg| {
            if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
                let trimmed = seg.trim_start_matches('0');
                if trimmed.is_empty() {
                    "0".to_string()
                } else {
                    trimmed.to_string()
                }
            } else {
                seg.to_string()
            }
        })
        .collect();

    if parts.len() == 4 && parts[3] == "0" {
        parts.pop();
    }

    let mut out = parts.join(".");
    if let Some(pre) = prerelease {
        out.push('-');
        out.push_str(pre);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIT_NUSPEC: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd">
  <metadata>
    <id>git</id>
    <version>2.43.0</version>
    <title>Git</title>
    <authors>The Git Development Community</authors>
    <description>Git is a distributed version control system.</description>
    <dependencies>
      <dependency id="git.install" version="2.43.0" />
    </dependencies>
  </metadata>
</package>
"#;

    #[test]
    fn parses_id_and_version_ignoring_namespace_and_dependency() {
        // Must read metadata/id + metadata/version, NOT the <dependency> attrs.
        assert_eq!(
            parse_nuspec(GIT_NUSPEC),
            Some(("git".to_string(), "2.43.0".to_string()))
        );
    }

    #[test]
    fn skips_empty_sentinel_metadata() {
        // Self-closing / empty id or version => no coordinate (choco #2850).
        let empty = r#"<package><metadata><id /><version></version></metadata></package>"#;
        assert_eq!(parse_nuspec(empty), None);
    }

    #[test]
    fn normalizes_nuget_versions() {
        assert_eq!(normalize_version("1.01.1"), "1.1.1");
        assert_eq!(normalize_version("1.0.0.0"), "1.0.0");
        assert_eq!(normalize_version("1.2.3.4"), "1.2.3.4");
        assert_eq!(normalize_version("1.0.7+r3456"), "1.0.7");
        assert_eq!(normalize_version("2.0.0-beta1"), "2.0.0-beta1");
        assert_eq!(normalize_version("2.43.0"), "2.43.0");
    }
}
