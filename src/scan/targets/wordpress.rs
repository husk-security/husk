//! WordPress plugins & themes (ecosystem id `"wordpress"`, category web).
//!
//! OSV coverage: NONE. OSV.dev carries no WordPress ecosystem, so this target
//! is **pure local inventory** (no `osv_ecosystem` mapping). The whole point is
//! capturing the EXACT installed `(slug, version)` so a future enrichment
//! provider (Wordfence Intelligence, Patchstack), or an incident responder,
//! can flag a specific compromised release (cf. the EssentialPlugin/Flippa
//! supply-chain attack that shipped malware in `v2.6.7` of 30+ plugins).
//!
//! Carriers, all parsed the WordPress `get_file_data()` way (read first 8 KiB,
//! normalize line endings, scan for `Key: value` header lines after stripping
//! the leading comment markers):
//!   * `wp-content/plugins/<slug>/<mainfile>.php`: `Plugin Name:` (required
//!     gate) + `Version:`. PRIMARY. The main file has no fixed name.
//!   * `wp-content/themes/<slug>/style.css`: `Theme Name:` (required gate) +
//!     `Version:` (+ optional `Template:` => child theme of that parent slug).
//!     PRIMARY for themes.
//!   * `wp-content/plugins/<slug>/readme.txt`: `Stable tag:` as a SECONDARY
//!     version carrier; emitted only when a `Stable tag:` actually parses (a
//!     stray readme without one is not inventory).
//!
//! The directory `<slug>` is the canonical WordPress.org identifier and is used
//! as the coordinate name (lowercased); the header display name is not the
//! coordinate. Versions are free-form (NOT semver) and kept verbatim after a
//! light normalization (strip a leading `v`, trailing comment artifacts).

use super::support::Emitter;
use super::{ScanTarget, file_name};
use std::io::Read as _;
use std::path::Path;

/// WordPress reads only the first 8 KiB of a file when extracting headers; we
/// mirror that both for fidelity and to bound huge/minified files.
const HEADER_WINDOW: usize = 8192;

/// Plugins and themes, dispatched by the same target.
pub struct WordPressTarget;

impl ScanTarget for WordPressTarget {
    fn ecosystem_id(&self) -> &'static str {
        "wordpress"
    }

    fn detects(&self, path: &Path) -> bool {
        // Strictly gate on the `wp-content/{plugins,themes}` path segments so a
        // bare `readme.txt`/`style.css` elsewhere never trips us.
        let Some(name) = file_name(path) else {
            return false;
        };
        let is_candidate = name == "style.css"
            || name == "readme.txt"
            || Path::new(name)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("php"));
        if !is_candidate {
            return false;
        }
        under_wp_content(path)
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        // Bounded read: only the header window ever leaves the disk (a 200 MB
        // minified bundle must not be read whole just to scan its header).
        // Lossy decode so non-UTF8 binary noise can't abort us.
        let mut window = Vec::with_capacity(HEADER_WINDOW);
        let read = std::fs::File::open(path)
            .and_then(|f| f.take(HEADER_WINDOW as u64).read_to_end(&mut window));
        if let Err(err) = read {
            out.warn(err);
            return;
        }
        let text = normalize_newlines(&String::from_utf8_lossy(&window));

        let Some(slug) = slug_for(path) else {
            return;
        };

        let name = file_name(path).unwrap_or("");
        let parsed = if name == "style.css" {
            if find_header(&text, "Theme Name").is_none() {
                return;
            }
            ParsedHeader {
                version: find_header(&text, "Version"),
                version_line: header_line(&text, "Version"),
            }
        } else if name == "readme.txt" {
            // Secondary carrier, gated on its one meaningful header: a readme
            // with no parseable `Stable tag:` must not become inventory (any
            // stray readme under wp-content/plugins/** would otherwise emit an
            // empty-version coordinate).
            let parsed = ParsedHeader {
                version: find_header(&text, "Stable tag"),
                version_line: header_line(&text, "Stable tag"),
            };
            if parsed
                .version
                .as_deref()
                .and_then(normalize_version)
                .is_none()
            {
                return;
            }
            parsed
        } else {
            if find_header(&text, "Plugin Name").is_none() {
                return;
            }
            ParsedHeader {
                version: find_header(&text, "Version"),
                version_line: header_line(&text, "Version"),
            }
        };

        let version = parsed
            .version
            .as_deref()
            .and_then(normalize_version)
            .unwrap_or_default();

        out.pkg(&slug, &version, parsed.version_line);
    }
}

struct ParsedHeader {
    version: Option<String>,
    version_line: Option<usize>,
}

fn under_wp_content(path: &Path) -> bool {
    let comps: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    if comps
        .iter()
        .any(|c| matches!(*c, "node_modules" | "vendor" | ".git"))
    {
        return false;
    }
    comps
        .windows(2)
        .any(|w| w[0] == "wp-content" && matches!(w[1], "plugins" | "themes" | "mu-plugins"))
}

/// The slug = the component right after `plugins`/`themes`/`mu-plugins`. For a
/// single-file plugin (`.../plugins/hello.php`, no subdir) the slug is the file
/// stem. Returns a lowercased slug.
fn slug_for(path: &Path) -> Option<String> {
    let comps: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    let anchor = comps
        .iter()
        .position(|c| matches!(*c, "plugins" | "themes" | "mu-plugins"))?;
    let next = comps.get(anchor + 1)?;
    let is_file = comps.get(anchor + 2).is_none()
        && Path::new(next)
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("php"));
    let slug = if is_file {
        Path::new(next).file_stem().and_then(|s| s.to_str())?
    } else {
        next
    };
    let slug = slug.trim().to_ascii_lowercase();
    if slug.is_empty() { None } else { Some(slug) }
}

/// Replace `\r\n` and lone `\r` with `\n` so CR-only (classic Mac) files parse.
fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// Find the first `key: value` header line (case-insensitive key), stripping
/// the WordPress comment-marker prefix (optional `<?php` then any run of
/// space/tab/`/`/`*`/`#`/`@`) and trailing comment artifacts. Returns the
/// trimmed value (which may be empty if the field is present but blank).
fn find_header(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(value) = match_header_line(line, key) {
            return Some(value);
        }
    }
    None
}

/// 1-based line number of the first header line for `key`, for jump-to-source.
fn header_line(text: &str, key: &str) -> Option<usize> {
    text.lines()
        .position(|line| match_header_line(line, key).is_some())
        .map(|idx| idx + 1)
}

fn match_header_line(line: &str, key: &str) -> Option<String> {
    let stripped = strip_marker_prefix(line);
    let colon = stripped.find(':')?;
    let (found_key, rest) = stripped.split_at(colon);
    if !found_key.trim().eq_ignore_ascii_case(key) {
        return None;
    }
    let value = &rest[1..];
    Some(cleanup_header_comment(value))
}

/// Drop a leading optional `<?php` and then any run of comment markers
/// (space, tab, `/`, `*`, `#`, `@`), the port of WordPress's header regex
/// prefix `^(?:[ \t]*<\?php)?[ \t/*#@]*`.
fn strip_marker_prefix(line: &str) -> &str {
    let trimmed = line.trim_start_matches([' ', '\t']);
    let trimmed = trimmed.strip_prefix("<?php").unwrap_or(trimmed);
    trimmed.trim_start_matches([' ', '\t', '/', '*', '#', '@'])
}

/// Port of `_cleanup_header_comment`: trim, then strip trailing comment
/// artifacts (`*/`, `?>`, `*`) and surrounding whitespace.
fn cleanup_header_comment(value: &str) -> String {
    let mut v = value.trim();
    loop {
        let trimmed = v
            .trim_end()
            .trim_end_matches("*/")
            .trim_end_matches("?>")
            .trim_end_matches('*')
            .trim_end();
        if trimmed.len() == v.trim_end().len() {
            v = trimmed;
            break;
        }
        v = trimmed;
    }
    v.trim().to_string()
}

/// Normalize a free-form WordPress version. Returns `None` when there is no
/// usable version (empty, `trunk`, or no leading ASCII digit after `v`-strip).
fn normalize_version(value: &str) -> Option<String> {
    let v = value.trim().trim_matches(['"', '\'']).trim();
    if v.is_empty() || v.eq_ignore_ascii_case("trunk") {
        return None;
    }
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    let v = v.trim();
    if !v.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_value_strips_php_comment_markers() {
        let text = r#"<?php
/**
 * Plugin Name:       Acme SEO Toolkit
 * Version:           2.6.7
 * Text Domain:       acme-seo
 */"#;
        assert_eq!(
            find_header(text, "Plugin Name").as_deref(),
            Some("Acme SEO Toolkit")
        );
        assert_eq!(find_header(text, "Version").as_deref(), Some("2.6.7"));
        // case-insensitive key match
        assert_eq!(find_header(text, "version").as_deref(), Some("2.6.7"));
    }

    #[test]
    fn css_header_and_template() {
        let text = r#"/*
Theme Name: Aurora
Version: 1.4.0
Template: parenttheme
*/"#;
        assert_eq!(find_header(text, "Theme Name").as_deref(), Some("Aurora"));
        assert_eq!(find_header(text, "Version").as_deref(), Some("1.4.0"));
        assert_eq!(
            find_header(text, "Template").as_deref(),
            Some("parenttheme")
        );
    }

    #[test]
    fn version_normalization_keeps_freeform_rejects_trunk() {
        assert_eq!(normalize_version("2.6.7").as_deref(), Some("2.6.7"));
        assert_eq!(normalize_version("v1.4").as_deref(), Some("1.4"));
        assert_eq!(normalize_version("1.0-beta").as_deref(), Some("1.0-beta"));
        assert_eq!(normalize_version("  \"5.3\"  ").as_deref(), Some("5.3"));
        assert_eq!(normalize_version("trunk"), None);
        assert_eq!(normalize_version(""), None);
        assert_eq!(normalize_version("latest"), None);
    }

    #[test]
    fn slug_prefers_directory_then_file_stem() {
        let p = Path::new("site/wp-content/plugins/akismet/akismet.php");
        assert_eq!(slug_for(p).as_deref(), Some("akismet"));
        // single-file plugin -> file stem
        let single = Path::new("site/wp-content/plugins/hello.php");
        assert_eq!(slug_for(single).as_deref(), Some("hello"));
        // theme via style.css
        let theme = Path::new("site/wp-content/themes/Aurora/style.css");
        assert_eq!(slug_for(theme).as_deref(), Some("aurora"));
    }

    #[test]
    fn cr_only_line_endings_normalized() {
        let cr = "/*\rTheme Name: Aurora\rVersion: 1.4.0\r*/";
        let text = normalize_newlines(cr);
        assert_eq!(find_header(&text, "Version").as_deref(), Some("1.4.0"));
    }
}
