//! JetBrains IDE plugins (`META-INF/plugin.xml`): inventory-only, ecosystem
//! `jetbrains-plugin` (no OSV/GHSA ecosystem; the threat signal is id-based
//! matching against curated malicious-plugin lists).
//!
//! The coordinate is the descriptor's Marketplace-unique `<id>` (or legacy
//! `<name>` fallback) plus a free-form `<version>`. Only plaintext
//! `plugin.xml` files are parsed (source trees, extracted plugins);
//! installed plugins ship their descriptor inside a jar, and we deliberately
//! pull in no zip reader.

use super::support::{Emitter, path_ends_with, read_text};
use super::{ScanTarget, find_line};
use std::path::Path;

pub struct JetBrainsPluginTarget;

impl ScanTarget for JetBrainsPluginTarget {
    fn ecosystem_id(&self) -> &'static str {
        "jetbrains-plugin"
    }

    fn detects(&self, path: &Path) -> bool {
        path_ends_with(path, &["META-INF", "plugin.xml"])
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        if let Some((id, version)) = parse_plugin_xml(&contents) {
            let line = find_line(&contents, &format!("<id>{id}"))
                .or_else(|| find_line(&contents, &id))
                .or_else(|| find_line(&contents, "<idea-plugin"));
            out.pkg(&id, &version, line);
        }
    }
}

/// Returns `None` unless the `<idea-plugin` root element is present: the
/// gate that avoids hijacking Maven/Eclipse `plugin.xml` files (the generic
/// filename is why `detects` alone isn't enough). Id falls back to `<name>`
/// (id is optional and defaults to name).
fn parse_plugin_xml(contents: &str) -> Option<(String, String)> {
    if !contents.contains("<idea-plugin") {
        return None;
    }

    let id = first_element_text(contents, "id")
        .or_else(|| first_element_text(contents, "name"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())?;

    // Source-tree descriptors often carry a build-time placeholder
    // (`${version}`, `0.0.0`); normalize those to "unknown" rather than
    // emitting a bogus pinned version.
    let version = first_element_text(contents, "version")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !is_placeholder_version(s))
        .map(normalize_version)
        .unwrap_or_else(|| "unknown".to_string());

    Some((id, version))
}

/// Trimmed, entity/CDATA-decoded text of the first `<tag>..</tag>` (opening
/// tag may carry attributes).
fn first_element_text(contents: &str, tag: &str) -> Option<String> {
    let open_bare = format!("<{tag}>");
    let open_attr = format!("<{tag} ");
    let (start_idx, open_len) = match contents.find(&open_bare) {
        Some(i) => (i, open_bare.len()),
        None => {
            let i = contents.find(&open_attr)?;
            let rest = contents.get(i..)?;
            let gt = rest.find('>')?;
            (i, gt + 1)
        }
    };
    let after_open = start_idx + open_len;
    let body = contents.get(after_open..)?;
    let close = format!("</{tag}>");
    let end = body.find(&close)?;
    let raw = body.get(..end)?;
    Some(decode_xml(raw))
}

/// Strip a single CDATA wrapper (defensively) and decode the five predefined
/// XML entities. Trims surrounding whitespace.
fn decode_xml(raw: &str) -> String {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix("<![CDATA[")
        .and_then(|s| s.strip_suffix("]]>"))
        .unwrap_or(trimmed);
    inner
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // `&amp;` last so we don't double-decode an already-decoded `&`.
        .replace("&amp;", "&")
        .trim()
        .to_string()
}

/// A `<version>` that is clearly a build-time template, not a real version.
fn is_placeholder_version(v: &str) -> bool {
    v == "0.0.0"
        || v.eq_ignore_ascii_case("PLACEHOLDER")
        || v.contains('$')
        || v.contains('@')
        || v.contains('%')
        || v.contains('{')
}

/// JetBrains versions are free-form; we only trim and strip a rare leading `v`.
fn normalize_version(v: String) -> String {
    let trimmed = v.trim();
    trimmed
        .strip_prefix('v')
        .filter(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or(trimmed)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<idea-plugin>
  <id>com.example.aihelper</id>
  <name>AI Code Helper</name>
  <version>1.4.2</version>
  <vendor email="dev@example.com" url="https://example.com">Example Labs</vendor>
  <idea-version since-build="233" until-build="251.*"/>
  <description><![CDATA[ Adds AI-powered code completion. ]]></description>
  <change-notes><![CDATA[ <ul><li>version 9.9.9 of model</li></ul> ]]></change-notes>
  <depends>com.intellij.modules.platform</depends>
</idea-plugin>"#;

    #[test]
    fn parses_id_and_version() {
        assert_eq!(
            parse_plugin_xml(SAMPLE),
            Some(("com.example.aihelper".to_string(), "1.4.2".to_string()))
        );
    }

    #[test]
    fn ignores_non_idea_plugin_root() {
        // A Maven Mojo descriptor reuses plugin.xml but has a `<plugin>` root.
        let maven = "<plugin><artifactId>foo</artifactId><version>1.0</version></plugin>";
        assert_eq!(parse_plugin_xml(maven), None);
    }

    #[test]
    fn falls_back_to_name_when_id_absent() {
        let xml = "<idea-plugin><name>Legacy Plugin</name><version>2.0</version></idea-plugin>";
        assert_eq!(
            parse_plugin_xml(xml),
            Some(("Legacy Plugin".to_string(), "2.0".to_string()))
        );
    }

    #[test]
    fn placeholder_version_becomes_unknown() {
        let xml =
            "<idea-plugin><id>my.plugin</id><version>${pluginVersion}</version></idea-plugin>";
        assert_eq!(
            parse_plugin_xml(xml),
            Some(("my.plugin".to_string(), "unknown".to_string()))
        );
    }

    #[test]
    fn handles_build_number_version_and_entities() {
        let xml = "<idea-plugin><id>com.jetbrains.python</id><version>251.23774.435</version><vendor>JetBrains &amp; Co</vendor></idea-plugin>";
        assert_eq!(
            parse_plugin_xml(xml),
            Some((
                "com.jetbrains.python".to_string(),
                "251.23774.435".to_string()
            ))
        );
    }

    #[test]
    fn strips_leading_v() {
        assert_eq!(normalize_version("v1.2.3".to_string()), "1.2.3");
        // A `v` not followed by a digit (e.g. a name) is left alone.
        assert_eq!(normalize_version("vendorbuild".to_string()), "vendorbuild");
    }
}
