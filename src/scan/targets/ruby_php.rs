//! Ruby (`Gemfile.lock` → OSV `RubyGems`) and PHP (`composer.lock` → OSV
//! `Packagist`).

use super::support::{Emitter, LineFinder};
use serde_json::Value as JsonValue;

/// Gemfile.lock: under `GEM\n  specs:\n` resolved gems are listed at 4-space
/// indent as `name (version)`; their dependencies at 6-space indent (skipped:
/// dependency lines carry a version *requirement*, not a pin).
pub(super) fn gemfile_lock(contents: &str, out: &mut Emitter<'_>) {
    let mut in_specs = false;
    for (idx, raw) in contents.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }
        // A non-indented, non-empty line ends the current section.
        if !raw.starts_with(' ') && !trimmed.is_empty() {
            in_specs = false;
            continue;
        }
        if !in_specs {
            continue;
        }
        let indent = raw.chars().take_while(|c| *c == ' ').count();
        if indent != 4 {
            continue; // 6 = transitive dep requirement, not a resolved pin
        }
        if let Some((name, version)) = parse_gem_line(trimmed) {
            out.pkg(&name, &version, Some(idx + 1));
        }
    }
}

/// `rails (7.0.4)` → (`rails`, `7.0.4`). Platform-suffixed pins like
/// `nokogiri (1.13.9-x86_64-linux)` keep only the upstream version.
fn parse_gem_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once(" (")?;
    let version = rest.trim_end_matches(')');
    let version = version.split('-').next().unwrap_or(version);
    if name.is_empty() || version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some((name.trim().to_string(), version.to_string()))
}

/// composer.lock: `packages` / `packages-dev` arrays of `{name, version}`.
pub(super) fn composer_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("composer.lock is not valid JSON");
        return;
    };
    let mut lines = LineFinder::new(contents);
    for section in ["packages", "packages-dev"] {
        let Some(entries) = json.get(section).and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in entries {
            let Some(name) = entry.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
                continue;
            };
            // Composer pins often carry a leading `v` (e.g. `v3.4.0`).
            let version = version.trim_start_matches('v');
            out.pkg(&name.to_ascii_lowercase(), version, lines.find(name));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_gem_lines() {
        assert_eq!(
            parse_gem_line("rails (7.0.4)"),
            Some(("rails".to_string(), "7.0.4".to_string()))
        );
        assert_eq!(
            parse_gem_line("nokogiri (1.13.9-x86_64-linux)"),
            Some(("nokogiri".to_string(), "1.13.9".to_string()))
        );
        // Dependency-requirement lines (no exact pin) are rejected.
        assert_eq!(parse_gem_line("rails (>= 6.0)"), None);
    }

    #[test]
    fn composer_lowercases_and_strips_v() {
        let lock = r#"{"packages":[{"name":"PHPUnit/PHPUnit","version":"v9.5.0"}]}"#;
        let found: Vec<(String, String)> = run_parser("packagist", lock, composer_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect();
        assert_eq!(
            found,
            vec![("phpunit/phpunit".to_string(), "9.5.0".to_string())]
        );
    }
}
