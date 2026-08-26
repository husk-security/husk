//! Perl / CPAN: the `cpanfile` DECLARED dependency manifest.
//!
//! Ecosystem id `cpan` (shared with the Carton `cpanfile.snapshot` target in
//! `perl.rs`); no OSV ecosystem, so inventory-only until a CPAN advisory feed
//! (CPANSA) is bundled.
//!
//! `cpanfile` is real Perl source; we NEVER eval it (arbitrary code
//! execution); we statically scan the comment-stripped directive lines.
//! One coordinate per module with an EXACT pin (bare `1.23`, or `== 1.02`
//! with the operator stripped); ranges/inequalities/missing/variable versions
//! are skipped, as is the `perl` interpreter pseudo-module. The coordinate is
//! the module name verbatim (`JSON::XS`); CPAN advisories often key by
//! DISTRIBUTION name (`JSON-XS`) instead, but mapping needs the 02packages
//! index (out of scope).

use super::ScanTarget;
use super::support::{Emitter, read_text};
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

pub struct CpanfileTarget;

impl ScanTarget for CpanfileTarget {
    fn ecosystem_id(&self) -> &'static str {
        "cpan"
    }

    fn detects(&self, path: &Path) -> bool {
        // `cpanfile` or a named variant like `dev.cpanfile`, but NOT
        // `cpanfile.snapshot` (the Carton lockfile, owned by `perl.rs`).
        let Some(name) = super::file_name(path) else {
            return false;
        };
        if name == "cpanfile.snapshot" {
            return false;
        }
        name == "cpanfile" || name.ends_with(".cpanfile")
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        for dep in parse_cpanfile(&contents) {
            out.pkg(&dep.name, &dep.version, Some(dep.line));
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Dep {
    name: String,
    version: String,
    /// 1-based source line.
    line: usize,
}

/// Matches the `requires` family (`requires`, `configure_/build_/test_/
/// author_requires`); `recommends`/`suggests`/`conflicts` deliberately not.
/// Name and version must be quoted literals; a bareword/`$variable` version
/// is not statically resolvable and is treated as absent.
fn directive_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\b(?:configure_|build_|test_|author_)?requires\s*\(?\s*(?:'([^']*)'|"([^"]*)")\s*(?:,\s*(?:'([^']*)'|"([^"]*)"))?"#,
        )
        .expect("static cpanfile directive regex compiles")
    })
}

/// Drop everything from the first unquoted `#`; a `#` inside a quoted string
/// is preserved.
fn strip_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..idx],
            _ => {}
        }
    }
    line
}

/// Normalize an EXACT pin (`1.23`, `v1.2.3`, or `== 1.02` with the operator
/// stripped) into a coordinate version; ranges/inequalities/lists/empty are
/// not pins and yield `None`.
fn normalize_exact_version(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if spec.contains(',') {
        return None;
    }
    // `==` is the only operator that pins.
    let body = match spec.strip_prefix("==") {
        Some(rest) => rest.trim(),
        None => spec,
    };
    if body.is_empty() {
        return None;
    }
    let mut chars = body.chars();
    let pinned = match chars.next() {
        Some(c) if c.is_ascii_digit() => true,
        Some('v') => matches!(chars.next(), Some(c) if c.is_ascii_digit()),
        _ => false,
    };
    if !pinned {
        return None;
    }
    // Defensively reject any inequality operator that slipped through.
    if body.contains(['>', '<', '!', '=']) {
        return None;
    }
    Some(body.to_string())
}

/// Scan the comment-stripped cpanfile text for directive occurrences.
/// Non-line-anchored so multiple directives on one line inside a `sub { ... }`
/// block are all captured. Never evaluates the Perl.
fn parse_cpanfile(contents: &str) -> Vec<Dep> {
    let re = directive_regex();
    let mut deps = Vec::new();

    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let line = line.strip_prefix('\u{feff}').unwrap_or(line);
        let line = strip_comment(line);

        for caps in re.captures_iter(line) {
            let Some(name) = caps.get(1).or_else(|| caps.get(2)) else {
                continue;
            };
            let name = name.as_str();
            if name == "perl" {
                continue; // interpreter version, not a CPAN module.
            }
            let version = caps.get(3).or_else(|| caps.get(4)).map(|m| m.as_str());
            let Some(version) = version.and_then(normalize_exact_version) else {
                continue;
            };
            deps.push(Dep {
                name: name.to_string(),
                version,
                line: idx + 1,
            });
        }
    }

    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# cpanfile - declared CPAN dependencies
requires 'perl', '5.010';
requires 'Plack', '1.0';                 # bare version -> cpan/Plack@1.0
requires 'JSON::XS', '== 4.03';          # exact -> cpan/JSON::XS@4.03
requires 'Moose', '>= 2.2000, < 3.0';
requires 'DBI', '>= 1.643';
requires 'strict';
requires 'warnings';
recommends 'JSON::XS', '2.0';
conflicts 'JSON', '< 2.0';
on 'test' => sub {
    requires 'Test::More', '0.96';
    requires 'Test::Deep', '>= 1.130';
};
feature 'sqlite', 'SQLite support' => sub {
    recommends 'DBD::SQLite', '1.50';
};
"#;

    #[test]
    fn collects_only_exact_pins_from_requires() {
        let deps = parse_cpanfile(SAMPLE);
        let coords: Vec<(&str, &str)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect();
        // perl (interpreter), ranges, no-version, recommends, conflicts skipped.
        assert_eq!(
            coords,
            vec![
                ("Plack", "1.0"),
                ("JSON::XS", "4.03"),
                ("Test::More", "0.96"),
            ]
        );
    }

    #[test]
    fn multiple_directives_on_one_line() {
        let line = "on 'x' => sub { requires 'A','1.0'; requires 'B','2.0'; };";
        let deps = parse_cpanfile(line);
        let coords: Vec<(&str, &str)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect();
        assert_eq!(coords, vec![("A", "1.0"), ("B", "2.0")]);
    }

    #[test]
    fn normalize_exact_version_rules() {
        assert_eq!(normalize_exact_version("1.23").as_deref(), Some("1.23"));
        assert_eq!(normalize_exact_version("2.00").as_deref(), Some("2.00"));
        assert_eq!(normalize_exact_version("v1.2.3").as_deref(), Some("v1.2.3"));
        assert_eq!(normalize_exact_version("== 1.02").as_deref(), Some("1.02"));
        assert_eq!(normalize_exact_version(">= 1.0"), None);
        assert_eq!(normalize_exact_version("< 2.0"), None);
        assert_eq!(normalize_exact_version(">= 2.2000, < 3.0"), None);
        assert_eq!(normalize_exact_version(""), None);
        assert_eq!(normalize_exact_version("  "), None);
    }

    #[test]
    fn strip_comment_keeps_quoted_hash() {
        assert_eq!(
            strip_comment("requires 'X', '1.0'; # note"),
            "requires 'X', '1.0'; "
        );
        assert_eq!(
            strip_comment("requires 'a#b', '1.0';"),
            "requires 'a#b', '1.0';"
        );
    }

    #[test]
    fn directive_family_and_lookalikes() {
        // The whole requires family is collected; lookalike identifiers and
        // the optional/anti directives are not.
        let body = "configure_requires 'ExtUtils::MakeMaker', '7.0';\n\
                    build_requires \"Module::Build\", \"0.42\";\n\
                    author_requires 'Perl::Critic', '1.14';\n\
                    myrequires 'Nope', '1.0';\n\
                    requiresque 'AlsoNope', '1.0';\n\
                    requires $module, '1.0';\n";
        let deps = parse_cpanfile(body);
        let coords: Vec<(&str, &str)> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect();
        assert_eq!(
            coords,
            vec![
                ("ExtUtils::MakeMaker", "7.0"),
                ("Module::Build", "0.42"),
                ("Perl::Critic", "1.14"),
            ]
        );
    }
}
