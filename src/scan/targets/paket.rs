//! Paket (.NET `paket.lock`) -> OSV `NuGet`.
//!
//! [Paket](https://fsprojects.github.io/Paket/) is an alternative dependency
//! manager over NuGet; `paket.lock` records the exactly-pinned versions of
//! every direct and transitive dependency across all groups. Resolved packages
//! are plain NuGet packages, so they reuse the canonical `"nuget"` id.
//!
//! The format is a bespoke, indentation-significant text file: two spaces per
//! nesting level, top-level repository-type headers (`NUGET`, `GITHUB`, `GIT`,
//! `HTTP`, `GIST`), `GROUP` headers, and `remote:` markers. The single-pass
//! scanner mirrors the reference implementations (Paket / snyk-paket-parser).
//! Only `NUGET`-section, indentation-level-2 lines are resolved pins: deeper
//! lines are transitive *constraints* (ranges like `(>= 4.3)`), and
//! `GITHUB`/`GIT`/`HTTP`/`GIST` entries are source/commit pins with no OSV
//! NuGet coverage; both skipped.

use super::support::Emitter;
use std::collections::HashSet;

/// `paket.lock`: emit every resolved NUGET pin across all groups.
pub(super) fn paket_lock(contents: &str, out: &mut Emitter<'_>) {
    for entry in parse_paket_lock(contents) {
        out.pkg(&entry.name, &entry.version, Some(entry.line));
    }
}

/// One resolved NuGet coordinate extracted from a `paket.lock`.
struct PaketEntry {
    name: String,
    version: String,
    /// 1-based source line, for "jump to source" UX.
    line: usize,
}

/// The fixed set of repository-type section headers Paket emits at indent 0.
const REPOSITORY_TYPES: [&str; 5] = ["NUGET", "GITHUB", "GIT", "HTTP", "GIST"];

/// Pure, dependency-free `paket.lock` parser. Single pass over lines, driven by
/// 2-space indentation levels. Collects every indentation-level-2 entry under
/// every `NUGET` section across every group, de-duplicated on
/// (lowercased-name, version): NuGet ids are case-insensitive, so this dedup
/// is intra-file semantics (a global case-sensitive dedup would not collapse
/// `Foo`/`foo`), not just duplicate suppression.
fn parse_paket_lock(contents: &str) -> Vec<PaketEntry> {
    // Strip a leading UTF-8 BOM (Windows-written files) so the first
    // indentation count is correct. CRLF is handled by `.lines()`. (`read_text`
    // strips the BOM for files; this keeps the parser safe on raw strings.)
    let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);

    let mut entries: Vec<PaketEntry> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut in_nuget_section = false;

    for (idx, raw) in contents.lines().enumerate() {
        // Indentation = leading spaces / 2 (floor; lenient on stray spacing).
        let leading = raw.len() - raw.trim_start_matches(' ').len();
        let indent = leading / 2;
        let content = raw.trim();
        if content.is_empty() {
            continue;
        }

        match indent {
            0 => {
                let upper = content.to_ascii_uppercase();
                if upper == "GROUP" || upper.starts_with("GROUP ") {
                    in_nuget_section = false;
                } else if REPOSITORY_TYPES.contains(&upper.as_str()) {
                    // Only NUGET yields OSV-mappable coordinates.
                    in_nuget_section = upper == "NUGET";
                }
                // Otherwise a group-option line (RESTRICTION:/STORAGE:/...).
            }
            1 => {
                // `remote:` / `specs:` markers, not coordinates; ignore.
            }
            2 => {
                if let Some((name, version)) = in_nuget_section
                    .then(|| parse_nuget_entry(content))
                    .flatten()
                    && seen.insert((name.to_ascii_lowercase(), version.clone()))
                {
                    entries.push(PaketEntry {
                        name,
                        version,
                        line: idx + 1,
                    });
                }
            }
            // indent >= 3: transitive constraint lines (ranges); skip.
            _ => {}
        }
    }

    entries
}

/// Extract `(name, version)` from a NUGET indentation-2 line, mirroring the
/// canonical Paket regex `^([^ ]+)\W+\(([^)]+)\)\W*(.*)$`: a space-free package
/// id, then the exact pinned version inside parentheses, then ignored trailing
/// options.
///
/// Examples:
///   `FSharp.Compiler.Service (43.9.101)` -> (`FSharp.Compiler.Service`, `43.9.101`)
///   `Microsoft.CSharp (4.7) - redirects: force` -> (`Microsoft.CSharp`, `4.7`)
///
/// Returns `None` for lines with no parenthesized version (e.g. a stray
/// constraint line that slipped to indent 2); tolerate and skip.
fn parse_nuget_entry(content: &str) -> Option<(String, String)> {
    let name = content.split_whitespace().next()?;
    if name.is_empty() {
        return None;
    }
    let open = content.find('(')?;
    let close = content[open + 1..].find(')')? + open + 1;
    let version = content.get(open + 1..close)?.trim();
    if version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "STORAGE: NONE\n\
CONTENT: NONE\n\
RESTRICTION: >= netstandard2.0\n\
NUGET\n  \
remote: https://api.nuget.org/v3/index.json\n    \
FSharp.Core (9.0.101)\n    \
Newtonsoft.Json (13.0.3) - restriction: >= netstandard2.0\n    \
Serilog (3.1.1)\n      \
System.Diagnostics.DiagnosticSource (>= 8.0)\n    \
Microsoft.CSharp (4.7) - redirects: force, restriction: >= net45\n\
\n\
GROUP Test\n\
NUGET\n  \
remote: https://api.nuget.org/v3/index.json\n    \
xunit (2.6.6)\n      \
xunit.assert (>= 2.6.6)\n    \
Moq (4.20.70)\n      \
Castle.Core (>= 5.1.1)\n\
\n\
GROUP Build\n\
GITHUB\n  \
remote: forki/FsUnit\n    \
FsUnit.fs (7623fc13439f0e60bd05c1ed3b5f6dcb937fe468)\n";

    #[test]
    fn parses_resolved_nuget_pins_across_groups() {
        let entries = parse_paket_lock(SAMPLE);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        // Resolved indent-2 NUGET pins from both Main and Test groups.
        assert!(names.contains(&"FSharp.Core"));
        assert!(names.contains(&"Newtonsoft.Json"));
        assert!(names.contains(&"Serilog"));
        assert!(names.contains(&"Microsoft.CSharp"));
        assert!(names.contains(&"xunit"));
        assert!(names.contains(&"Moq"));
        // Transitive constraint lines (indent >= 3) are NOT coordinates.
        assert!(!names.contains(&"System.Diagnostics.DiagnosticSource"));
        assert!(!names.contains(&"xunit.assert"));
        assert!(!names.contains(&"Castle.Core"));
        // GITHUB source/commit pins are not NuGet coordinates.
        assert!(!names.contains(&"FsUnit.fs"));
    }

    #[test]
    fn extracts_exact_pinned_versions() {
        let entries = parse_paket_lock(SAMPLE);
        let fsharp = entries
            .iter()
            .find(|e| e.name == "FSharp.Core")
            .expect("FSharp.Core present");
        assert_eq!(fsharp.version, "9.0.101");
        let csharp = entries
            .iter()
            .find(|e| e.name == "Microsoft.CSharp")
            .expect("Microsoft.CSharp present");
        // Trailing ` - redirects: ...` options are ignored.
        assert_eq!(csharp.version, "4.7");
    }

    #[test]
    fn strips_bom_and_dedupes() {
        // BOM-prefixed, same package twice (e.g. once per group/remote).
        let input = "\u{feff}NUGET\n  remote: a\n    Foo (1.0.0)\n\
GROUP Test\nNUGET\n  remote: b\n    Foo (1.0.0)\n";
        let entries = parse_paket_lock(input);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Foo");
        assert_eq!(entries[0].version, "1.0.0");
    }

    #[test]
    fn line_for_nuget_entry() {
        let entry = parse_nuget_entry("Newtonsoft.Json (13.0.3) - restriction: x");
        assert_eq!(
            entry,
            Some(("Newtonsoft.Json".to_string(), "13.0.3".to_string()))
        );
        // No parenthesized version -> not a coordinate.
        assert_eq!(parse_nuget_entry("Microsoft.Net.Http"), None);
    }
}
