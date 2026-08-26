//! Perl / CPAN. Carton's `cpanfile.snapshot` (the lockfile) → inventory-only.
//!
//! CPAN has no OSV.dev native ingestion, so these coordinates are
//! inventory-only until a CPAN advisory feed (CPANSA / CPAN-Security's
//! OSV-format port, ecosystem id `CPAN`) is bundled for matching.
//!
//! The snapshot is the Carton lockfile (`carton install`). Its first line is
//! literally `# carton snapshot format: version 1.0`. It is a bespoke,
//! fixed-indent text format (YAML-ISH but NOT real YAML), so it is parsed by
//! hand with a small state machine mirroring `Carton::Snapshot::Parser`.
//!
//! Coordinate model: one coordinate per CPAN *distribution* (the `Name-Version`
//! block header under `DISTRIBUTIONS`, split on the LAST hyphen). The
//! distribution name + version is exactly the key the CPAN advisory databases
//! use (e.g. `Mojolicious`/`9.22`), NOT the module name.

use super::support::Emitter;

/// `cpanfile.snapshot`: one coordinate per distribution block. Duplicate
/// (name, version) blocks are fine; discovery dedups globally per
/// (coordinate, manifest).
pub(super) fn cpanfile_snapshot(contents: &str, out: &mut Emitter<'_>) {
    for dist in parse_snapshot(contents) {
        out.pkg(&dist.name, &dist.version, Some(dist.line));
    }
}

/// One CPAN distribution block parsed out of a snapshot.
#[derive(Debug, PartialEq, Eq)]
struct Distribution {
    /// Distribution name, e.g. `Mojolicious`, `libwww-perl`.
    name: String,
    /// Pinned version, e.g. `9.22`, `6.67`. Kept verbatim.
    version: String,
    /// 1-based source line of the block header (for "jump to source").
    line: usize,
}

/// A version-like token starts with an ASCII digit or a leading `v`
/// (`9.22`, `v2.0.1`, `1.1903`). Used to validate the last-hyphen split so we
/// don't mistake a hyphen inside a distribution name for the version separator.
fn looks_like_version(token: &str) -> bool {
    let mut chars = token.chars();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => true,
        Some('v') => matches!(chars.next(), Some(c) if c.is_ascii_digit()),
        _ => false,
    }
}

/// Split a `Name-Version` distribution header token on its LAST hyphen.
/// Distribution names legitimately contain hyphens (`libwww-perl-6.67` →
/// `libwww-perl`/`6.67`), so the last hyphen is the version boundary. If the
/// trailing token is not version-like, keep the whole token as the name with an
/// unknown version (in practice every real entry has a version).
fn split_dist_header(token: &str) -> (String, String) {
    if let Some(idx) = token.rfind('-') {
        let (name, version) = token.split_at(idx);
        let version = &version[1..]; // drop the '-'
        if !name.is_empty() && looks_like_version(version) {
            return (name.to_string(), version.to_string());
        }
    }
    (token.to_string(), String::new())
}

/// Hand-rolled state-machine parse of a Carton `cpanfile.snapshot`.
///
/// Indentation is significant and fixed-width (spaces, not tabs):
///   0 = section keyword (`DISTRIBUTIONS`)
///   2 = distribution header (`Name-Version`)
///   4 = keys (`pathname:` / `provides:` / `requirements:`)
///   6 = entries inside provides/requirements
///
/// We only need the 2-space distribution headers for the primary coordinate.
/// Zero-distribution / truncated snapshots parse to an empty Vec gracefully.
fn parse_snapshot(contents: &str) -> Vec<Distribution> {
    let mut dists = Vec::new();
    let mut in_distributions = false;

    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);

        // Trailers terminate the DISTRIBUTIONS data.
        if line == "__ENV__" || line == "__END__" {
            break;
        }
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start().len();

        if indent == 0 {
            // A zero-indent line is a section keyword; only DISTRIBUTIONS
            // matters. Any other zero-indent line closes the section.
            in_distributions = line.trim() == "DISTRIBUTIONS";
            continue;
        }

        if !in_distributions {
            continue;
        }

        // EXACTLY 2 leading spaces + a non-space token = a distribution header.
        if indent == 2 {
            let token = line.trim();
            if token.is_empty() || token.contains(char::is_whitespace) {
                continue;
            }
            let (name, version) = split_dist_header(token);
            dists.push(Distribution {
                name,
                version,
                line: idx + 1,
            });
        }
        // 4-/6-space lines (pathname/provides/requirements + their entries) are
        // not needed for the primary distribution coordinate, so we skip them.
    }

    dists
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "# carton snapshot format: version 1.0\n\
DISTRIBUTIONS\n\
\x20\x20Algorithm-Diff-1.1903\n\
\x20\x20\x20\x20pathname: T/TY/TYEMQ/Algorithm-Diff-1.1903.tar.gz\n\
\x20\x20\x20\x20provides:\n\
\x20\x20\x20\x20\x20\x20Algorithm::Diff 1.1903\n\
\x20\x20\x20\x20requirements:\n\
\x20\x20\x20\x20\x20\x20ExtUtils::MakeMaker 0\n\
\x20\x20Mojolicious-9.22\n\
\x20\x20\x20\x20pathname: S/SR/SRI/Mojolicious-9.22.tar.gz\n\
\x20\x20\x20\x20provides:\n\
\x20\x20\x20\x20\x20\x20Mojo::UserAgent 9.22\n\
\x20\x20libwww-perl-6.67\n\
\x20\x20\x20\x20pathname: O/OA/OALDERS/libwww-perl-6.67.tar.gz\n";

    #[test]
    fn parses_distributions_on_last_hyphen() {
        let dists = parse_snapshot(SAMPLE);
        let coords: Vec<(&str, &str)> = dists
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect();
        assert_eq!(
            coords,
            vec![
                ("Algorithm-Diff", "1.1903"),
                ("Mojolicious", "9.22"),
                // hyphenated distribution name must split on the LAST hyphen.
                ("libwww-perl", "6.67"),
            ]
        );
    }

    #[test]
    fn empty_snapshot_yields_no_coordinates() {
        let empty = "# carton snapshot format: version 1.0\nDISTRIBUTIONS\n";
        assert!(parse_snapshot(empty).is_empty());
    }

    #[test]
    fn version_like_validation() {
        assert!(looks_like_version("9.22"));
        assert!(looks_like_version("v2.0.1"));
        assert!(!looks_like_version("perl"));
        assert!(!looks_like_version(""));
        // not version-like trailing token → whole token kept as name.
        assert_eq!(
            split_dist_header("Some-Weird-name"),
            ("Some-Weird-name".to_string(), String::new())
        );
    }
}
