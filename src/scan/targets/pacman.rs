//! Arch Linux pacman (libalpm local DB `desc` files under
//! `/var/lib/pacman/local/<name>-<ver>/desc`). No OSV ecosystem; inventory
//! only (OSV.dev has no "Arch" ecosystem; security.archlinux.org keys by
//! CVE/ASA, not a queryable coordinate). Ecosystem id: `"arch"`.
//!
//! The libalpm *local* database is plain uncompressed text on disk (unlike the
//! gzip'd `sync/*.db` tarballs, which list available repo packages and are
//! deliberately ignored). Each installed package owns a directory whose `desc`
//! file holds fully-resolved, pinned `%NAME%`/`%VERSION%` fields. We read those
//! two authoritative fields rather than splitting the directory name, since
//! package names legitimately contain hyphens (`gcc-libs`) and the version is
//! itself `[epoch:]pkgver-pkgrel`.

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name};
use std::path::Path;

pub struct PacmanTarget;

impl ScanTarget for PacmanTarget {
    fn ecosystem_id(&self) -> &'static str {
        "arch"
    }

    /// A pacman local-DB `desc` file: named `desc`, whose grandparent directory
    /// is `local` and where a sibling `ALPM_DB_VERSION` file exists. Gating on
    /// `ALPM_DB_VERSION` (the single most reliable libalpm discriminator) avoids
    /// hijacking unrelated files literally named `desc` and avoids the sync-DB
    /// tarball contents (which would be under `sync/`, not `local/`). Cheap:
    /// only filename/parent inspection plus one stat for the sibling marker.
    fn detects(&self, path: &Path) -> bool {
        if !matches!(file_name(path), Some("desc")) {
            return false;
        }
        // <root>/<name>-<ver>/desc  ->  parent = <name>-<ver>, grandparent = <root>.
        let Some(pkg_dir) = path.parent() else {
            return false;
        };
        let Some(root) = pkg_dir.parent() else {
            return false;
        };
        // The DB root directory is conventionally named `local`.
        if !matches!(file_name(root), Some("local")) {
            return false;
        }
        // Definitive marker: the schema-version file sits in the DB root.
        root.join("ALPM_DB_VERSION").is_file()
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        if let Some((name, version, line)) = parse_desc(&contents) {
            out.pkg(&name, &version, line);
        }
    }
}

/// Extract `(name, version, 1-based line of %NAME%)` from a libalpm local `desc`.
///
/// A `desc` is a sequence of stanzas: a header line that is exactly `%FIELD%`,
/// followed by one or more value lines, terminated by a blank line. We match on
/// the `%NAME%` / `%VERSION%` headers (not on field order) and take the next
/// line as the value, trimming trailing `\r` and surrounding whitespace.
/// Returns `None` if either field is missing or empty (corrupt/partial install),
/// so the caller can skip that package without aborting the whole inventory.
fn parse_desc(contents: &str) -> Option<(String, String, Option<usize>)> {
    let lines: Vec<&str> = contents.lines().collect();
    let mut name: Option<(String, usize)> = None;
    let mut version: Option<String> = None;

    for (idx, raw) in lines.iter().enumerate() {
        match raw.trim() {
            "%NAME%" => {
                if let Some(value) = lines.get(idx + 1).map(|v| v.trim())
                    && !value.is_empty()
                {
                    // 1-based line of the value (idx is 0-based for the
                    // `%NAME%` header; the value sits on the next line).
                    name = Some((value.to_string(), idx + 2));
                }
            }
            "%VERSION%" => {
                if let Some(value) = lines.get(idx + 1).map(|v| v.trim())
                    && !value.is_empty()
                {
                    version = Some(value.to_string());
                }
            }
            _ => {}
        }
        // NAME then VERSION appear first in every desc; stop once both seen.
        if name.is_some() && version.is_some() {
            break;
        }
    }

    let (name, line) = name?;
    let version = version?;
    Some((name, version, Some(line)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_and_version() {
        let desc = "%NAME%\nglibc\n\n%VERSION%\n2.41+r6+g0e16d6cd57-3\n\n%ARCH%\nx86_64\n";
        let (name, version, line) = parse_desc(desc).expect("parsed");
        assert_eq!(name, "glibc");
        // Versions can contain '+', '.', letters and ':'; do not over-sanitize.
        assert_eq!(version, "2.41+r6+g0e16d6cd57-3");
        assert_eq!(line, Some(2));
    }

    #[test]
    fn keeps_epoch_and_pkgrel() {
        let desc = "%NAME%\npython-requests\n\n%VERSION%\n1:2.32.3-2\n";
        let (name, version, _) = parse_desc(desc).expect("parsed");
        assert_eq!(name, "python-requests");
        assert_eq!(version, "1:2.32.3-2");
    }

    #[test]
    fn skips_missing_version() {
        let desc = "%NAME%\nbroken\n\n%DESC%\ninterrupted install\n";
        assert!(parse_desc(desc).is_none());
    }

    #[test]
    fn trims_crlf() {
        let desc = "%NAME%\r\nfilesystem\r\n\r\n%VERSION%\r\n2024.04.07-1\r\n";
        let (name, version, _) = parse_desc(desc).expect("parsed");
        assert_eq!(name, "filesystem");
        assert_eq!(version, "2024.04.07-1");
    }
}
