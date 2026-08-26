//! Debian/Ubuntu dpkg (`/var/lib/dpkg/status` -> OSV `Debian`).
//!
//! The status db is RFC822-style stanzas separated by blank lines. A
//! coordinate is emitted only when the `Status` current-state is `installed`,
//! keyed on the *source* package (from `Source`, falling back to the binary
//! `Package`); OSV Debian advisories are keyed on source names. Read-only:
//! never invokes `dpkg`/`dpkg-query`.
//!
//! OSV's Debian/Ubuntu ecosystems are release-qualified (`Debian:12`), so the
//! release is read from the sibling `/etc/os-release` and encoded into the
//! ecosystem id (`debian:12`). Without a readable os-release we fall back to
//! the bare `debian` id, which stays inventory-only (a release-less OSV
//! distro query matches nothing).

use super::support::{Emitter, LineFinder, path_ends_with, read_text};
use super::{ScanTarget, os_release, sysroot_before};
use std::path::Path;

const STATUS_SUFFIX: &str = "var/lib/dpkg/status";

pub struct DpkgTarget;

impl ScanTarget for DpkgTarget {
    fn ecosystem_id(&self) -> &'static str {
        "debian"
    }

    fn detects(&self, path: &Path) -> bool {
        // Matched component-wise so container/chroot roots trigger too, while
        // rotated `status-old`/`status.backup` duplicates never do.
        path_ends_with(path, &["var", "lib", "dpkg", "status"])
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        // Lossy decode: Maintainer/Description on old systems can carry
        // non-UTF8 bytes and must not hard-fail the file.
        let Some(contents) = read_text(path, out) else {
            return;
        };
        let ecosystem = release_qualified_ecosystem(path);
        let mut lines = LineFinder::new(&contents);
        for installed in parse_status(&contents) {
            out.pkg_in(
                &ecosystem,
                &installed.source_name,
                &installed.version,
                lines.find(&format!("Package: {}", installed.binary_name)),
            );
        }
    }
}

/// `debian:<VERSION_ID>` / `ubuntu:<VERSION_ID>` from the sibling
/// `etc/os-release`, else the bare `debian` family id.
fn release_qualified_ecosystem(path: &Path) -> String {
    if let Some(sysroot) = sysroot_before(path, STATUS_SUFFIX)
        && let Some((id, version_id)) = os_release(&sysroot)
        && (id == "debian" || id == "ubuntu")
        && !version_id.is_empty()
    {
        return format!("{id}:{version_id}");
    }
    "debian".to_string()
}

#[derive(Debug, PartialEq, Eq)]
struct InstalledPackage {
    binary_name: String,
    source_name: String,
    version: String,
}

/// Tolerates `\n` and `\r\n`, malformed/truncated stanzas (skipped, never
/// aborting the file), and folded continuation lines.
fn parse_status(contents: &str) -> Vec<InstalledPackage> {
    let mut out = Vec::new();
    let mut stanza: Vec<(String, String)> = Vec::new();

    let flush = |stanza: &mut Vec<(String, String)>, out: &mut Vec<InstalledPackage>| {
        if !stanza.is_empty() {
            if let Some(pkg) = stanza_to_package(stanza) {
                out.push(pkg);
            }
            stanza.clear();
        }
    };

    for raw in contents.lines() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);

        if line.trim().is_empty() {
            flush(&mut stanza, &mut out);
            continue;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            // Folded line: append to the current field's value so
            // "key: value"-looking text inside a Description is not mistaken
            // for a new field.
            if let Some(last) = stanza.last_mut() {
                last.1.push('\n');
                last.1.push_str(line.trim_start());
            }
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            // A valid field name is printable with no spaces (Debian policy).
            if !name.is_empty() && !name.contains(' ') {
                let value = value.strip_prefix(' ').unwrap_or(value);
                stanza.push((name.to_string(), value.to_string()));
                continue;
            }
        }
    }
    flush(&mut stanza, &mut out);

    out
}

fn stanza_to_package(stanza: &[(String, String)]) -> Option<InstalledPackage> {
    let field = |want: &str| -> Option<&str> {
        stanza
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(want))
            .map(|(_, value)| value.trim())
    };

    let binary_name = field("Package")?;
    if binary_name.is_empty() {
        return None;
    }

    // The Status current-state is the last token ("install ok installed");
    // config-files / half-installed / unpacked are present-but-not-installed.
    let status = field("Status")?;
    let state = status.split_whitespace().last()?;
    if state != "installed" {
        return None;
    }

    let version = field("Version")?;
    if version.is_empty() {
        return None;
    }

    // Source name: token before any whitespace/parenthesis
    // ("zlib (1:1.2.13-1)" -> "zlib"), falling back to the binary name.
    let source_name = match field("Source") {
        Some(src) if !src.is_empty() => src
            .split(|c: char| c.is_whitespace() || c == '(')
            .next()
            .unwrap_or(binary_name)
            .trim(),
        _ => binary_name,
    };
    let source_name = if source_name.is_empty() {
        binary_name
    } else {
        source_name
    };

    Some(InstalledPackage {
        binary_name: binary_name.to_string(),
        source_name: source_name.to_string(),
        version: version.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nMulti-Arch: same\nSource: openssl\nVersion: 3.0.11-1~deb12u2\nDepends: libc6 (>= 2.34)\nDescription: Secure Sockets Layer toolkit - shared libraries\n This package is part of the OpenSSL project's implementation of the SSL\n Version: not-a-real-field-inside-description\n\nPackage: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nSource: zlib (1:1.2.13.dfsg-1)\nVersion: 1:1.2.13.dfsg-1\nDescription: compression library - runtime\n\nPackage: nano\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 7.2-1\nDescription: small, friendly text editor\n";

    #[test]
    fn parses_installed_with_source_and_skips_config_files() {
        let pkgs = parse_status(SAMPLE);
        // nano is in config-files state -> excluded. Two installed remain.
        assert_eq!(pkgs.len(), 2);

        // Source field maps binary libssl3 -> source openssl.
        assert_eq!(
            pkgs[0],
            InstalledPackage {
                binary_name: "libssl3".to_string(),
                source_name: "openssl".to_string(),
                version: "3.0.11-1~deb12u2".to_string(),
            }
        );

        // "Source: zlib (1:1.2.13.dfsg-1)" -> source name "zlib", paren stripped.
        assert_eq!(pkgs[1].source_name, "zlib");
        // Epoch/colon preserved verbatim.
        assert_eq!(pkgs[1].version, "1:1.2.13.dfsg-1");
    }

    #[test]
    fn source_falls_back_to_binary_name() {
        let stanza = "Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2+b7\nArchitecture: amd64\n";
        let pkgs = parse_status(stanza);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].source_name, "bash");
        assert_eq!(pkgs[0].binary_name, "bash");
    }

    #[test]
    fn handles_crlf_and_eof_stanza() {
        let crlf = "Package: tar\r\nStatus: install ok installed\r\nVersion: 1.34+dfsg-1.2+deb12u1\r\nArchitecture: amd64";
        let pkgs = parse_status(crlf);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version, "1.34+dfsg-1.2+deb12u1");
    }
}
