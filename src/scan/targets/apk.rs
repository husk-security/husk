//! Alpine apk (`/lib/apk/db/installed` -> OSV `Alpine:v3.XX`).
//!
//! Even under apk-tools v3 (Alpine 3.23) the installed db stays in the v2
//! colon-prefixed text format: blank-line-separated records of `X:value`
//! lines. We only need `P:` (name) and `V:` (version; the `-rN` suffix is
//! load-bearing for OSV matching). The ecosystem is release-qualified as
//! `alpine:v<MAJOR.MINOR>` from `/etc/alpine-release` or `/etc/os-release`,
//! falling back to bare `alpine` (inventory-only).

use super::support::{Emitter, path_ends_with, read_text};
use super::{ScanTarget, os_release, sysroot_before};
use std::path::Path;

pub struct AlpineApkTarget;

impl ScanTarget for AlpineApkTarget {
    fn ecosystem_id(&self) -> &'static str {
        "alpine"
    }

    fn detects(&self, path: &Path) -> bool {
        path_matches_apk_db(path)
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        // Defensive: a binary apk v3 ADB database must not be mis-parsed as text.
        let Some(contents) = read_text(path, out) else {
            return;
        };
        if looks_binary(&contents) {
            return;
        }
        parse_installed(&contents, &release_qualified_ecosystem(path), out);
    }
}

/// Matches component-wise so both host (`/lib/apk/db/installed`) and container
/// image-layer roots (`usr/lib/apk/db/installed`) trigger, but a bare file
/// named `installed` elsewhere never does.
fn path_matches_apk_db(path: &Path) -> bool {
    path_ends_with(path, &["lib", "apk", "db", "installed"])
}

/// A NUL byte signals a binary blob (real apk v2 db is plain UTF-8 text).
fn looks_binary(contents: &str) -> bool {
    contents.as_bytes().contains(&0)
}

fn parse_installed(contents: &str, ecosystem: &str, out: &mut Emitter<'_>) {
    let mut cur_name: Option<String> = None;
    let mut cur_version: Option<String> = None;
    // 1-based line of the record's `P:`, for jump-to-source.
    let mut cur_line: Option<usize> = None;

    let flush = |name: &mut Option<String>,
                 version: &mut Option<String>,
                 line: &mut Option<usize>,
                 out: &mut Emitter<'_>| {
        if let (Some(n), Some(v)) = (name.take(), version.take())
            && !n.is_empty()
            && !v.is_empty()
        {
            out.pkg_in(ecosystem, &n, &v, *line);
        }
        *line = None;
    };

    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);

        if line.is_empty() {
            flush(&mut cur_name, &mut cur_version, &mut cur_line, out);
            continue;
        }

        // Split on the FIRST ':' only; values can themselves contain colons.
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };

        match key {
            "P" => {
                cur_name = Some(value.to_string());
                if cur_line.is_none() {
                    cur_line = Some(idx + 1);
                }
            }
            "V" => cur_version = Some(value.to_string()),
            _ => {}
        }
    }

    // Trailing record may not be terminated by a blank line.
    flush(&mut cur_name, &mut cur_version, &mut cur_line, out);
}

/// Release-qualified ecosystem id (`alpine:v3.19`) from the sibling
/// `etc/alpine-release` (preferred) or `etc/os-release`; bare `alpine`
/// (inventory-only) when neither is readable.
fn release_qualified_ecosystem(path: &Path) -> String {
    for suffix in ["usr/lib/apk/db/installed", "lib/apk/db/installed"] {
        if let Some(sysroot) = sysroot_before(path, suffix) {
            if let Some(branch) = alpine_branch(&sysroot) {
                return format!("alpine:{branch}");
            }
            break;
        }
    }
    "alpine".to_string()
}

/// Alpine release branch (`v3.19`) from `etc/alpine-release` or os-release
/// `VERSION_ID`; a `3.19.1` patch version collapses to the `v3.19` branch OSV
/// keys advisories on.
fn alpine_branch(sysroot: &Path) -> Option<String> {
    let version = std::fs::read_to_string(sysroot.join("etc/alpine-release"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| os_release(sysroot).map(|(_, version_id)| version_id))?;
    let mut parts = version.split('.');
    let major = parts.next().filter(|s| !s.is_empty())?;
    let minor = parts.next().filter(|s| !s.is_empty())?;
    Some(format!("v{major}.{minor}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;
    use std::path::PathBuf;

    fn parse(db: &str) -> Vec<PackageRef> {
        run_parser("alpine", db, |contents, out| {
            parse_installed(contents, "alpine", out)
        })
    }

    #[test]
    fn parses_two_records() {
        let db = "P:musl\nV:1.2.5-r0\nA:x86_64\no:musl\nF:lib\nR:libc.musl-x86_64.so.1\n\nP:busybox\nV:1.36.1-r29\nA:x86_64\np:cmd:busybox=1.36.1-r29\nF:bin\nR:busybox\n";
        let pkgs = parse(db);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "musl");
        // Version is verbatim, including the `-rN` release suffix.
        assert_eq!(pkgs[0].version, "1.2.5-r0");
        assert_eq!(pkgs[1].name, "busybox");
        assert_eq!(pkgs[1].version, "1.36.1-r29");
        assert!(pkgs.iter().all(|p| p.ecosystem == "alpine"));
    }

    #[test]
    fn flushes_trailing_record_without_blank_line() {
        let db = "P:zlib\nV:1.3.1-r1\nA:aarch64";
        let pkgs = parse(db);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version, "1.3.1-r1");
    }

    #[test]
    fn drops_incomplete_record_missing_version() {
        // Truncated db: a record with P: but no V: must not be emitted.
        let db = "P:openssl\nA:x86_64\n\nP:ca-certificates\nV:20240705-r0\n";
        let pkgs = parse(db);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "ca-certificates");
    }

    #[test]
    fn value_may_contain_colon() {
        let db = "P:so-test\nV:1.0.0-r0\np:so:libc.musl-x86_64.so.1=1\n";
        let pkgs = parse(db);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version, "1.0.0-r0");
    }

    #[test]
    fn detects_path_variants() {
        assert!(path_matches_apk_db(&PathBuf::from("/lib/apk/db/installed")));
        assert!(path_matches_apk_db(&PathBuf::from(
            "/some/image/usr/lib/apk/db/installed"
        )));
        assert!(path_matches_apk_db(&PathBuf::from("lib/apk/db/installed")));
        assert!(!path_matches_apk_db(&PathBuf::from("/var/lib/dpkg/status")));
        assert!(!path_matches_apk_db(&PathBuf::from("/home/me/installed")));
    }
}
