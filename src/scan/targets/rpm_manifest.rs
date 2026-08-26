//! RPM package manifest (`rpm-manifest.txt` / `packages.txt` -> OSV `Red Hat`).
//!
//! RPM-based distributions (Fedora, RHEL/CentOS/Rocky/Alma, openSUSE/SUSE) all
//! describe an installed package as a NEVRA string:
//! `NAME-[EPOCH:]VERSION-RELEASE.ARCH` (e.g. `openssl-3.0.7-18.el9_2.x86_64`).
//! A conventional export is `rpm -qa` or
//! `rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'`, typically saved as
//! `rpm-manifest.txt` (unambiguous) or the more generic `packages.txt`.
//!
//! The OSV ecosystem string for these advisories is `Red Hat`; advisory keys use
//! RPM EVR ordering `EPOCH:VERSION-RELEASE` (e.g. `0:3.12.1-4.el9_4.6`), and the
//! purl form is `pkg:rpm/redhat/<name>`. Coordinates are emitted as
//! `(name, "EPOCH:VERSION-RELEASE")`, already in the advisory-key shape; any
//! local matcher must implement rpmvercmp (NOT semver).
//!
//! NEVRA parsing anchors from the RIGHT (matching rpm hawkey `hy_split_nevra`)
//! because RPM names legitimately contain `-` (e.g. `perl-File-Path`,
//! `kernel-headers`): the last `-` delimits RELEASE, the second-to-last `-`
//! delimits VERSION, and the trailing `.<arch>` is stripped only when the suffix
//! is a recognized architecture token.

use super::support::Emitter;

/// `rpm-manifest.txt`: the name is unambiguous, so the file is trusted as an
/// `rpm -qa` export by name alone.
pub(super) fn rpm_manifest_txt(contents: &str, out: &mut Emitter<'_>) {
    parse_manifest(contents, false, out);
}

/// `packages.txt`: a generic name; the parser validates each line as NEVRA
/// and emits nothing unless the file is predominantly a real RPM manifest.
pub(super) fn rpm_packages_txt(contents: &str, out: &mut Emitter<'_>) {
    parse_manifest(contents, true, out);
}

/// Recognized RPM architecture tokens. A trailing `.<token>` is only treated as
/// an arch (and stripped) when `token` is one of these; otherwise the dot is
/// part of VERSION/RELEASE (e.g. `glibc-2.34-60.el9_2.7` has no arch suffix).
const ARCHES: &[&str] = &[
    "x86_64", "i386", "i486", "i586", "i686", "aarch64", "armv7hl", "ppc64", "ppc64le", "s390x",
    "noarch", "src", "riscv64",
];

struct Nevra {
    name: String,
    /// Advisory-key form: `EPOCH:VERSION-RELEASE` (epoch always explicit).
    evr: String,
    /// Distro family inferred from the RELEASE dist tag, used as the coordinate
    /// ecosystem id so `osv_ecosystem` can route to the right OSV ecosystem.
    ecosystem: &'static str,
}

/// Infer the distro family from an RPM RELEASE string's dist tag. RHEL-family
/// (`.el9`) -> OSV `Red Hat`; SUSE/openSUSE -> OSV `openSUSE`; Fedora (`.fc39`)
/// has no OSV ecosystem (Bodhi only) so stays inventory; anything unrecognized
/// stays the bare `rpm` id (inventory). Shared with the binary-rpmdb reader.
///
/// The `.el`/`.fc` dist tags are anchored on a following ASCII digit
/// (`.el9`, `.fc38`) so an unrelated substring like `.electron` or `.fcgi` in
/// a release string never misclassifies the family.
pub(crate) fn rpm_family(release: &str) -> &'static str {
    let r = release.to_ascii_lowercase();
    if has_digit_tag(&r, ".el") {
        "redhat"
    } else if has_digit_tag(&r, ".fc") {
        "fedora"
    } else if r.contains(".suse")
        || r.contains(".sle")
        || r.contains("lp15")
        || r.contains("lp16")
        || r.contains("bp15")
        || r.contains("slfo")
    {
        "suse"
    } else {
        "rpm"
    }
}

/// True when `tag` occurs in `r` immediately followed by an ASCII digit.
fn has_digit_tag(r: &str, tag: &str) -> bool {
    r.match_indices(tag).any(|(idx, _)| {
        r.as_bytes()
            .get(idx + tag.len())
            .is_some_and(u8::is_ascii_digit)
    })
}

/// Parse one whitespace-trimmed NEVRA token. Returns `None` when the token is
/// not a bare NEVRA (too few `-`, gpg-pubkey, etc.).
fn parse_nevra(token: &str) -> Option<Nevra> {
    let core = match token.rsplit_once('.') {
        Some((head, suffix)) if ARCHES.contains(&suffix) => head,
        _ => token,
    };

    // Anchor from the right: NAME-VERSION-RELEASE.
    let (head, release) = core.rsplit_once('-')?;
    let (name, version_head) = head.rsplit_once('-')?;
    if name.is_empty() || version_head.is_empty() || release.is_empty() {
        return None;
    }

    // gpg-pubkey entries are GPG keys, not software; never inventory them.
    if name == "gpg-pubkey" {
        return None;
    }

    // EPOCH: "[epoch:]version". Split the version head on the first ':'; the left
    // side is the epoch (digits) when present, else epoch is implicitly 0.
    let (epoch, version) = match version_head.split_once(':') {
        Some((e, v)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) && !v.is_empty() => {
            (e, v)
        }
        // A ':' that is not a clean digit-epoch prefix: keep the head verbatim.
        _ => ("0", version_head),
    };

    Some(Nevra {
        name: name.to_string(),
        evr: format!("{epoch}:{version}-{release}"),
        ecosystem: rpm_family(release),
    })
}

/// Pure parser for the NEVRA manifest text. When `ambiguous_name` is true (the
/// generic `packages.txt`), the file must be predominantly valid NEVRA before
/// anything is emitted, so pip/conda lists are not mislabeled as RPMs.
fn parse_manifest(contents: &str, ambiguous_name: bool, out: &mut Emitter<'_>) {
    let mut candidates: Vec<(Nevra, usize)> = Vec::new();
    // Count of non-empty, non-comment lines attempted.
    let mut considered = 0usize;

    for (idx, raw) in contents.lines().enumerate() {
        // `lines()` strips '\n'; trim a lone '\r' (CRLF dumps) and whitespace.
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Internal whitespace => not a bare NEVRA (rpm -qa -i / --last / dnf
        // columnar / sosreport). Skip but still count it as a considered line so
        // a non-manifest packages.txt drags the validity ratio down.
        if line.contains(char::is_whitespace) {
            considered += 1;
            continue;
        }

        considered += 1;
        if let Some(nevra) = parse_nevra(line) {
            candidates.push((nevra, idx + 1));
        }
    }

    // For the ambiguous generic name, bail on the whole file unless most lines
    // validated as NEVRA. `rpm-manifest.txt` is trusted by name.
    if ambiguous_name && (considered == 0 || candidates.len() * 2 < considered) {
        return;
    }

    for (n, line) in candidates {
        out.pkg_in(n.ecosystem, &n.name, &n.evr, Some(line));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str, ambiguous_name: bool) -> Vec<PackageRef> {
        run_parser("rpm", contents, |c, out| {
            parse_manifest(c, ambiguous_name, out)
        })
    }

    #[test]
    fn parses_nevra_with_arch_and_implicit_epoch() {
        let n = parse_nevra("openssl-3.0.7-18.el9_2.x86_64").expect("nevra");
        assert_eq!(n.name, "openssl");
        assert_eq!(n.evr, "0:3.0.7-18.el9_2");
    }

    #[test]
    fn parses_explicit_epoch() {
        let n = parse_nevra("bind-32:9.10.2-2.P1.fc22.x86_64").expect("nevra");
        assert_eq!(n.name, "bind");
        assert_eq!(n.evr, "32:9.10.2-2.P1.fc22");
    }

    #[test]
    fn name_with_hyphens_anchors_from_right() {
        let n = parse_nevra("perl-File-Path-2.18-450.fc38.noarch").expect("nevra");
        assert_eq!(n.name, "perl-File-Path");
        assert_eq!(n.evr, "0:2.18-450.fc38");
    }

    #[test]
    fn arch_false_match_keeps_release_dot() {
        // ".7" is not an arch; the suffix stays part of RELEASE.
        let n = parse_nevra("glibc-2.34-60.el9_2.7.x86_64").expect("nevra");
        assert_eq!(n.name, "glibc");
        assert_eq!(n.evr, "0:2.34-60.el9_2.7");
    }

    #[test]
    fn gpg_pubkey_is_skipped() {
        assert!(parse_nevra("gpg-pubkey-fd431d51-4ae0493b").is_none());
    }

    #[test]
    fn too_few_hyphens_is_rejected() {
        assert!(parse_nevra("justaname").is_none());
        assert!(parse_nevra("name-1.0").is_none());
    }

    #[test]
    fn manifest_skips_comments_blanks_and_columnar() {
        let raw = r#"# rpm -qa export
openssl-3.0.7-18.el9_2.x86_64

perl-File-Path-2.18-450.fc38.noarch
kernel-headers 5.14.0-284.11.1.el9_2 baseos
gpg-pubkey-fd431d51-4ae0493b
"#;
        let pkgs = parse(raw, false);
        assert_eq!(pkgs.len(), 2);
        let openssl = pkgs.iter().find(|p| p.name == "openssl").expect("openssl");
        assert_eq!(openssl.version, "0:3.0.7-18.el9_2");
        // Family inferred from the dist tag: `.el9` -> redhat, `.fc38` -> fedora.
        assert_eq!(openssl.ecosystem, "redhat");
        let perl = pkgs
            .iter()
            .find(|p| p.name == "perl-File-Path")
            .expect("perl");
        assert_eq!(perl.ecosystem, "fedora");
        // No gpg-pubkey, no columnar (internal-whitespace) line emitted.
        assert!(pkgs.iter().all(|p| p.name != "gpg-pubkey"));
    }

    #[test]
    fn ambiguous_packages_txt_bails_on_non_nevra() {
        // A pip-freeze style list under the generic name must emit nothing.
        let raw = r#"requests==2.31.0
flask==3.0.0
numpy==1.26.0
"#;
        let pkgs = parse(raw, true);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn ambiguous_packages_txt_accepts_real_nevra() {
        let raw = r#"openssl-3.0.7-18.el9_2.x86_64
python3-3.11.2-2.el9.x86_64
"#;
        let pkgs = parse(raw, true);
        assert_eq!(pkgs.len(), 2);
    }
}
