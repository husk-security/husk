//! Version-comparison strategies, one per naming scheme.
//!
//! The crate deliberately does *not* have a single universal comparator:
//! ecosystems disagree about what a version even is. What it has instead is
//! one algorithm per contract, named for what it is, so a call site can never
//! silently pick the wrong semantics:
//!
//! - [`naive_vercmp`]: generic numeric-segment compare for registry versions
//!   (npm/pypi/cargo/go advisory targets). Not a full semver/PEP 440 parser.
//! - [`pacman_vercmp`]: faithful pacman/libalpm `vercmp` for Arch packages
//!   (`[epoch:]version[-pkgrel]`, digit-outranks-alpha, rpmvercmp segments).
//!
//! OSV-covered ecosystems don't need a local comparator at all: OSV does the
//! version-range matching server-side.

use std::cmp::Ordering;

/// Compare two version strings by numeric segments (non-numeric segments fall
/// back to lexical compare). Not a full semver/PEP 440 parser; it only decides
/// the Upgrade/Downgrade label and which of two advisory targets is higher.
pub fn naive_vercmp(a: &str, b: &str) -> Ordering {
    let segs = |s: &str| -> Vec<String> {
        // Go keeps versions as `v0.35.0` while advisories say `0.36.0`; without
        // stripping the prefix, `"0"` vs `"v0"` compares lexically and every
        // fixed version looks like a downgrade.
        let s = match s.strip_prefix(['v', 'V']) {
            Some(rest) if rest.starts_with(|c: char| c.is_ascii_digit()) => rest,
            _ => s,
        };
        s.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    let (a, b) = (segs(a), segs(b));
    for (x, y) in a.iter().zip(b.iter()) {
        let ord = numeric_segment_cmp(x, y);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    // Tie-break when one version is a prefix of the other. A numeric extra
    // segment extends the release (`1.2.3` > `1.2`), but a non-numeric one is
    // a prerelease tag: `8.0.0-rc.6` is LOWER than `8.0.0`, per semver/PEP
    // 440, so a stable fix is never mislabeled a downgrade from its rc.
    // Numeric-ness is a digit-run check, NOT a fixed-width parse: a >u64
    // segment must still count as a release extension, not a prerelease tag.
    match a.len().cmp(&b.len()) {
        Ordering::Equal => Ordering::Equal,
        Ordering::Greater if !is_numeric_segment(&a[b.len()]) => Ordering::Less,
        Ordering::Less if !is_numeric_segment(&b[a.len()]) => Ordering::Greater,
        longer_wins => longer_wins,
    }
}

/// True when the segment is one or more ASCII digits. Deliberately not a
/// fixed-width `parse::<u64>`; that also errors on *overflow*, which would
/// misclassify an oversized-but-numeric segment as non-numeric.
fn is_numeric_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// Compare two segments as unsigned decimal integers without parsing to a
/// fixed-width type: trim leading zeros, then compare by digit-run length and
/// finally by byte value. This orders arbitrarily large numeric segments
/// correctly (a `u64::parse` fallback to lexical compare would misorder an
/// overflowing segment against a shorter one, e.g. treat a 21-digit number as
/// "less than" a 3-digit one). Falls back to plain lexical compare when either
/// segment isn't all-ASCII-digits (mirrors the pre-existing non-numeric path).
fn numeric_segment_cmp(x: &str, y: &str) -> Ordering {
    if is_numeric_segment(x) && is_numeric_segment(y) {
        let xt = x.trim_start_matches('0');
        let yt = y.trim_start_matches('0');
        xt.len().cmp(&yt.len()).then_with(|| xt.cmp(yt))
    } else {
        x.cmp(y)
    }
}

/// Pick the safe version to move to from an advisory's fixed-version
/// candidates: the *smallest* fix above the current version (the nearest
/// upgrade, never jumping a major stream when the current one is fixed), else
/// the *highest* fix below it.
///
/// That second case is the one no other scanner models: when the compromised
/// release is the newer one, the fix is a downgrade.
pub fn pick_fix_version<'a>(
    current: &str,
    candidates: impl Iterator<Item = &'a str>,
) -> Option<String> {
    let (mut upgrade, mut downgrade): (Option<&str>, Option<&str>) = (None, None);
    for candidate in candidates {
        match naive_vercmp(candidate, current) {
            Ordering::Greater => {
                if upgrade.is_none_or(|best| naive_vercmp(candidate, best) == Ordering::Less) {
                    upgrade = Some(candidate);
                }
            }
            Ordering::Less => {
                if downgrade.is_none_or(|best| naive_vercmp(candidate, best) == Ordering::Greater) {
                    downgrade = Some(candidate);
                }
            }
            Ordering::Equal => {}
        }
    }
    upgrade.or(downgrade).map(str::to_string)
}

/// pacman/libalpm `vercmp`: compare two versions of the form
/// `[epoch:]version[-pkgrel]`. Returns the ordering of `a` relative to `b`.
///
/// This is NOT interchangeable with [`naive_vercmp`]: it honors epochs
/// (`1:1.0` > `2.0`), compares an optional trailing pkgrel, and follows the
/// rpmvercmp rule that a numeric segment outranks an alphabetic one.
pub fn pacman_vercmp(a: &str, b: &str) -> Ordering {
    // Epoch defaults to "0" (not parsed to a fixed-width int) so an
    // oversized epoch compares correctly instead of silently collapsing to 0.
    let split_epoch = |s: &str| -> (String, String) {
        match s.split_once(':') {
            Some((e, rest)) if !e.is_empty() && e.bytes().all(|c| c.is_ascii_digit()) => {
                (e.to_string(), rest.to_string())
            }
            _ => ("0".to_string(), s.to_string()),
        }
    };
    let (ea, ra) = split_epoch(a);
    let (eb, rb) = split_epoch(b);
    match numeric_segment_cmp(&ea, &eb) {
        Ordering::Equal => {}
        other => return other,
    }

    let split_rel = |s: &str| -> (String, Option<String>) {
        match s.rsplit_once('-') {
            Some((v, r)) => (v.to_string(), Some(r.to_string())),
            None => (s.to_string(), None),
        }
    };
    let (va, rela) = split_rel(&ra);
    let (vb, relb) = split_rel(&rb);

    match rpm_segment_cmp(&va, &vb) {
        Ordering::Equal => {}
        other => return other,
    }
    match (rela, relb) {
        (Some(x), Some(y)) => rpm_segment_cmp(&x, &y),
        _ => Ordering::Equal,
    }
}

/// The rpmvercmp segment algorithm shared by pacman: compare block-by-block.
/// Numeric blocks compare numerically (and outrank alphabetic blocks);
/// alphabetic blocks compare lexically; non-alphanumerics are separators.
fn rpm_segment_cmp(a: &str, b: &str) -> Ordering {
    let mut a = a.as_bytes();
    let mut b = b.as_bytes();

    loop {
        while !a.is_empty() && !a[0].is_ascii_alphanumeric() {
            a = &a[1..];
        }
        while !b.is_empty() && !b[0].is_ascii_alphanumeric() {
            b = &b[1..];
        }
        if a.is_empty() || b.is_empty() {
            break;
        }

        let a_digit = a[0].is_ascii_digit();
        let b_digit = b[0].is_ascii_digit();

        let take = |s: &[u8], digit: bool| -> usize {
            s.iter()
                .take_while(|c| c.is_ascii_alphanumeric() && c.is_ascii_digit() == digit)
                .count()
        };

        let (seg_a, seg_b);
        if a_digit && b_digit {
            let na = take(a, true);
            let nb = take(b, true);
            let sa = trim_zeros(&a[..na]);
            let sb = trim_zeros(&b[..nb]);
            match sa.len().cmp(&sb.len()).then_with(|| sa.cmp(sb)) {
                Ordering::Equal => {}
                other => return other,
            }
            seg_a = na;
            seg_b = nb;
        } else if !a_digit && !b_digit {
            let na = take(a, false);
            let nb = take(b, false);
            match a[..na].cmp(&b[..nb]) {
                Ordering::Equal => {}
                other => return other,
            }
            seg_a = na;
            seg_b = nb;
        } else {
            return if a_digit {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        a = &a[seg_a..];
        b = &b[seg_b..];
    }

    match (a.is_empty(), b.is_empty()) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => Ordering::Equal,
    }
}

/// Strip leading ASCII `0`s from a numeric segment (keeping one digit for zero).
fn trim_zeros(seg: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < seg.len() && seg[i] == b'0' {
        i += 1;
    }
    &seg[i..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::{Equal, Greater, Less};

    #[test]
    fn pick_fix_version_prefers_the_stable_fix_over_its_prerelease() {
        assert_eq!(
            pick_fix_version("8.0.0-rc.6", ["8.0.0"].into_iter()).as_deref(),
            Some("8.0.0")
        );
    }

    #[test]
    fn pick_fix_version_handles_go_v_prefix() {
        assert_eq!(
            pick_fix_version("v0.35.0", ["0.36.0", "0.55.0"].into_iter()).as_deref(),
            Some("0.36.0")
        );
    }

    #[test]
    fn pick_fix_version_prefers_nearest_upgrade_then_nearest_downgrade() {
        // Nearest upgrade wins over a bigger jump, or another major's fix.
        assert_eq!(
            pick_fix_version("7.20.12", ["7.26.10", "8.0.0-rc.6"].into_iter()).as_deref(),
            Some("7.26.10")
        );
        // Only fixes below the current version: the compromised-newer-release
        // case, where the nearest downgrade wins.
        assert_eq!(
            pick_fix_version("1.131.51", ["1.131.49", "1.131.50"].into_iter()).as_deref(),
            Some("1.131.50")
        );
        // Equal-to-current candidates are ignored; nothing else means no fix.
        assert_eq!(pick_fix_version("1.0.0", ["1.0.0"].into_iter()), None);
        assert_eq!(pick_fix_version("1.0.0", [].into_iter()), None);
    }

    #[test]
    fn naive_vercmp_orders_numeric_segments() {
        assert_eq!(naive_vercmp("1.2.3", "1.10.0"), Less);
        assert_eq!(naive_vercmp("2.0.0", "1.99.99"), Greater);
        assert_eq!(naive_vercmp("1.2.3", "1.2.3"), Equal);
        assert_eq!(naive_vercmp("1.2.3", "1.2"), Greater); // longer wins on tie
        assert_eq!(naive_vercmp("1.131.50", "1.131.51"), Less);
        // Go module versions carry a `v` prefix; advisories don't.
        assert_eq!(naive_vercmp("0.36.0", "v0.35.0"), Greater);
        assert_eq!(naive_vercmp("v0.35.0", "0.35.0"), Equal);
        assert_eq!(naive_vercmp("victory", "v1.0.0"), Greater); // bare-word not stripped
    }

    #[test]
    fn naive_vercmp_orders_prereleases_below_their_release() {
        // Prereleases sort below their release even though they segment longer.
        assert_eq!(naive_vercmp("8.0.0-rc.6", "8.0.0"), Less);
        assert_eq!(naive_vercmp("8.0.0", "8.0.0-rc.6"), Greater);
        assert_eq!(naive_vercmp("1.0.0-beta.1", "1.0.0"), Less);
        // Prerelease-vs-prerelease still compares segment-wise.
        assert_eq!(naive_vercmp("8.0.0-rc.6", "8.0.0-rc.7"), Less);
        // A numeric extension is a higher release, not a prerelease.
        assert_eq!(naive_vercmp("1.2.0", "1.2"), Greater);
    }

    #[test]
    fn pacman_vercmp_basic_ordering() {
        assert_eq!(pacman_vercmp("1.0.1", "1.0.2"), Less);
        assert_eq!(pacman_vercmp("1.0.2", "1.0.1"), Greater);
        assert_eq!(pacman_vercmp("1.0.0", "1.0.0"), Equal);
        assert_eq!(pacman_vercmp("1.0-1", "1.0-2"), Less);
        assert_eq!(pacman_vercmp("1.10", "1.9"), Greater);
        assert_eq!(pacman_vercmp("1.0a", "1.0"), Greater);
    }

    #[test]
    fn pacman_vercmp_respects_epoch() {
        assert_eq!(pacman_vercmp("1:1.0", "2.0"), Greater);
        assert_eq!(pacman_vercmp("1:1.0", "2:0.1"), Less);
    }

    #[test]
    fn naive_vercmp_orders_oversized_numeric_segments() {
        // 21 digits overflows u64::MAX (20 digits), exercising the no-parse path.
        assert_eq!(
            naive_vercmp("100000000000000000000.0", "999.0"),
            Ordering::Greater
        );
        assert_eq!(
            naive_vercmp("100000000000000000000.0", "100000000000000000001.0"),
            Less
        );
        assert_eq!(naive_vercmp("000000000000000000001.0", "1.0"), Equal);
    }

    #[test]
    fn naive_vercmp_treats_oversized_numeric_extra_segment_as_release_extension() {
        // A purely numeric extra segment is a release extension even when it
        // overflows u64.
        assert_eq!(
            naive_vercmp("1.0.0.100000000000000000000", "1.0.0"),
            Greater
        );
        assert_eq!(naive_vercmp("1.0.0", "1.0.0.100000000000000000000"), Less);
        // Non-numeric extras still read as prerelease tags (unchanged).
        assert_eq!(naive_vercmp("1.0.0.rc1", "1.0.0"), Less);
    }

    #[test]
    fn pacman_vercmp_orders_oversized_epoch() {
        // An epoch that overflows u64 must compare by value, not collapse to 0.
        assert_eq!(pacman_vercmp("100000000000000000000:1.0", "9:1.0"), Greater);
        assert_eq!(
            pacman_vercmp("100000000000000000000:1.0", "100000000000000000001:1.0"),
            Less
        );
    }

    #[test]
    fn the_two_comparators_are_not_interchangeable() {
        // Epochs: pacman honors them; the naive comparator does not.
        assert_eq!(pacman_vercmp("1:1.0", "2.0"), Greater);
        assert_eq!(naive_vercmp("1:1.0", "2.0"), Less);
    }
}
