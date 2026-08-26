//! Upstream `version-debian.go`: dpkg version ordering,
//! `[epoch:]upstream[-revision]`.
//!
//! See <https://man7.org/linux/man-pages/man7/deb-version.7.html>

use super::BigDigits;
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct DebianVersion {
    epoch: BigDigits,
    upstream: String,
    revision: String,
}

fn split_around(s: &str, sep: char, reverse: bool) -> (&str, &str) {
    let index = if reverse { s.rfind(sep) } else { s.find(sep) };
    match index {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    }
}

/// Split the leading run of ASCII digits off `str`, as a number (empty run
/// is zero). `None` only if the digits fail to parse, mirroring upstream's
/// error path.
fn split_digit_prefix(str: &str) -> Option<(BigDigits, &str)> {
    let end = str
        .bytes()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(str.len());
    if end == 0 {
        return Some((BigDigits::zero(), str));
    }
    Some((BigDigits::parse(&str[..end])?, &str[end..]))
}

/// Split the leading run of non-digits off `str`.
fn split_non_digit_prefix(str: &str) -> (&str, &str) {
    let end = str
        .bytes()
        .position(|byte| byte.is_ascii_digit())
        .unwrap_or(str.len());
    str.split_at(end)
}

fn weigh_char(char: Option<u8>) -> i32 {
    // Tilde and end-of-string take precedence.
    let Some(c) = char else { return 2 };
    if c == b'~' {
        return 1;
    }
    let mut c = i32::from(c);
    // All letters sort earlier than all non-letters.
    if !(65..=90).contains(&c) && !(97..=122).contains(&c) {
        c += 122;
    }
    c
}

fn compare_versions(mut a: &str, mut b: &str) -> Option<Ordering> {
    while !a.is_empty() || !b.is_empty() {
        let (ap, a_rest) = split_non_digit_prefix(a);
        let (bp, b_rest) = split_non_digit_prefix(b);
        a = a_rest;
        b = b_rest;

        // First the initial non-digit parts compare character-wise...
        if ap != bp {
            for i in 0..ap.len().max(bp.len()) {
                let aw = weigh_char(ap.as_bytes().get(i).copied());
                let bw = weigh_char(bp.as_bytes().get(i).copied());
                match aw.cmp(&bw) {
                    Ordering::Equal => {}
                    diff => return Some(diff),
                }
            }
        }

        // ...then the initial digit parts compare numerically.
        let (adp, a_rest) = split_digit_prefix(a)?;
        let (bdp, b_rest) = split_digit_prefix(b)?;
        a = a_rest;
        b = b_rest;
        match adp.cmp(&bdp) {
            Ordering::Equal => {}
            diff => return Some(diff),
        }
    }
    Some(Ordering::Equal)
}

pub(super) fn parse(str: &str) -> Option<DebianVersion> {
    let str = str.trim();
    let (epoch, rest) = if str.contains(':') {
        let (epoch, rest) = split_around(str, ':', false);
        (BigDigits::parse(epoch)?, rest)
    } else {
        (BigDigits::zero(), str)
    };
    let (upstream, revision) = if rest.contains('-') {
        split_around(rest, '-', true)
    } else {
        (rest, "0")
    };
    Some(DebianVersion {
        epoch,
        upstream: upstream.to_string(),
        revision: revision.to_string(),
    })
}

impl DebianVersion {
    pub(super) fn cmp(&self, other: &DebianVersion) -> Ordering {
        let diff = self.epoch.cmp(&other.epoch);
        if diff != Ordering::Equal {
            return diff;
        }
        // An unparseable digit run is unreachable after parse, so Equal is
        // the faithful stand-in for upstream's error path here.
        let diff = compare_versions(&self.upstream, &other.upstream).unwrap_or(Ordering::Equal);
        if diff != Ordering::Equal {
            return diff;
        }
        compare_versions(&self.revision, &other.revision).unwrap_or(Ordering::Equal)
    }
}
