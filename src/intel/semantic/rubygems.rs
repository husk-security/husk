//! Upstream `version-rubygems.go`: RubyGems `Gem::Version` ordering.

use super::{BigDigits, fetch};
use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct RubyGemsVersion {
    segments: Vec<String>,
}

fn canonicalize(str: &str) -> String {
    let mut result = String::new();
    let mut check_previous = false;
    let mut previous_was_digit = true;
    for c in str.chars() {
        if c == '.' {
            check_previous = false;
            result.push('.');
            continue;
        }
        let is_digit = c.is_ascii_digit();
        if check_previous && previous_was_digit != is_digit {
            result.push('.');
        }
        result.push(c);
        previous_was_digit = is_digit;
        check_previous = true;
    }
    result
}

/// Numbers up to the first non-numeric segment, then everything after as
/// the build.
fn group_segments(segments: &[String]) -> (Vec<String>, Vec<String>) {
    let mut numbers = Vec::new();
    let mut build = Vec::new();
    for segment in segments {
        if !build.is_empty() || BigDigits::parse(segment).is_none() {
            build.push(segment.clone());
            continue;
        }
        numbers.push(segment.clone());
    }
    (numbers, build)
}

/// Drop trailing literal-"0" segments, as upstream.
fn remove_zeros(segments: Vec<String>) -> Vec<String> {
    let mut i = segments.len() as isize - 1;
    while i >= 0 {
        if segments[i as usize] != "0" {
            i += 1;
            break;
        }
        i -= 1;
    }
    let end = i.max(0) as usize;
    segments[..end].to_vec()
}

pub(super) fn parse(str: &str) -> RubyGemsVersion {
    let segments: Vec<String> = canonicalize(str).split('.').map(str::to_string).collect();
    let (numbers, build) = group_segments(&segments);
    let mut canonical = remove_zeros(numbers);
    canonical.extend(remove_zeros(build));
    RubyGemsVersion {
        segments: canonical,
    }
}

impl RubyGemsVersion {
    pub(super) fn cmp(&self, other: &RubyGemsVersion) -> Ordering {
        let a: Vec<&str> = self.segments.iter().map(String::as_str).collect();
        let b: Vec<&str> = other.segments.iter().map(String::as_str).collect();
        let count = a.len().max(b.len());
        for i in 0..count {
            let as_ = fetch(&a, i, "0");
            let bs = fetch(&b, i, "0");
            let ai = BigDigits::parse(as_);
            let bi = BigDigits::parse(bs);
            let diff = match (ai, bi) {
                (Some(a), Some(b)) => a.cmp(&b),
                (None, None) => as_.cmp(bs),
                // A numeric segment sorts after a non-numeric one.
                (Some(_), None) => return Ordering::Greater,
                (None, Some(_)) => return Ordering::Less,
            };
            if diff != Ordering::Equal {
                return diff;
            }
        }
        Ordering::Equal
    }
}
