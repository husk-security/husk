//! Upstream `version-alpine.go`: apk version ordering,
//! `number{.number}...{letter}{_suffix{number}}...{~hash}{-r#}`.
//!
//! See <https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-package.5.scd>

use super::BigDigits;
use regex::Regex;
use std::cmp::Ordering;
use std::sync::LazyLock;

static NUMBER_COMPONENTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^((\d+)\.?)*").expect("regex"));
static FIRST_LOWERCASE_LETTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z]").expect("regex"));
static SUFFIXES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)").expect("regex"));
static HASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^~([0-9a-f]+)").expect("regex"));
static BUILD_COMPONENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^-r(\d*)").expect("regex"));

#[derive(Clone, Debug)]
struct NumberComponent {
    original: String,
    value: BigDigits,
    index: usize,
}

impl NumberComponent {
    fn zero() -> Self {
        NumberComponent {
            original: "0".to_string(),
            value: BigDigits::zero(),
            index: 0,
        }
    }

    fn cmp_component(&self, other: &NumberComponent) -> Ordering {
        // Trailing components with leading zeros compare as strings (apk
        // treats them like fractional digits); the first component never does.
        if self.index != 0
            && other.index != 0
            && (self.original.starts_with('0') || other.original.starts_with('0'))
        {
            return self.original.cmp(&other.original);
        }
        self.value.cmp(&other.value)
    }
}

#[derive(Clone, Debug)]
struct Suffix {
    /// Sort weight, implicitly naming the suffix:
    /// alpha, beta, pre, rc, <none>, cvs, svn, git, hg, p.
    weight: usize,
    number: BigDigits,
}

fn weight_suffix(suffix: &str) -> usize {
    // "p" is omitted: it is the highest weight, the fall-through.
    let supported = ["alpha", "beta", "pre", "rc", "", "cvs", "svn", "git", "hg"];
    supported
        .iter()
        .position(|s| *s == suffix)
        .unwrap_or(supported.len())
}

#[derive(Clone, Debug)]
pub struct AlpineVersion {
    original: String,
    invalid: bool,
    remainder: String,
    components: Vec<NumberComponent>,
    letter: String,
    suffixes: Vec<Suffix>,
    build_component: BigDigits,
}

pub(super) fn parse(str: &str) -> Option<AlpineVersion> {
    let original = str.to_string();
    let mut v = AlpineVersion {
        original,
        invalid: false,
        remainder: String::new(),
        components: Vec::new(),
        letter: String::new(),
        suffixes: Vec::new(),
        build_component: BigDigits::zero(),
    };
    let mut rest = str;

    // Number components: digit sequences separated by ".", no limits. A
    // trailing dot not followed by a digit ends the run, as in apk.
    if let Some(m) = NUMBER_COMPONENTS.find(rest)
        && !m.as_str().is_empty()
    {
        for (index, digits) in m.as_str().split('.').enumerate() {
            if digits.is_empty() {
                break;
            }
            v.components.push(NumberComponent {
                original: digits.to_string(),
                value: BigDigits::parse(digits)?,
                index,
            });
        }
        rest = &rest[m.end()..];
    }

    // Optional single lower-case letter.
    if FIRST_LOWERCASE_LETTER.is_match(rest) {
        v.letter = rest[..1].to_string();
        rest = &rest[1..];
    }

    // Suffixes: `_name` optionally followed by a number, stripped in order
    // from the front only (a non-leading match leaves the remainder intact,
    // as upstream).
    let mut remaining = rest.to_string();
    for captures in SUFFIXES.captures_iter(rest) {
        let number = match &captures[2] {
            "" => "0",
            number => number,
        };
        v.suffixes.push(Suffix {
            weight: weight_suffix(&captures[1]),
            number: BigDigits::parse(number)?,
        });
        if let Some(stripped) = remaining.strip_prefix(&captures[0]) {
            remaining = stripped.to_string();
        }
    }

    // Optional `~hash`, parsed but ignored in comparison.
    if let Some(m) = HASH.find(&remaining) {
        let end = m.end();
        remaining = remaining[end..].to_string();
    }

    // Optional trailing `-r{number}`; anything else left over marks the
    // version invalid.
    if !remaining.is_empty() {
        if let Some(captures) = BUILD_COMPONENT.captures(&remaining) {
            let number = match captures.get(1).map(|m| m.as_str()).unwrap_or("") {
                "" => "0",
                number => number,
            };
            v.build_component = BigDigits::parse(number)?;
            let matched = captures[0].len();
            remaining = remaining[matched..].to_string();
        } else {
            v.invalid = true;
        }
    }

    v.remainder = remaining;
    Some(v)
}

impl AlpineVersion {
    fn fetch_component(&self, n: usize) -> NumberComponent {
        self.components
            .get(n)
            .cloned()
            .unwrap_or_else(NumberComponent::zero)
    }

    fn fetch_suffix(&self, n: usize) -> Suffix {
        self.suffixes.get(n).cloned().unwrap_or(Suffix {
            weight: 5,
            number: BigDigits::zero(),
        })
    }

    pub(super) fn cmp(&self, other: &AlpineVersion) -> Ordering {
        // Two invalid versions fall back to a plain string compare.
        if self.invalid && other.invalid {
            return self.original.cmp(&other.original);
        }
        let count = self.components.len().max(other.components.len());
        for i in 0..count {
            let diff = self
                .fetch_component(i)
                .cmp_component(&other.fetch_component(i));
            if diff != Ordering::Equal {
                return diff;
            }
        }
        let letters = match (self.letter.is_empty(), other.letter.is_empty()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.letter.cmp(&other.letter),
        };
        if letters != Ordering::Equal {
            return letters;
        }
        let suffix_count = self.suffixes.len().max(other.suffixes.len());
        for i in 0..suffix_count {
            let a = self.fetch_suffix(i);
            let b = other.fetch_suffix(i);
            let diff = a
                .weight
                .cmp(&b.weight)
                .then_with(|| a.number.cmp(&b.number));
            if diff != Ordering::Equal {
                return diff;
            }
        }
        let build = self.build_component.cmp(&other.build_component);
        if build != Ordering::Equal {
            return build;
        }
        match (self.remainder.is_empty(), other.remainder.is_empty()) {
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => Ordering::Equal,
        }
    }
}
