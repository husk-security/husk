//! Upstream `version-maven.go`: Maven's ComparableVersion ordering.
//!
//! See <https://maven.apache.org/pom.html#version-order-specification>

use super::BigDigits;
use regex::Regex;
use std::cmp::Ordering;
use std::sync::LazyLock;

static DIGIT_TO_NON_DIGIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\D\d").expect("regex"));
static NON_DIGIT_TO_DIGIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d\D").expect("regex"));

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    prefix: String,
    value: String,
    is_null: bool,
}

impl Token {
    fn qualifier_order(&self) -> Option<usize> {
        if BigDigits::parse(&self.value).is_some() {
            if self.prefix == "-" {
                return Some(2);
            }
            if self.prefix == "." {
                return Some(3);
            }
        }
        if self.prefix == "-" {
            return Some(1);
        }
        if self.prefix == "." {
            return Some(0);
        }
        None
    }

    fn should_trim(&self) -> bool {
        self.value == "0" || self.value.is_empty() || self.value == "final" || self.value == "ga"
    }

    fn same(&self, other: &Token) -> bool {
        self.prefix == other.prefix && self.value == other.value
    }

    fn less_than(&self, other: &Token) -> Option<bool> {
        if self.prefix == other.prefix {
            let a = BigDigits::parse(&self.value);
            let b = BigDigits::parse(&other.value);
            if let (Some(a), Some(b)) = (&a, &b) {
                return Some(a.cmp(b) == Ordering::Less);
            }
            // Numerics sort after non-numerics, unless a null value.
            if a.is_some() && !self.is_null {
                return Some(false);
            }
            if b.is_some() && !other.is_null {
                return Some(true);
            }
            let left = keyword_order(&self.value);
            let right = keyword_order(&other.value);
            if left == KEYWORD_ORDER.len() && right == KEYWORD_ORDER.len() {
                // Both unknown qualifiers: lexical.
                return Some(self.value < other.value);
            }
            return Some(left < right);
        }
        // Else ".qualifier" < "-qualifier" < "-number" < ".number".
        Some(self.qualifier_order()? < other.qualifier_order()?)
    }
}

const KEYWORD_ORDER: [&str; 7] = ["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];

fn keyword_order(keyword: &str) -> usize {
    KEYWORD_ORDER
        .iter()
        .position(|k| *k == keyword)
        .unwrap_or(KEYWORD_ORDER.len())
}

fn null_token_for(token: &Token) -> Option<Token> {
    if token.prefix == "." {
        // "sp" is the only qualifier after an empty value; the comparator's
        // shape forces expressing that here.
        let value = if token.value == "sp" { "" } else { "0" };
        return Some(Token {
            prefix: ".".to_string(),
            value: value.to_string(),
            is_null: true,
        });
    }
    if token.prefix == "-" {
        return Some(Token {
            prefix: "-".to_string(),
            value: String::new(),
            is_null: true,
        });
    }
    None
}

#[derive(Clone, Debug)]
pub struct MavenVersion {
    tokens: Vec<Token>,
}

/// Indexes where a token switches between digit and non-digit runs, which
/// count as hyphen-separated.
fn find_transitions(token: &str) -> Vec<usize> {
    let mut indexes: Vec<usize> = DIGIT_TO_NON_DIGIT
        .find_iter(token)
        .chain(NON_DIGIT_TO_DIGIT.find_iter(token))
        .map(|m| m.start() + 1)
        .collect();
    indexes.sort_unstable();
    indexes
}

/// Split keeping each single-char delimiter as its own element.
fn split_chars_inclusive<'a>(s: &'a str, chars: &[char]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(at) = rest.find(|c| chars.contains(&c)) {
        out.push(&rest[..at]);
        out.push(&rest[at..at + 1]);
        rest = &rest[at + 1..];
    }
    out.push(rest);
    out
}

pub(super) fn parse(str: &str) -> MavenVersion {
    let mut tokens: Vec<Token> = Vec::new();
    let raw_tokens = split_chars_inclusive(str, &['-', '.']);

    let mut i = 0;
    while i < raw_tokens.len() {
        let mut prefix = if i == 0 {
            String::new()
        } else {
            raw_tokens[i - 1].to_string()
        };
        let mut transitions = find_transitions(raw_tokens[i]);
        transitions.push(raw_tokens[i].len());

        let mut prev_index = 0;
        for (j, transition) in transitions.iter().copied().enumerate() {
            if j > 0 {
                prefix = "-".to_string();
            }
            // Qualifiers are case-insensitive, though the spec doesn't say.
            let mut current = raw_tokens[i][prev_index..transition].to_lowercase();
            if current.is_empty() {
                current = "0".to_string();
            }
            if current == "cr" {
                current = "rc".to_string();
            }
            // "ga"/"final" (and Maven's "release") equal the empty string.
            if current == "ga" || current == "final" || current == "release" {
                current = String::new();
            }
            // a/b/m are alpha/beta/milestone when directly followed by a number.
            if transition != raw_tokens[i].len() {
                if current == "a" {
                    current = "alpha".to_string();
                }
                if current == "b" {
                    current = "beta".to_string();
                }
                if current == "m" {
                    current = "milestone".to_string();
                }
            }
            // Remove leading zeros from numerics.
            if let Some(digits) = BigDigits::parse(&current) {
                current = digits.digits_string();
            }
            tokens.push(Token {
                prefix: prefix.clone(),
                value: current,
                is_null: false,
            });
            prev_index = transition;
        }
        i += 2;
    }

    // From the end, trim trailing null values (0, "", "final", "ga"),
    // repeating at each remaining hyphen from end to start.
    let mut i = tokens.len() as isize - 1;
    while i > 0 {
        if tokens[i as usize].should_trim() {
            tokens.remove(i as usize);
            i -= 1;
            continue;
        }
        while i >= 0 && tokens[i as usize].prefix != "-" {
            i -= 1;
        }
        i -= 1;
    }

    MavenVersion { tokens }
}

impl MavenVersion {
    fn same(&self, other: &MavenVersion) -> bool {
        self.tokens.len() == other.tokens.len()
            && self
                .tokens
                .iter()
                .zip(other.tokens.iter())
                .all(|(a, b)| a.same(b))
    }

    fn less_than(&self, other: &MavenVersion) -> Option<bool> {
        let count = self.tokens.len().max(other.tokens.len());
        for i in 0..count {
            // The shorter side pads with null values whose shape depends on
            // the other side's prefix: 0 for '.', "" for '-'.
            let left = match self.tokens.get(i) {
                Some(token) => token.clone(),
                None => null_token_for(&other.tokens[i])?,
            };
            let right = match other.tokens.get(i) {
                Some(token) => token.clone(),
                None => null_token_for(&self.tokens[i])?,
            };
            if left.same(&right) {
                continue;
            }
            return left.less_than(&right);
        }
        Some(false)
    }

    pub(super) fn cmp(&self, other: &MavenVersion) -> Ordering {
        self.try_cmp(other).unwrap_or(Ordering::Equal)
    }

    pub(super) fn try_cmp(&self, other: &MavenVersion) -> Option<Ordering> {
        if self.same(other) {
            return Some(Ordering::Equal);
        }
        if self.less_than(other)? {
            return Some(Ordering::Less);
        }
        Some(Ordering::Greater)
    }
}
