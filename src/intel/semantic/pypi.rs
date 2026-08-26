//! Upstream `version-pypi.go`: PEP 440 ordering with the same legacy
//! (pre-PEP 440) fallback normalization as upstream.
//!
//! See <https://peps.python.org/pep-0440/>

use super::{BigDigits, Components, is_ascii_digit};
use regex::Regex;
use std::cmp::Ordering;
use std::sync::LazyLock;

static LOCAL_SPLITTER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[._-]").expect("regex"));
static PARTS_FINDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d+|[a-z]+|\.|-)").expect("regex"));
// From PEP 440 Appendix B, as vendored by upstream.
static VERSION_FINDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*v?(?:(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)(?P<pre>[-_\.]?(?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))[-_\.]?(?P<pre_n>[0-9]+)?)?(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?)(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?\s*$",
    )
    .expect("regex")
});

#[derive(Clone, Debug, Default)]
struct LetterNumber {
    letter: String,
    number: Option<BigDigits>,
}

#[derive(Clone, Debug)]
pub struct PyPIVersion {
    epoch: BigDigits,
    release: Components,
    pre: LetterNumber,
    post: LetterNumber,
    dev: LetterNumber,
    local: Vec<String>,
    legacy: Vec<String>,
}

fn parse_letter_version(letter: &str, number: &str) -> Option<LetterNumber> {
    if !letter.is_empty() {
        // An implicit 0 when a pre-release has no numeral.
        let number = if number.is_empty() { "0" } else { number };
        let letter = letter.to_lowercase();
        let letter = match letter.as_str() {
            "alpha" => "a",
            "beta" => "b",
            "c" | "pre" | "preview" => "rc",
            "rev" | "r" => "post",
            other => other,
        };
        return Some(LetterNumber {
            letter: letter.to_string(),
            number: Some(BigDigits::parse(number)?),
        });
    }
    if !number.is_empty() {
        // A number without a letter is the implicit post-release syntax
        // (e.g. `1.0-1`).
        return Some(LetterNumber {
            letter: "post".to_string(),
            number: Some(BigDigits::parse(number)?),
        });
    }
    Some(LetterNumber::default())
}

fn parse_local_version(local: &str) -> Vec<String> {
    if local.is_empty() {
        return Vec::new();
    }
    LOCAL_SPLITTER
        .split(local)
        .map(|part| part.to_lowercase())
        .collect()
}

fn normalize_legacy_part(part: &str) -> String {
    let part = match part {
        "pre" | "preview" | "rc" => "c",
        "-" => "final-",
        "dev" => "@",
        other => other,
    };
    if part.chars().next().is_some_and(is_ascii_digit) {
        // Zero-pad for numeric comparison, as upstream's `%08s`.
        return format!("{part:0>8}");
    }
    format!("*{part}")
}

fn parse_version_parts(str: &str) -> Vec<String> {
    let mut splits: Vec<&str> = PARTS_FINDER.find_iter(str).map(|m| m.as_str()).collect();
    splits.push("final");

    let mut parts: Vec<String> = Vec::new();
    for part in splits {
        if part.is_empty() || part == "." {
            continue;
        }
        let part = normalize_legacy_part(part);
        if part.starts_with('*') {
            if part.as_str() < "*final" {
                while parts.last().is_some_and(|last| last == "*final-") {
                    parts.pop();
                }
            }
            while parts.last().is_some_and(|last| last == "00000000") {
                parts.pop();
            }
        }
        parts.push(part);
    }
    parts
}

fn parse_legacy(str: &str) -> PyPIVersion {
    PyPIVersion {
        epoch: BigDigits::parse("-1").expect("constant"),
        release: Components::default(),
        pre: LetterNumber::default(),
        post: LetterNumber::default(),
        dev: LetterNumber::default(),
        local: Vec::new(),
        legacy: parse_version_parts(str),
    }
}

pub(super) fn parse(str: &str) -> Option<PyPIVersion> {
    let str = str.to_lowercase();
    let Some(captures) = VERSION_FINDER.captures(&str) else {
        return Some(parse_legacy(&str));
    };
    let group = |name: &str| captures.name(name).map(|m| m.as_str()).unwrap_or("");

    let epoch = match group("epoch") {
        "" => BigDigits::zero(),
        epoch => BigDigits::parse(epoch)?,
    };
    let mut release = Vec::new();
    for part in group("release").split('.') {
        release.push(BigDigits::parse(part)?);
    }
    let pre = parse_letter_version(group("pre_l"), group("pre_n"))?;
    let post_number = match group("post_n1") {
        "" => group("post_n2"),
        number => number,
    };
    let post = parse_letter_version(group("post_l"), post_number)?;
    let dev = parse_letter_version(group("dev_l"), group("dev_n"))?;

    Some(PyPIVersion {
        epoch,
        release: Components(release),
        pre,
        post,
        dev,
        local: parse_local_version(group("local")),
        legacy: Vec::new(),
    })
}

impl PyPIVersion {
    /// The sort trick ensuring e.g. `1.0.dev0` sorts before `1.0a0`.
    fn should_apply_pre_trick(&self) -> bool {
        self.pre.number.is_none() && self.post.number.is_none() && self.dev.number.is_some()
    }

    fn compare_pre(&self, other: &PyPIVersion) -> Ordering {
        match (
            self.should_apply_pre_trick(),
            other.should_apply_pre_trick(),
        ) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            (false, false) => {}
        }
        match (&self.pre.number, &other.pre.number) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => {
                let ai = self.pre.letter.as_bytes()[0];
                let bi = other.pre.letter.as_bytes()[0];
                ai.cmp(&bi).then_with(|| a.cmp(b))
            }
        }
    }

    fn compare_post(&self, other: &PyPIVersion) -> Ordering {
        match (&self.post.number, &other.post.number) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }

    fn compare_dev(&self, other: &PyPIVersion) -> Ordering {
        match (&self.dev.number, &other.dev.number) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }

    fn compare_local(&self, other: &PyPIVersion) -> Ordering {
        let min_len = self.local.len().min(other.local.len());
        for i in 0..min_len {
            let ai = BigDigits::parse(&self.local[i]);
            let bi = BigDigits::parse(&other.local[i]);
            let compare = match (ai, bi) {
                (Some(a), Some(b)) => a.cmp(&b),
                (None, None) => self.local[i].cmp(&other.local[i]),
                // Numeric segments compare greater than lexicographic ones.
                (Some(_), None) => Ordering::Greater,
                (None, Some(_)) => Ordering::Less,
            };
            if compare != Ordering::Equal {
                return compare;
            }
        }
        self.local.len().cmp(&other.local.len())
    }

    /// Legacy (pre-PEP 440) versions always sort below PEP 440 versions.
    fn compare_legacy(&self, other: &PyPIVersion) -> Ordering {
        match (self.legacy.is_empty(), other.legacy.is_empty()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => self.legacy.concat().cmp(&other.legacy.concat()),
        }
    }

    pub(super) fn cmp(&self, other: &PyPIVersion) -> Ordering {
        self.compare_legacy(other)
            .then_with(|| self.epoch.cmp(&other.epoch))
            .then_with(|| self.release.cmp_components(&other.release))
            .then_with(|| self.compare_pre(other))
            .then_with(|| self.compare_post(other))
            .then_with(|| self.compare_dev(other))
            .then_with(|| self.compare_local(other))
    }
}
