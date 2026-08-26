//! Upstream `version-packagist.go`: PHP `version_compare` ordering with
//! composer's leading-`v` trim.

use super::BigDigits;
use regex::Regex;
use std::cmp::Ordering;
use std::sync::LazyLock;

static SEPARATORS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[-_+]").expect("regex"));
static NON_DIGIT_TO_DIGIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([^\d.])(\d)").expect("regex"));
static DIGIT_TO_NON_DIGIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d)([^\d.])").expect("regex"));

#[derive(Clone, Debug)]
pub struct PackagistVersion {
    components: Vec<String>,
}

fn canonicalize(v: &str) -> String {
    let v = v.strip_prefix('v').unwrap_or(v);
    let v = v.strip_prefix('V').unwrap_or(v);
    let v = SEPARATORS.replace_all(v, ".");
    let v = NON_DIGIT_TO_DIGIT.replace_all(&v, "$1.$2");
    DIGIT_TO_NON_DIGIT.replace_all(&v, "$1.$2").into_owned()
}

fn weigh_special(str: &str) -> usize {
    if str.starts_with("RC") {
        return 3;
    }
    let specials = ["dev", "a", "b", "rc", "#", "p"];
    for (i, special) in specials.iter().enumerate() {
        if str.starts_with(special) {
            return i;
        }
    }
    0
}

fn compare_specials(a: &str, b: &str) -> Ordering {
    weigh_special(a).cmp(&weigh_special(b))
}

fn compare_components(a: &[String], b: &[String]) -> Ordering {
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        let ai = BigDigits::parse(&a[i]);
        let bi = BigDigits::parse(&b[i]);
        let compare = match (ai, bi) {
            (Some(ai), Some(bi)) => ai.cmp(&bi),
            (None, None) => compare_specials(&a[i], &b[i]),
            (Some(_), None) => compare_specials("#", &b[i]),
            (None, Some(_)) => compare_specials(&a[i], "#"),
        };
        if compare != Ordering::Equal {
            return compare;
        }
    }
    // Upstream tests the next component with Atoi (a machine int), not the
    // big-int path, so mirror that exactly.
    if a.len() > b.len() {
        let next = &a[b.len()];
        if next.parse::<i64>().is_ok() {
            return Ordering::Greater;
        }
        return compare_components(&a[b.len()..], &["#".to_string()]);
    }
    if a.len() < b.len() {
        let next = &b[a.len()];
        if next.parse::<i64>().is_ok() {
            return Ordering::Less;
        }
        return compare_components(&["#".to_string()], &b[a.len()..]);
    }
    Ordering::Equal
}

pub(super) fn parse(str: &str) -> PackagistVersion {
    PackagistVersion {
        components: canonicalize(str).split('.').map(str::to_string).collect(),
    }
}

impl PackagistVersion {
    pub(super) fn cmp(&self, other: &PackagistVersion) -> Ordering {
        compare_components(&self.components, &other.components)
    }
}
