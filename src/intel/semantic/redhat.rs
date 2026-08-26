//! Upstream `version-redhat.go`: rpmvercmp(8) ordering over
//! `[epoch:]version[-release]`.
//!
//! See <https://docs.fedoraproject.org/en-US/packaging-guidelines/Versioning/>

use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub struct RedHatVersion {
    epoch: String,
    version: String,
    release: String,
}

fn is_only_digits(str: &str) -> bool {
    str.bytes().all(|byte| byte.is_ascii_digit())
}

fn should_be_trimmed(byte: u8) -> bool {
    !byte.is_ascii_alphanumeric() && byte != b'~' && byte != b'^'
}

/// rpmvercmp(8) over two components, byte-wise as upstream.
fn compare_components(a: &str, b: &str) -> Ordering {
    if a.is_empty() && !b.is_empty() {
        return Ordering::Less;
    }
    if !a.is_empty() && b.is_empty() {
        return Ordering::Greater;
    }
    let a = a.as_bytes();
    let b = b.as_bytes();
    let (mut ai, mut bi) = (0usize, 0usize);

    loop {
        // 1. Trim anything that is not [A-Za-z0-9], `~`, or `^`.
        while ai < a.len() && should_be_trimmed(a[ai]) {
            ai += 1;
        }
        while bi < b.len() && should_be_trimmed(b[bi]) {
            bi += 1;
        }

        // 2/3. Tilde sorts before everything, including end-of-string.
        let a_tilde = ai < a.len() && a[ai] == b'~';
        let b_tilde = bi < b.len() && b[bi] == b'~';
        if a_tilde && b_tilde {
            ai += 1;
            bi += 1;
            continue;
        }
        if a_tilde {
            return Ordering::Less;
        }
        if b_tilde {
            return Ordering::Greater;
        }

        // 4/5. Caret sorts before everything except end-of-string.
        let a_caret = ai < a.len() && a[ai] == b'^';
        let b_caret = bi < b.len() && b[bi] == b'^';
        if a_caret && b_caret {
            ai += 1;
            bi += 1;
            continue;
        }
        if a_caret {
            return if bi == b.len() {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        if b_caret {
            return if ai == a.len() {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        // 6. Stop when either string is exhausted.
        if ai == a.len() || bi == b.len() {
            break;
        }

        // 7. Pop the leading run of digits (or letters) from both.
        let is_digit_run = a[ai].is_ascii_digit();
        let run = |bytes: &[u8], mut i: usize| {
            let start = i;
            while i < bytes.len() {
                let matches = if is_digit_run {
                    bytes[i].is_ascii_digit()
                } else {
                    bytes[i].is_ascii_alphabetic()
                };
                if !matches {
                    break;
                }
                i += 1;
            }
            (start, i)
        };
        let (a_start, a_end) = run(a, ai);
        let (b_start, b_end) = run(b, bi);
        ai = a_end;
        bi = b_end;

        // 8. An empty run from `b` decides by the run type of `a`.
        if b_start == b_end {
            return if is_digit_run {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let mut a_run = &a[a_start..a_end];
        let mut b_run = &b[b_start..b_end];

        // 9. Numeric runs: strip leading zeros, longer wins.
        if is_digit_run {
            while let [b'0', rest @ ..] = a_run {
                a_run = rest;
            }
            while let [b'0', rest @ ..] = b_run {
                b_run = rest;
            }
            match a_run.len().cmp(&b_run.len()) {
                Ordering::Equal => {}
                diff => return diff,
            }
        }

        // 10. Byte-wise compare decides, else continue.
        match a_run.cmp(b_run) {
            Ordering::Equal => {}
            diff => return diff,
        }
    }

    // Whatever has more left over wins.
    (a.len() - ai).cmp(&(b.len() - bi))
}

pub(super) fn parse(str: &str) -> RedHatVersion {
    let (epoch, vr) = match str.split_once(':') {
        Some((epoch, vr)) if is_only_digits(epoch) => (epoch, vr),
        _ => ("", str),
    };
    let (version, release) = match vr.split_once('-') {
        // Upstream keeps the separator on the release component.
        Some((version, release)) => (version, format!("-{release}")),
        None => (vr, String::new()),
    };
    let epoch = if epoch.is_empty() { "0" } else { epoch };
    RedHatVersion {
        epoch: epoch.to_string(),
        version: version.to_string(),
        release,
    }
}

impl RedHatVersion {
    pub(super) fn cmp(&self, other: &RedHatVersion) -> Ordering {
        compare_components(&self.epoch, &other.epoch)
            .then_with(|| compare_components(&self.version, &other.version))
            .then_with(|| compare_components(&self.release, &other.release))
    }
}
