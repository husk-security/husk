//! Crystal / Shards (`shard.lock` → inventory only; no OSV ecosystem).
//!
//! `shard.lock` is a small hand-written YAML document produced by the Shards
//! dependency manager:
//!
//! ```yaml
//! version: 2.0
//! shards:
//!   molinillo:
//!     git: https://github.com/crystal-lang/crystal-molinillo.git
//!     version: 0.2.0
//!   ameba:
//!     git: https://github.com/crystal-ameba/ameba.git
//!     version: 1.5.0
//! ```
//!
//! Each 2-space-indented key under `shards:` is a dependency; its resolved
//! pin is the `version:` line one level deeper. Parsed line-based with
//! indentation as the sole structural signal.

use super::support::Emitter;

/// Pair each dependency name with the first `version:` seen before the next
/// dependency key. Dependencies without a resolved version are skipped (a
/// lock should always pin, but partial input is tolerated).
pub(super) fn shard_lock(contents: &str, out: &mut Emitter<'_>) {
    let mut in_shards = false;
    // The current dependency awaiting its version: (name, declaration line).
    let mut pending: Option<(String, usize)> = None;

    for (idx, raw) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = raw.chars().take_while(|c| *c == ' ').count();

        if indent == 0 {
            in_shards = trimmed == "shards:";
            pending = None;
            continue;
        }
        if !in_shards {
            continue;
        }

        // A dependency key is a 2-space-indented `name:` with no inline value.
        if indent == 2 {
            if let Some(name) = trimmed.strip_suffix(':')
                && !name.is_empty()
            {
                pending = Some((name.to_string(), line_no));
            }
            continue;
        }

        if indent > 2
            && let Some((name, _decl_line)) = &pending
            && let Some(version) = trimmed.strip_prefix("version:")
        {
            let version = version.trim().trim_matches('"').trim_matches('\'');
            if !version.is_empty() {
                out.pkg(name, normalize_version(version), Some(line_no));
                // One pin per dependency, even if the block repeats
                // a version key.
                pending = None;
            }
        }
    }
}

/// Strip a leading `v` (unconditionally, unlike
/// [`super::support::strip_v`]) and any `+git.commit.<sha>` build metadata.
/// Prereleases and calendar versions are kept verbatim.
fn normalize_version(value: &str) -> &str {
    let value = value.strip_prefix('v').unwrap_or(value);
    value.split('+').next().unwrap_or(value).trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str) -> Vec<(String, String, usize)> {
        run_parser("shards", contents, shard_lock)
            .into_iter()
            .map(|p| (p.name, p.version, p.line.expect("line recorded")))
            .collect()
    }

    #[test]
    fn parses_shards_with_versions() {
        let contents = "version: 2.0\n\
shards:\n\
\x20\x20molinillo:\n\
\x20\x20\x20\x20git: https://github.com/crystal-lang/crystal-molinillo.git\n\
\x20\x20\x20\x20version: 0.2.0\n\
\x20\x20ameba:\n\
\x20\x20\x20\x20git: https://github.com/crystal-ameba/ameba.git\n\
\x20\x20\x20\x20version: 1.5.0\n";
        assert_eq!(
            parse(contents),
            vec![
                ("molinillo".to_string(), "0.2.0".to_string(), 5),
                ("ameba".to_string(), "1.5.0".to_string(), 8),
            ]
        );
    }

    #[test]
    fn ignores_deps_without_version_and_quotes_pins() {
        let contents = "shards:\n\
\x20\x20no_version:\n\
\x20\x20\x20\x20git: https://example.com/x.git\n\
\x20\x20quoted:\n\
\x20\x20\x20\x20version: \"1.0.0\"\n";
        assert_eq!(
            parse(contents),
            vec![("quoted".to_string(), "1.0.0".to_string(), 5)]
        );
    }

    #[test]
    fn strips_git_commit_build_metadata_and_leading_v() {
        let contents = "shards:\n\
\x20\x20readline:\n\
\x20\x20\x20\x20version: 0.1.0+git.commit.0fb7d186da8e1b157998d98d1c96e99699b791eb\n";
        assert_eq!(
            parse(contents),
            vec![("readline".to_string(), "0.1.0".to_string(), 3)]
        );
        assert_eq!(normalize_version("v1.2.3"), "1.2.3");
        assert_eq!(normalize_version("2017.04.1"), "2017.04.1");
        assert_eq!(normalize_version("2.0.0-rc1"), "2.0.0-rc1");
    }
}
