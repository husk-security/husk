//! Erlang / Elixir rebar3 (`rebar.lock` -> OSV `Hex`).
//!
//! `rebar.lock` is an Erlang term file. Package (Hex) dependencies are encoded
//! as tuples shaped like:
//!
//! ```text
//! {<<"name">>,{pkg,<<"hex_name">>,<<"1.2.3">>},0},
//! ```
//!
//! Newer rebar3 versions append a per-package hash (`{pkg,Name,Vsn,Hash}`) and
//! emit a leading version-annotation tuple plus a trailing hash block; we only
//! care about the `pkg` entries, from which we hand-extract the two relevant
//! binary strings: the Hex package name and the pinned version. Source deps
//! (`git`, `git_subdir`, …) are intentionally skipped: they have no Hex
//! coordinate to match against OSV.

use super::support::{Emitter, count_newlines};

/// Parse a `rebar.lock`, emitting every Hex `pkg` entry. Tolerates malformed
/// input by skipping anything it cannot fully resolve.
pub(super) fn rebar_lock(contents: &str, out: &mut Emitter<'_>) {
    // The term file flattens reasonably onto lines, but to be robust against
    // pretty-printed wrapping we scan the whole text for each `{pkg,` marker.
    // Lines are tracked with a running counter (markers arrive in file order).
    let mut search_from = 0usize;
    let mut line = 1usize;
    let mut counted_to = 0usize;
    while let Some(rel) = contents[search_from..].find("{pkg,") {
        let start = search_from + rel;
        // Advance past this marker so the loop always makes progress.
        search_from = start + "{pkg,".len();

        // Within the `{pkg, ... }` tuple the first two `<<"...">>` binaries are
        // the Hex package name and the version. Pull them in order.
        let tail = &contents[search_from..];
        let Some((name, after_name)) = next_binary(tail) else {
            continue;
        };
        let Some((version, _)) = next_binary(&tail[after_name..]) else {
            continue;
        };

        // Resolve the 1-based line of the entry for finding location.
        line += count_newlines(&contents[counted_to..start]);
        counted_to = start;
        out.pkg(name, version, Some(line));
    }
}

/// Find the next `<<"...">>` binary literal in `s`, returning its contents and
/// the offset just past its closing `>>` (so callers can continue from there).
fn next_binary(s: &str) -> Option<(&str, usize)> {
    let open = s.find("<<\"")?;
    let body_start = open + "<<\"".len();
    let rel_end = s[body_start..].find("\">>")?;
    let body_end = body_start + rel_end;
    Some((&s[body_start..body_end], body_end + "\">>".len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    fn parse(contents: &str) -> Vec<(String, String, usize)> {
        run_parser("hex", contents, rebar_lock)
            .into_iter()
            .map(|p| (p.name, p.version, p.line.expect("line recorded")))
            .collect()
    }

    #[test]
    fn parses_pkg_entries_with_and_without_hash() {
        let contents = r#"{"1.2.0",
[{<<"cowboy">>,{pkg,<<"cowboy">>,<<"2.10.0">>},0},
 {<<"jsx">>,{pkg,<<"jsx">>,<<"3.1.0">>,<<"ABCDEF">>},1},
 {<<"my_git_dep">>,
  {git,"https://github.com/example/dep.git",{ref,"deadbeef"}},
  0}]}.
[
{pkg_hash,[
 {<<"cowboy">>, <<"HASH">>}]}
]."#;
        let pkgs = parse(contents);
        // git dep is skipped; both pkg entries parsed.
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].0, "cowboy");
        assert_eq!(pkgs[0].1, "2.10.0");
        assert_eq!(pkgs[1].0, "jsx");
        assert_eq!(pkgs[1].1, "3.1.0");
        // Line numbers are 1-based.
        assert_eq!(pkgs[0].2, 2);
        assert_eq!(pkgs[1].2, 3);
    }

    #[test]
    fn tolerates_empty_and_malformed() {
        assert!(parse("").is_empty());
        assert!(parse("{pkg,<<\"only_name\">>}").is_empty());
    }
}
