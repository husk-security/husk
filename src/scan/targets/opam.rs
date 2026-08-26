//! OCaml / opam (`*.opam.locked` + `.opam-switch/switch-state` -> OSV `opam`).
//!
//! Two complementary, hand-rolled parsers over the opam file format (a custom
//! Lisp-ish text format, not TOML/JSON):
//!
//! 1. `<name>.opam.locked`: written by `opam lock`. A standard opam manifest
//!    whose `depends:`/`depopts:` field pins every (transitive) dependency to
//!    an exact version, e.g.
//!
//!    ```text
//!    opam-version: "2.0"
//!    depends: [
//!      "dune" {= "3.10.0"}
//!      "ocaml" {= "5.1.0"}
//!    ]
//!    ```
//!
//! 2. `<switch-prefix>/.opam-switch/switch-state`: opam's on-disk installed
//!    database for a switch (global switches under `~/.opam/<name>/...`, local
//!    switches under `<project>/_opam/...`). The `installed:` field is the
//!    authoritative set of everything actually present, as a list of bare
//!    `"<name>.<version>"` tokens (name and version joined by a literal dot):
//!
//!    ```text
//!    opam-version: "2.0"
//!    installed: [
//!      "cmdliner.1.2.0"
//!      "dune.3.10.0"
//!    ]
//!    ```
//!
//! OSV ecosystem id is the lowercase string `opam`; opam versions are opaque
//! (not SemVer) so we pass name and version verbatim, stripping only quotes.

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name};
use std::path::Path;

pub struct OpamTarget;

impl ScanTarget for OpamTarget {
    fn ecosystem_id(&self) -> &'static str {
        "opam"
    }

    fn detects(&self, path: &Path) -> bool {
        if path.to_str().is_some_and(|p| p.ends_with(".opam.locked")) {
            return true;
        }
        // Require the `.opam-switch` parent so an unrelated file literally
        // named `switch-state` is not hijacked.
        if matches!(file_name(path), Some("switch-state")) {
            return path
                .parent()
                .and_then(file_name)
                .is_some_and(|p| p == ".opam-switch");
        }
        false
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(contents) = read_text(path, out) else {
            return;
        };
        if matches!(file_name(path), Some("switch-state")) {
            parse_switch_state(&contents, out);
        } else {
            parse_locked(&contents, out);
        }
    }
}

/// Pure parser over a `*.opam.locked` file: scan the `depends:`/`depopts:`
/// blocks and pull out `"name" {= "version"}` pinned entries. Tolerates
/// malformed lines by skipping them.
fn parse_locked(contents: &str, out: &mut Emitter<'_>) {
    let mut in_depends = false;

    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();

        // The opening `[` may be on the same line as the field name
        // (`depends: [`).
        if line.starts_with("depends:") || line.starts_with("depopts:") {
            in_depends = true;
            continue;
        }
        if !in_depends {
            continue;
        }
        // Entries may carry their own `]` from a `{ ... }` constraint, so
        // only a bare `]` terminates the block.
        if line == "]" {
            in_depends = false;
            continue;
        }

        // Only pinned (`{= "x"}`) entries carry an exact version; skip range
        // constraints and bare names (no resolvable version).
        if let Some((name, version)) = pinned_entry(line) {
            out.pkg(name, version, Some(idx + 1));
        }
    }
}

/// Pure parser over a `.opam-switch/switch-state` file: collect the
/// `installed:` list of `"name.version"` tokens (the authoritative set of
/// what is actually present in the switch). Tolerates malformed input.
fn parse_switch_state(contents: &str, out: &mut Emitter<'_>) {
    let mut in_installed = false;

    for (idx, raw) in contents.lines().enumerate() {
        let line = raw.trim();

        // The opening `[` may share the `installed:` field's line.
        if line.starts_with("installed:") {
            in_installed = true;
            // Fall through so a token on the same line is still parsed.
        } else if in_installed && line == "]" {
            // Only a bare `]` closes the list.
            in_installed = false;
            continue;
        }
        if !in_installed {
            continue;
        }

        // Each entry is a quoted `"<name>.<version>"` token. Split on the
        // FIRST dot: opam package names never contain a dot, but versions do.
        if let Some((name, version)) = installed_token(line) {
            out.pkg(name, version, Some(idx + 1));
        }
    }
}

/// Parse one `"name" {= "version"}` line into `(name, version)`. Returns
/// `None` if the line is not an exact-version pin.
fn pinned_entry(line: &str) -> Option<(&str, &str)> {
    let name = quoted_token(line)?;
    if name.is_empty() {
        return None;
    }

    // The exact-version constraint looks like `{= "3.10.0"}` (whitespace
    // around `=` varies).
    let brace = line.find('{')?;
    let constraint = line.get(brace + 1..)?;
    let eq = constraint.find('=')?;
    // Reject `>=`, `<=`, `!=` etc.; only a lone `=` is an exact pin.
    let before_eq = constraint.get(..eq)?.trim_end();
    if before_eq
        .chars()
        .next_back()
        .is_some_and(|c| matches!(c, '>' | '<' | '!'))
    {
        return None;
    }
    let after_eq = constraint.get(eq + 1..)?;
    let version = quoted_token(after_eq)?;
    if version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Parse one `"name.version"` installed token into `(name, version)` by
/// splitting on the FIRST dot. Returns `None` if there is no quoted token or
/// the token has no dot (e.g. a virtual/base pseudo-package with no version).
fn installed_token(line: &str) -> Option<(&str, &str)> {
    let token = quoted_token(line)?;
    let dot = token.find('.')?;
    let name = token.get(..dot)?;
    let version = token.get(dot + 1..)?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Return the contents of the first `"..."` double-quoted token in `s`.
fn quoted_token(s: &str) -> Option<&str> {
    let start = s.find('"')? + 1;
    let rest = s.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    #[test]
    fn parses_pinned_depends() {
        let contents = r#"opam-version: "2.0"
name: "myproj"
version: "dev"
depends: [
  "dune" {= "3.10.0"}
  "ocaml" {>= "4.14.0"}
  "cmdliner" {= "1.2.0" & with-test}
  "ocamlfind" {build & = "1.9.6"}
]
"#;
        let pkgs = run_parser("opam", contents, parse_locked);
        // dune and cmdliner are exact pins; ocaml is a range (skipped),
        // ocamlfind has `=` after a flag and is still an exact pin.
        let names: Vec<(&str, &str)> = pkgs
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        assert!(names.contains(&("dune", "3.10.0")));
        assert!(names.contains(&("cmdliner", "1.2.0")));
        assert!(names.contains(&("ocamlfind", "1.9.6")));
        assert!(!names.iter().any(|(n, _)| *n == "ocaml"));
        assert!(pkgs.iter().all(|p| p.ecosystem == "opam"));
    }

    #[test]
    fn parses_switch_state_installed() {
        let contents = r#"opam-version: "2.0"
compiler: ["ocaml-base-compiler.5.1.0"]
roots: ["dune.3.10.0" "cmdliner.1.2.0"]
installed: [
  "cmdliner.1.2.0"
  "dune.3.10.0"
  "ocaml-base-compiler.5.1.0"
  "ppxlib.0.30.0"
]
pinned: ["mylib.dev"]
"#;
        let pkgs = run_parser("opam", contents, parse_switch_state);
        let names: Vec<(&str, &str)> = pkgs
            .iter()
            .map(|p| (p.name.as_str(), p.version.as_str()))
            .collect();
        // Only the `installed:` list is harvested; the hyphenated name keeps
        // its hyphens because we split on the FIRST dot.
        assert!(names.contains(&("cmdliner", "1.2.0")));
        assert!(names.contains(&("dune", "3.10.0")));
        assert!(names.contains(&("ocaml-base-compiler", "5.1.0")));
        assert!(names.contains(&("ppxlib", "0.30.0")));
        // roots/compiler/pinned are not part of the installed list.
        assert_eq!(pkgs.len(), 4);
        assert!(pkgs.iter().all(|p| p.ecosystem == "opam"));
    }

    #[test]
    fn quoted_and_pinned_helpers() {
        assert_eq!(quoted_token(r#"  "foo" {= "1.0"}"#), Some("foo"));
        assert_eq!(quoted_token("no quotes"), None);
        assert_eq!(pinned_entry(r#"  "x" {= "2.1"}"#), Some(("x", "2.1")));
        assert_eq!(pinned_entry(r#"  "x" {>= "2.1"}"#), None);
        assert_eq!(pinned_entry(r#"  "x""#), None);
        // First-dot split keeps hyphenated names intact, versions with dots.
        assert_eq!(
            installed_token(r#"  "ocaml-base-compiler.5.1.0""#),
            Some(("ocaml-base-compiler", "5.1.0"))
        );
        assert_eq!(installed_token(r#"  "novers""#), None);
    }
}
