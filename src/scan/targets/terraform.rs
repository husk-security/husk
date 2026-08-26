//! Terraform / OpenTofu providers (`.terraform.lock.hcl`).
//!
//! The dependency lock file written by `terraform init` / `tofu init` records
//! the exact selected version of every provider. There is **no OSV ecosystem**
//! for Terraform providers and no advisory feed keyed by provider coordinate,
//! so these coordinates are an **inventory-only** asset list (useful for
//! provenance / typosquat heuristics, not CVE matching).
//!
//! The file is HCL2 but machine-generated and highly regular: a sequence of
//! top-level `provider "HOST/NAMESPACE/TYPE" { ... }` blocks, each with a
//! mandatory `version = "X.Y.Z"` attribute (an exact pin, never a range). We
//! parse it with a small hand-rolled brace-depth line scanner rather than
//! pulling in a general HCL parser. `constraints` and the multi-line `hashes`
//! array are ignored. The filename is unique and unambiguous (same name and
//! format for both Terraform and OpenTofu).

use super::support::{Emitter, strip_v};

/// `.terraform.lock.hcl`: one coordinate per `provider` block.
pub(super) fn terraform_lock(contents: &str, out: &mut Emitter<'_>) {
    for (name, version, line) in parse_lock(contents) {
        out.pkg(&name, &version, Some(line));
    }
}

/// Parse the lock file body into `(provider_address, version, 1-based line)`
/// triples. Pure (string in, no IO) so it is unit-testable.
///
/// The provider address is the fully-qualified `host/namespace/type` source,
/// lowercased (HCL provider addresses are case-insensitive). We keep the full
/// address so two providers with the same `type` from different namespaces or
/// hosts stay distinct.
fn parse_lock(contents: &str) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    // Brace-depth state machine. The only `{`/`}` in this file are block
    // delimiters (the `hashes` array uses `[`/`]`), so naive counting is safe.
    let mut depth: i32 = 0;
    let mut current: Option<(String, usize)> = None; // (address, opening line)
    let mut version: Option<String> = None;

    for (idx, raw) in contents.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw.trim_start();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        if depth == 0 {
            if let Some(addr) = parse_provider_open(trimmed) {
                current = Some((addr, line_no));
                version = None;
                depth = 1;
                continue;
            }
        } else {
            // The first `version = "..."` inside the block wins.
            if version.is_none()
                && let Some(v) = parse_version(trimmed)
            {
                version = Some(v);
            }
        }

        // Counted last so the opening line of a block (handled above, with
        // depth already set to 1) is not double-counted.
        if depth > 0 {
            depth += count_braces(raw);
            if depth <= 0 {
                // Block closed: emit only if a version was found (malformed
                // blocks are skipped, not fatal).
                if let (Some((addr, open_line)), Some(v)) = (current.take(), version.take()) {
                    out.push((addr, v, open_line));
                }
                depth = 0;
                current = None;
                version = None;
            }
        }
    }

    out
}

/// If `trimmed` opens a provider block, return its lowercased source address.
/// Matches `provider "HOST/NAMESPACE/TYPE" {`.
fn parse_provider_open(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("provider")?;
    // Require whitespace after the keyword so we don't match an identifier that
    // merely starts with "provider".
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let address = first_quoted(rest)?;
    if address.is_empty() {
        return None;
    }
    Some(address.to_ascii_lowercase())
}

/// If `trimmed` is a `version = "X.Y.Z"` attribute, return the value with any
/// leading `v` stripped. Scoped to the version line specifically so hash array
/// elements are never mistaken for a version.
fn parse_version(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("version")?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    let value = first_quoted(rest)?;
    if value.is_empty() {
        return None;
    }
    Some(strip_v(value).to_string())
}

/// The contents of the first double-quoted string in `s`, if any.
fn first_quoted(s: &str) -> Option<&str> {
    let start = s.find('"')? + 1;
    let rest = s.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end)
}

/// Net `{` minus `}` on a line.
fn count_braces(line: &str) -> i32 {
    line.chars().fold(0, |acc, c| match c {
        '{' => acc + 1,
        '}' => acc - 1,
        _ => acc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# This file is maintained automatically by "terraform init".
# Manual edits may be lost in future updates.

provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.0"
  hashes = [
    "h1:HjUfLp3v0xVCfw1jE3iZUyZWPnFY4mAYg5RrZHs6JjQ=",
    "zh:0e8d3d8d6e5f0c0b3b2a1f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c",
  ]
}

provider "registry.opentofu.org/integrations/github" {
  version     = "6.2.1"
  constraints = "~> 6.0"
  hashes = [
    "h1:Zz9q0r1s2t3u4v5w6x7y8z9a0b1c2d3e4f5g6h7i8j9=",
  ]
}
"#;

    #[test]
    fn parses_provider_blocks() {
        let parsed = parse_lock(SAMPLE);
        assert_eq!(
            parsed,
            vec![
                (
                    "registry.terraform.io/hashicorp/aws".to_string(),
                    "5.31.0".to_string(),
                    4
                ),
                (
                    "registry.opentofu.org/integrations/github".to_string(),
                    "6.2.1".to_string(),
                    13
                ),
            ]
        );
    }

    #[test]
    fn ignores_hashes_and_constraints() {
        // A hash element happens to look like a quoted string but must never be
        // read as a version, and `constraints` must be ignored.
        let parsed = parse_lock(SAMPLE);
        assert!(parsed.iter().all(|(_, v, _)| v == "5.31.0" || v == "6.2.1"));
    }

    #[test]
    fn skips_block_without_version() {
        let input = r#"provider "registry.terraform.io/hashicorp/null" {
  constraints = "~> 3.0"
}
provider "registry.terraform.io/hashicorp/random" {
  version = "3.6.0"
}
"#;
        let parsed = parse_lock(input);
        assert_eq!(
            parsed,
            vec![(
                "registry.terraform.io/hashicorp/random".to_string(),
                "3.6.0".to_string(),
                4
            )]
        );
    }

    #[test]
    fn empty_and_comment_only_yield_nothing() {
        assert!(parse_lock("").is_empty());
        assert!(parse_lock("# just a comment\n// another\n").is_empty());
    }

    #[test]
    fn strips_leading_v_and_lowercases_address() {
        let input =
            "provider \"Registry.Terraform.IO/HashiCorp/AWS\" {\n  version = \"v5.31.0\"\n}\n";
        let parsed = parse_lock(input);
        assert_eq!(
            parsed,
            vec![(
                "registry.terraform.io/hashicorp/aws".to_string(),
                "5.31.0".to_string(),
                1
            )]
        );
    }
}
