//! Nix flakes (`flake.lock` → no OSV ecosystem; inventory-only).
//!
//! `flake.lock` pins every flake input to an immutable source coordinate (a
//! git `rev` + `narHash`). Inputs have no semantic version and no advisory
//! feed, so this emits pinned coordinates (`ecosystem = "nix"`) for inventory
//! only. The companion `flake.nix` carries no pins and is never parsed here.

use super::support::Emitter;
use serde_json::Value as JsonValue;

/// Parse `flake.lock`: skip the root node (the user's own project) and any
/// node without a `locked` object (pure `follows`/alias nodes). The node
/// *label* (map key) is never used as the coordinate name: Nix suffixes
/// duplicate labels with `_2`/`_3`, so it is unstable; the name is always
/// derived from `locked` fields. Distinct labels can pin the same source;
/// discovery dedups those globally.
pub(super) fn flake_lock(contents: &str, out: &mut Emitter<'_>) {
    let Ok(json) = serde_json::from_str::<JsonValue>(contents) else {
        out.warn("flake.lock is not valid JSON");
        return;
    };
    let Some(nodes) = json.get("nodes").and_then(|v| v.as_object()) else {
        return;
    };
    let root_label = json.get("root").and_then(|v| v.as_str()).unwrap_or("root");

    for (label, node) in nodes {
        if label == root_label {
            continue;
        }
        let Some(locked) = node.get("locked") else {
            continue;
        };
        if let Some((name, version)) = coordinate_from_locked(locked, label) {
            out.pkg(&name, &version, None);
        }
    }
}

/// Derive a `(name, version)` coordinate from a node's `locked` object.
///
/// Name derivation depends on the fetcher `type`; version prefers the immutable
/// commit `rev`, then the SRI `narHash`, then the `lastModified` epoch.
fn coordinate_from_locked(locked: &JsonValue, label: &str) -> Option<(String, String)> {
    let ty = locked.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let name = match ty {
        // Forge fetchers: canonical name is `owner/repo`.
        "github" | "gitlab" | "sourcehut" => {
            let owner = locked.get("owner").and_then(|v| v.as_str());
            let repo = locked.get("repo").and_then(|v| v.as_str());
            match (owner, repo) {
                (Some(o), Some(r)) if !o.is_empty() && !r.is_empty() => format!("{o}/{r}"),
                _ => label.to_string(),
            }
        }
        // Raw VCS / archive fetchers: the URL is the coordinate name.
        "git" | "mercurial" | "tarball" | "file" => locked
            .get("url")
            .and_then(|v| v.as_str())
            .map(normalize_url)
            .unwrap_or_else(|| label.to_string()),
        "path" => locked
            .get("path")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| label.to_string()),
        // Registry-resolved indirect input (rare in a locked file).
        "indirect" => locked
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| label.to_string()),
        _ => label.to_string(),
    };

    let version = locked_version(locked)?;
    Some((name, version))
}

/// Version surrogate for a `locked` node: prefer the git `rev`, then the SRI
/// `narHash`, then the `lastModified` unix epoch. `None` if none are present.
fn locked_version(locked: &JsonValue) -> Option<String> {
    if let Some(rev) = locked.get("rev").and_then(|v| v.as_str())
        && !rev.is_empty()
    {
        return Some(rev.to_string());
    }
    if let Some(hash) = locked.get("narHash").and_then(|v| v.as_str())
        && !hash.is_empty()
    {
        return Some(hash.to_string());
    }
    if let Some(epoch) = locked.get("lastModified").and_then(|v| v.as_i64()) {
        return Some(epoch.to_string());
    }
    None
}

/// Normalize a fetcher URL into a stable coordinate name: strip a `git+`
/// scheme prefix Nix adds, drop query params (the `rev` is captured
/// separately), strip a trailing `.git` and any trailing slash.
fn normalize_url(url: &str) -> String {
    let url = url.strip_prefix("git+").unwrap_or(url);
    let url = url.split(['?', '#']).next().unwrap_or(url);
    let url = url.trim_end_matches('/');
    let url = url.strip_suffix(".git").unwrap_or(url);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::targets::support::run_parser;

    fn parse_flake_lock(contents: &str) -> Vec<(String, String)> {
        run_parser("nix", contents, flake_lock)
            .into_iter()
            .map(|p| (p.name, p.version))
            .collect()
    }

    const SAMPLE: &str = r#"{
      "nodes": {
        "flake-utils": {
          "inputs": { "systems": "systems" },
          "locked": {
            "lastModified": 1731533236,
            "narHash": "sha256-l0KFg5HjrsfsO/JpG+r7fRrqm12kzFHyUHqHCVpMMbI=",
            "owner": "numtide",
            "repo": "flake-utils",
            "rev": "11707dc2f618dd54ca8739b309ec4fc024de578b",
            "type": "github"
          },
          "original": { "owner": "numtide", "repo": "flake-utils", "type": "github" }
        },
        "nixpkgs": {
          "locked": {
            "narHash": "sha256-ORvqDbb/LYxiJljGIejapjkc/kJbVote2N1WSb9W45I=",
            "owner": "NixOS",
            "repo": "nixpkgs",
            "rev": "173d0ad7a974f8543a9ab01d2271b2e290341b33",
            "type": "github"
          }
        },
        "somecrate": {
          "flake": false,
          "locked": {
            "rev": "9f8e7d6c5b4a39281706f5e4d3c2b1a0998877665",
            "type": "git",
            "url": "git+https://git.example.org/team/somecrate.git?ref=refs/heads/main"
          }
        },
        "tar": {
          "locked": {
            "lastModified": 1700000000,
            "narHash": "sha256-AbCdEf0000000000000000000000000000000000000=",
            "type": "tarball",
            "url": "https://example.com/x.tar.gz"
          }
        },
        "alias": { "inputs": { "nixpkgs": "nixpkgs" } },
        "root": {
          "inputs": { "flake-utils": "flake-utils", "nixpkgs": "nixpkgs" }
        }
      },
      "root": "root",
      "version": 7
    }"#;

    #[test]
    fn parses_forge_git_and_tarball_skipping_root_and_alias() {
        let mut coords = parse_flake_lock(SAMPLE);
        coords.sort();
        assert_eq!(
            coords,
            vec![
                (
                    "NixOS/nixpkgs".to_string(),
                    "173d0ad7a974f8543a9ab01d2271b2e290341b33".to_string()
                ),
                (
                    "https://example.com/x.tar.gz".to_string(),
                    "sha256-AbCdEf0000000000000000000000000000000000000=".to_string()
                ),
                (
                    // git+ prefix and ?ref= query stripped; rev is the version.
                    "https://git.example.org/team/somecrate".to_string(),
                    "9f8e7d6c5b4a39281706f5e4d3c2b1a0998877665".to_string()
                ),
                (
                    "numtide/flake-utils".to_string(),
                    "11707dc2f618dd54ca8739b309ec4fc024de578b".to_string()
                ),
            ]
        );
    }

    #[test]
    fn tarball_without_rev_falls_back_to_narhash() {
        // Covered above (the `tar` node has no rev); assert the surrogate.
        let coords = parse_flake_lock(SAMPLE);
        assert!(
            coords
                .iter()
                .any(|(n, v)| n == "https://example.com/x.tar.gz" && v.starts_with("sha256-"))
        );
    }

    #[test]
    fn malformed_input_yields_empty() {
        assert!(parse_flake_lock("not json").is_empty());
        assert!(parse_flake_lock("{}").is_empty());
        assert!(parse_flake_lock(r#"{"nodes":{"root":{}},"root":"root"}"#).is_empty());
    }

    #[test]
    fn normalize_url_strips_scheme_query_and_git_suffix() {
        assert_eq!(
            normalize_url("git+https://h/a/b.git?ref=main"),
            "https://h/a/b"
        );
        assert_eq!(normalize_url("https://h/a/"), "https://h/a");
    }
}
