//! Hugging Face Hub local cache (models / datasets / spaces): inventory-only
//! (no OSV ecosystem / advisory feed / PURL type; the inventory lets a future
//! model-malware feed flag known-bad revisions).
//!
//! The `huggingface_hub` client lays each cached repo out as
//! `<hub>/<type>s--<org>--<name>/{refs,blobs,snapshots,.no_exist}`. HF repos
//! are git repos; the immutable coordinate is `(repo_id, commit_sha)`, no
//! semver. The pinned revision is the 40-hex SHA stored as the sole contents
//! of the `refs/main` plaintext file, so that file is the scan target: path
//! yields the repo id, body yields the version. This scanner reads ONLY
//! directory names and that tiny text file; it never deserializes any
//! `.bin/.pkl/.pt/.ckpt/.safetensors` weight file (the actual attack
//! surface: pickle RCE).

use super::support::{Emitter, read_text};
use super::{ScanTarget, file_name};
use std::path::{Component, Path};

pub struct HuggingFaceTarget;

impl ScanTarget for HuggingFaceTarget {
    fn ecosystem_id(&self) -> &'static str {
        "huggingface"
    }

    fn detects(&self, path: &Path) -> bool {
        repo_id_from_refs_main(path).is_some()
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        let Some(repo_id) = repo_id_from_refs_main(path) else {
            return;
        };
        let Some(contents) = read_text(path, out) else {
            return;
        };
        // A malformed (non-hex) body still emits the repo id with an
        // "unknown" version rather than failing the scan.
        let version = match normalize_sha(&contents) {
            Some(sha) => sha,
            None => "unknown".to_string(),
        };
        out.pkg(&repo_id, &version, None);
    }
}

/// Derive the canonical HF `repo_id` from a `refs/main` file path. Required
/// shape, matched from the right so a relocated cache (`HF_HUB_CACHE`) still
/// works: `.../huggingface/hub/<type>s--<...>/refs/main`.
fn repo_id_from_refs_main(path: &Path) -> Option<String> {
    if file_name(path) != Some("main") {
        return None;
    }
    let segments: Vec<&str> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();

    let n = segments.len();
    if n < 5 {
        return None;
    }
    if segments.get(n - 1) != Some(&"main") || segments.get(n - 2) != Some(&"refs") {
        return None;
    }
    let repo_dir = segments.get(n - 3)?;
    // The `huggingface/hub` ancestor requirement prevents misfiring on an
    // unrelated `*/refs/main` git file.
    let hub = segments.get(n - 4)?;
    let parent = segments.get(n - 5)?;
    if !(*hub == "hub" && *parent == "huggingface") {
        return None;
    }
    repo_id_from_dir_name(repo_dir)
}

/// Recover the canonical `repo_id` from a cache dir name:
/// `models--julien-c--EsperBERTo-small` → `julien-c/EsperBERTo-small`,
/// `models--bert-base-cased` → `bert-base-cased` (no namespace). The cache
/// flattens `org/name` to `org--name`, so split on the LAST `--`;
/// best-effort, since org/name segments may themselves contain `--`
/// (unrecoverable from disk alone; the commit SHA stays unambiguous).
fn repo_id_from_dir_name(dir: &str) -> Option<String> {
    let remainder = dir
        .strip_prefix("models--")
        .or_else(|| dir.strip_prefix("datasets--"))
        .or_else(|| dir.strip_prefix("spaces--"))?;
    if remainder.is_empty() {
        return None;
    }
    match remainder.rsplit_once("--") {
        Some((org, name)) if !org.is_empty() && !name.is_empty() => Some(format!("{org}/{name}")),
        _ => Some(remainder.to_string()),
    }
}

/// Accept a trimmed/lowercased body as a commit SHA only if it is 7-64 hex
/// chars (40-char SHA-1 is the common case; permissive for short hashes and
/// future SHA-256 object names).
fn normalize_sha(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if !(7..=64).contains(&trimmed.len()) {
        return None;
    }
    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn repo_id_org_name_split_on_last_separator() {
        assert_eq!(
            repo_id_from_dir_name("models--julien-c--EsperBERTo-small").as_deref(),
            Some("julien-c/EsperBERTo-small")
        );
        assert_eq!(
            repo_id_from_dir_name("datasets--huggingface--DataMeasurementsFiles").as_deref(),
            Some("huggingface/DataMeasurementsFiles")
        );
    }

    #[test]
    fn repo_id_namespace_less_canonical_repo() {
        assert_eq!(
            repo_id_from_dir_name("models--bert-base-cased").as_deref(),
            Some("bert-base-cased")
        );
    }

    #[test]
    fn repo_id_rejects_non_hf_dirs() {
        assert!(repo_id_from_dir_name("node_modules").is_none());
        assert!(repo_id_from_dir_name("models--").is_none());
    }

    #[test]
    fn sha_normalized_and_trimmed() {
        assert_eq!(
            normalize_sha("  bbc77c8132af1cc5cf678da3f1ddf2de43606d48\n").as_deref(),
            Some("bbc77c8132af1cc5cf678da3f1ddf2de43606d48")
        );
        assert_eq!(normalize_sha("DEADBEEF").as_deref(), Some("deadbeef"));
    }

    #[test]
    fn sha_rejects_branch_names_and_empty() {
        assert!(normalize_sha("main").is_none()); // not hex
        assert!(normalize_sha("").is_none());
        assert!(normalize_sha("not-a-sha-value").is_none());
    }

    #[test]
    fn detects_refs_main_path_shape() {
        let p = PathBuf::from(
            "/home/u/.cache/huggingface/hub/models--julien-c--EsperBERTo-small/refs/main",
        );
        assert_eq!(
            repo_id_from_refs_main(&p).as_deref(),
            Some("julien-c/EsperBERTo-small")
        );
    }

    #[test]
    fn rejects_unrelated_refs_main() {
        // A plain git repo `refs/main` not under huggingface/hub.
        assert!(repo_id_from_refs_main(&PathBuf::from("/proj/.git/refs/main")).is_none());
        // Nested PR ref (refs/refs/pr/1/main-shaped) under a non-repo grandparent.
        assert!(
            repo_id_from_refs_main(&PathBuf::from(
                "/home/u/.cache/huggingface/hub/models--foo/refs/refs"
            ))
            .is_none()
        );
    }
}
