//! Personal trust ledger: `~/.husk/ledger.jsonl`.
//!
//! An append-only, hash-chained record of the security decisions a developer
//! makes over time (every `husk approve`: allow / block / suppress). Each line
//! is one JSON entry; each entry's `hash` is `sha256(prev_hash || payload)`, so
//! `husk ledger --verify` can recompute the chain and flag any edited or
//! corrupted entry. The chain detects accidental damage and casual edits; it is
//! not a cryptographic tamper-proofing scheme (anyone who can write the file
//! can rewrite the whole chain).
//!
//! **Privacy:** the ledger is strictly local:
//! written only to `~/.husk/ledger.jsonl`, never sent anywhere, and fully
//! deletable (remove the file and the chain simply restarts). It records only
//! the user's own explicit decisions, never scan contents.

use crate::hash::sha256_hex;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LedgerEntry {
    /// 1-based position in the chain.
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    /// e.g. `approve.allow`, `approve.block`, `approve.suppress`.
    pub action: String,
    /// The coordinate or finding id the decision is about.
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The project the decision was recorded from (the `.husk` dir's parent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Hex `hash` of the previous entry (`""` for the genesis entry).
    pub prev_hash: String,
    /// Hex `sha256(prev_hash || canonical-payload)`.
    pub hash: String,
}

pub fn ledger_path() -> Result<PathBuf> {
    Ok(crate::paths::husk_home()?.join("ledger.jsonl"))
}

/// The deterministic payload an entry's hash covers. Field order and the
/// newline separator are fixed so the digest is reproducible across versions.
fn payload(
    seq: u64,
    timestamp: &DateTime<Utc>,
    action: &str,
    target: &str,
    reason: Option<&str>,
    project: Option<&str>,
    prev_hash: &str,
) -> String {
    format!(
        "{seq}\n{}\n{action}\n{target}\n{}\n{}\n{prev_hash}",
        timestamp.to_rfc3339(),
        reason.unwrap_or(""),
        project.unwrap_or(""),
    )
}

/// Build a fully-hashed entry (pure; no IO, no clock). `prev` is the previous
/// entry, or `None` for the genesis entry.
pub fn build_entry(
    prev: Option<&LedgerEntry>,
    timestamp: DateTime<Utc>,
    action: &str,
    target: &str,
    reason: Option<&str>,
    project: Option<&str>,
) -> LedgerEntry {
    let seq = prev.map(|e| e.seq + 1).unwrap_or(1);
    let prev_hash = prev.map(|e| e.hash.clone()).unwrap_or_default();
    let body = payload(seq, &timestamp, action, target, reason, project, &prev_hash);
    let hash = sha256_hex(body.as_bytes());
    LedgerEntry {
        seq,
        timestamp,
        action: action.to_string(),
        target: target.to_string(),
        reason: reason.map(str::to_string),
        project: project.map(str::to_string),
        prev_hash,
        hash,
    }
}

/// Load and parse the ledger (oldest first). A missing ledger is an empty list,
/// not an error. Malformed trailing lines are skipped.
pub fn load() -> Result<Vec<LedgerEntry>> {
    let path = ledger_path()?;
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Ok(Vec::new());
    };
    Ok(parse(&contents))
}

/// Pure JSONL parse (testable without disk).
pub fn parse(contents: &str) -> Vec<LedgerEntry> {
    contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<LedgerEntry>(l).ok())
        .collect()
}

/// Append a decision to the ledger, returning the new entry. Creates
/// `~/.husk/` and the file on first use. Local-only; never touches the network.
pub fn append(
    action: &str,
    target: &str,
    reason: Option<&str>,
    project: Option<&str>,
) -> Result<LedgerEntry> {
    use std::io::{Read, Seek, SeekFrom, Write};

    let path = ledger_path()?;
    if let Some(parent) = path.parent() {
        // Owner-only (0700), like every other `~/.husk` writer: the ledger is
        // the privacy-promised record of the user's security decisions, and
        // `husk approve` may be the first command that ever creates the dir.
        crate::paths::ensure_dir_private(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;

    // Hold an exclusive advisory lock across read+compute+write so two
    // simultaneous `husk approve` writers can't both follow the same last entry
    // and fork the hash chain (released on drop). Re-read the last entry UNDER
    // the lock; `load()`'s earlier read could be stale by the time we write.
    file.lock()
        .with_context(|| format!("lock {}", path.display()))?;
    let mut contents = String::new();
    file.seek(SeekFrom::Start(0))?;
    file.read_to_string(&mut contents)
        .with_context(|| format!("read {}", path.display()))?;
    let entries = parse(&contents);

    let entry = build_entry(entries.last(), Utc::now(), action, target, reason, project);
    let mut line = serde_json::to_string(&entry)?;
    line.push('\n');
    // Append mode always writes at end, regardless of the seek above.
    file.write_all(line.as_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    Ok(entry)
}

/// Verify chain integrity. Returns the `seq` of the first broken entry, or
/// `None` if the whole chain is intact (or empty).
pub fn verify(entries: &[LedgerEntry]) -> Option<u64> {
    let mut prev: Option<&LedgerEntry> = None;
    for entry in entries {
        let expected_prev_hash = prev.map(|e| e.hash.as_str()).unwrap_or("");
        let expected_seq = prev.map(|e| e.seq + 1).unwrap_or(1);
        let body = payload(
            entry.seq,
            &entry.timestamp,
            &entry.action,
            &entry.target,
            entry.reason.as_deref(),
            entry.project.as_deref(),
            &entry.prev_hash,
        );
        let recomputed = sha256_hex(body.as_bytes());
        if entry.seq != expected_seq
            || entry.prev_hash != expected_prev_hash
            || entry.hash != recomputed
        {
            return Some(entry.seq);
        }
        prev = Some(entry);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> Vec<LedgerEntry> {
        let t = DateTime::<Utc>::from_timestamp(1_000_000, 0).unwrap();
        let a = build_entry(
            None,
            t,
            "approve.allow",
            "npm:lodash@4.17.21",
            None,
            Some("/proj"),
        );
        let b = build_entry(
            Some(&a),
            t,
            "approve.block",
            "npm:evil",
            Some("known malware"),
            Some("/proj"),
        );
        let c = build_entry(Some(&b), t, "approve.suppress", "secret:x", None, None);
        vec![a, b, c]
    }

    #[test]
    fn chains_and_increments() {
        let entries = chain();
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[0].prev_hash, "");
        assert_eq!(entries[1].seq, 2);
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(entries[2].prev_hash, entries[1].hash);
        assert_eq!(entries[0].hash.len(), 64); // hex sha256
        // Same inputs hash deterministically.
        let again = build_entry(
            None,
            DateTime::<Utc>::from_timestamp(1_000_000, 0).unwrap(),
            "approve.allow",
            "npm:lodash@4.17.21",
            None,
            Some("/proj"),
        );
        assert_eq!(again.hash, entries[0].hash);
    }

    #[test]
    fn verify_detects_tampering() {
        let mut entries = chain();
        assert_eq!(verify(&entries), None, "intact chain verifies");
        // Tamper with the middle entry's target; its hash no longer matches.
        entries[1].target = "npm:not-evil".to_string();
        assert_eq!(verify(&entries), Some(2));
    }

    #[test]
    fn roundtrips_jsonl() {
        let entries = chain();
        let text = entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let parsed = parse(&text);
        assert_eq!(parsed, entries);
        assert_eq!(verify(&parsed), None);
    }
}
