//! Thin SHA-256 helper over the `sha2` crate.
//!
//! Husk uses SHA-256 in a few non-cryptographic, content-addressing spots:
//! the personal trust ledger's hash chain ([`crate::ledger`]) and the stable
//! project id derived from a canonical path ([`crate::model::ProjectId`]).
//! These are not adversarial-integrity boundaries, but there is no reason to
//! hand-roll the primitive; this is glue over a vetted implementation.

use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}
