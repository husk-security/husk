//! RPM **binary** database reader (`/var/lib/rpm/rpmdb.sqlite`).
//!
//! Modern RPM distros (Fedora 33+, RHEL/CentOS Stream 9+, recent openSUSE) store
//! the installed-package database in a SQLite file `rpmdb.sqlite` whose
//! `Packages(hnum INTEGER PRIMARY KEY, blob BLOB)` table holds one binary RPM
//! *header* blob per installed package. This complements the text-manifest
//! reader (`rpm_manifest.rs`): the manifest path needs an `rpm -qa` export,
//! whereas this reads the authoritative on-disk DB directly.
//!
//! We read the DB read-only via the bundled `rusqlite`, then hand-parse each
//! header blob (the documented RPM header format; no `rpm` crate needed) for
//! NAME / EPOCH / VERSION / RELEASE, and family-qualify the coordinate from the
//! RELEASE dist tag exactly like the manifest reader (so `.el9` -> OSV
//! `Red Hat`, `.suse` -> OSV `openSUSE`, `.fc` -> Fedora inventory).
//!
//! The older Berkeley-DB (`Packages`) and ndb (`Packages.db`) backends are
//! binary formats handled separately; this module is the sqlite backend, which
//! covers the current mainstream distros.

use super::ScanTarget;
use super::support::{Emitter, path_ends_with, read_bytes};
use crate::scan::targets::rpm_manifest::rpm_family;
use rusqlite::{Connection, OpenFlags};
use std::collections::HashSet;
use std::path::Path;

/// Emit one parsed rpm header as a family-qualified coordinate, shared by all
/// three binary backends. gpg-pubkey pseudo-packages (GPG keys, not software)
/// and incomplete headers are never inventoried.
fn emit_header(h: &RpmHeader, out: &mut Emitter<'_>) {
    if h.name == "gpg-pubkey" || h.name.is_empty() || h.version.is_empty() {
        return;
    }
    out.pkg_in(rpm_family(&h.release), &h.name, &h.evr(), None);
}

pub struct RpmSqliteTarget;

impl ScanTarget for RpmSqliteTarget {
    fn ecosystem_id(&self) -> &'static str {
        "rpm"
    }

    fn detects(&self, path: &Path) -> bool {
        // The canonical locations are `/var/lib/rpm/rpmdb.sqlite` and the
        // image-mode `/usr/lib/sysimage/rpm/rpmdb.sqlite`; both end with
        // `rpm/rpmdb.sqlite`.
        path_ends_with(path, &["rpm", "rpmdb.sqlite"])
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        // Open strictly read-only: never create/migrate a user's rpmdb.
        let conn = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(conn) => conn,
            Err(err) => {
                out.warn(format_args!("open rpmdb: {err}"));
                return;
            }
        };
        // Tolerate a missing/renamed table rather than failing the whole scan.
        let Ok(mut stmt) = conn.prepare("SELECT blob FROM Packages") else {
            return;
        };
        let Ok(rows) = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)) else {
            return;
        };
        for blob in rows.flatten() {
            if let Some(h) = parse_rpm_header(&blob) {
                emit_header(&h, out);
            }
        }
    }
}

/// RPM **ndb** ("new database") backend reader (`/var/lib/rpm/Packages.db`),
/// the default on openSUSE/SUSE and Fedora's brief ndb era.
///
/// Layout (reverse-engineered + validated against a real openSUSE 15.6 db):
/// a 16-byte header (`RpmP` magic, then `slotNPages` as LE u32 at offset 12);
/// `slotNPages` × 4096-byte pages of 16-byte slot entries (`Slot` magic,
/// `pkgIndex`, `blkOffset`, `blkCount`, all LE); each non-empty slot points to a
/// blob at `blkOffset * 16` that opens with a 16-byte `BlbS` header (blob length
/// LE at offset 12) followed by a magic-less RPM header (`il`/`dl` big-endian),
/// parsed by the shared [`parse_rpm_header`].
pub struct RpmNdbTarget;

const NDB_HEADER_MAGIC: &[u8; 4] = b"RpmP";
const NDB_SLOT_MAGIC: &[u8; 4] = b"Slot";
const NDB_BLOB_MAGIC: &[u8; 4] = b"BlbS";
const NDB_BLK_SIZE: usize = 16;
const NDB_PAGE_SIZE: usize = 4096;

impl ScanTarget for RpmNdbTarget {
    fn ecosystem_id(&self) -> &'static str {
        "rpm"
    }

    fn detects(&self, path: &Path) -> bool {
        path_ends_with(path, &["rpm", "Packages.db"])
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        // Binary database: read the raw bytes (read_text is for text
        // manifests), under the same size cap every other target obeys.
        if let Some(data) = read_bytes(path, out) {
            parse_ndb(&data, out);
        }
    }
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let s = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Pure ndb parser: bytes-in, coordinates-out. Tolerates truncation/forged
/// offsets (every access is bounds-checked; bad slots are skipped).
fn parse_ndb(data: &[u8], out: &mut Emitter<'_>) {
    if data.get(..4) != Some(NDB_HEADER_MAGIC.as_slice()) {
        return;
    }
    let Some(slot_pages) = le_u32(data, 12) else {
        return;
    };
    // Slot region follows the 16-byte header; cap the size to the file.
    let slot_bytes = (slot_pages as usize).saturating_mul(NDB_PAGE_SIZE);
    let slot_end = (16 + slot_bytes).min(data.len());
    let mut offset = 16;
    while offset + 16 <= slot_end {
        let entry = &data[offset..offset + 16];
        offset += 16;
        if &entry[0..4] != NDB_SLOT_MAGIC.as_slice() {
            continue;
        }
        let pkg_index = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
        let blk_offset = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as usize;
        if pkg_index == 0 || blk_offset == 0 {
            continue;
        }
        let blob_start = blk_offset.saturating_mul(NDB_BLK_SIZE);
        // Blob: 16-byte `BlbS` header, blob length (LE) at +12, then the header.
        if data.get(blob_start..blob_start + 4) != Some(NDB_BLOB_MAGIC.as_slice()) {
            continue;
        }
        let Some(blob_len) = le_u32(data, blob_start + 12) else {
            continue;
        };
        let header_start = blob_start + 16;
        let header_end = header_start.saturating_add(blob_len as usize);
        let Some(header) = data.get(header_start..header_end.min(data.len())) else {
            continue;
        };
        if let Some(h) = parse_rpm_header(header) {
            emit_header(&h, out);
        }
    }
}

/// RPM **bdb** (Berkeley DB hash) backend reader (`/var/lib/rpm/Packages`),
/// the default on RHEL/CentOS/Rocky/AlmaLinux **8** (supported through 2029) and
/// EL≤7. The header blobs are large and live in `H_OFFPAGE` overflow-page
/// chains referenced from the hash pages.
///
/// Layout (reverse-engineered + validated against a real CentOS 7 `Packages`):
/// page 0 is the hash metadata page (magic `0x00061561` at offset 12, byte
/// order detected from it; page size at offset 20). Each hash page (type byte
/// 13 at offset 25) has `NUM_ENT` (u16 @ 20) and a u16 index array @ 26; data
/// items whose first byte is `H_OFFPAGE` (3) carry `pgno` (@+4) + total length
/// (@+8). Overflow pages (type 7) chain via `next_pgno` (@16) and hold
/// `len` (u16 @22) data bytes after a 26-byte header; the concatenation is a
/// magic-less rpm header parsed by [`parse_rpm_header`].
pub struct RpmBdbTarget;

const BDB_HASH_MAGIC: u32 = 0x0006_1561;
const BDB_PAGE_HASH: u8 = 13;
const BDB_PAGE_OVERFLOW_HDR: usize = 26;
const BDB_H_OFFPAGE: u8 = 3;

impl ScanTarget for RpmBdbTarget {
    fn ecosystem_id(&self) -> &'static str {
        "rpm"
    }

    fn detects(&self, path: &Path) -> bool {
        // Exactly `.../rpm/Packages`; never the ndb `Packages.db` or the
        // sqlite `rpmdb.sqlite`.
        path_ends_with(path, &["rpm", "Packages"])
    }

    fn parse(&self, path: &Path, out: &mut Emitter<'_>) {
        if let Some(data) = read_bytes(path, out) {
            parse_bdb(&data, out);
        }
    }
}

/// Read a `u16`/`u32` honoring the database's detected byte order.
fn bdb_u16(data: &[u8], off: usize, swap: bool) -> Option<u16> {
    let v = u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?);
    Some(if swap { v.swap_bytes() } else { v })
}
fn bdb_u32(data: &[u8], off: usize, swap: bool) -> Option<u32> {
    let v = u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?);
    Some(if swap { v.swap_bytes() } else { v })
}

/// Walk an `H_OFFPAGE` overflow-page chain, concatenating up to `tlen` bytes.
///
/// Both bounds here are attacker-controlled in a scanned repository, and both
/// are clamped: `tlen` is a raw `u32` from the data item (up to 4 GiB) but a
/// blob assembled out of `data` can never exceed `data`, and `next_pgno` is a
/// raw page number that a crafted file can point back into the chain, so
/// visited pages are tracked instead of trusting a large iteration guard.
/// Without both clamps, a tiny crafted file can drive a multi-gigabyte
/// allocation.
fn bdb_read_overflow(
    data: &[u8],
    mut pgno: u32,
    tlen: usize,
    page_size: usize,
    swap: bool,
) -> Vec<u8> {
    let tlen = tlen.min(data.len());
    let mut out = Vec::with_capacity(tlen.min(1 << 20));
    // Bounded by the page count of the file: a page whose header lies outside
    // `data` ends the walk, so the set can never outgrow the input.
    let mut visited = HashSet::new();
    while pgno != 0 && out.len() < tlen && visited.insert(pgno) {
        let po = (pgno as usize).saturating_mul(page_size);
        let (Some(next), Some(len)) = (bdb_u32(data, po + 16, swap), bdb_u16(data, po + 22, swap))
        else {
            break;
        };
        let start = po + BDB_PAGE_OVERFLOW_HDR;
        let end = start.saturating_add(len as usize).min(data.len());
        let Some(chunk) = data.get(start..end) else {
            break;
        };
        out.extend_from_slice(chunk);
        pgno = next;
    }
    out.truncate(tlen);
    out
}

/// Pure bdb parser: bytes-in, coordinates-out. Every access is bounds-checked.
fn parse_bdb(data: &[u8], out: &mut Emitter<'_>) {
    // Metadata magic at offset 12 fixes the byte order.
    let Some(raw_magic) = bdb_u32(data, 12, false) else {
        return;
    };
    let swap = if raw_magic == BDB_HASH_MAGIC {
        false
    } else if raw_magic.swap_bytes() == BDB_HASH_MAGIC {
        true
    } else {
        return; // not a Berkeley DB hash database
    };
    let page_size = bdb_u32(data, 20, swap).unwrap_or(0) as usize;
    if !(BDB_PAGE_OVERFLOW_HDR..=(1 << 20)).contains(&page_size) {
        return;
    }

    for base in (0..data.len()).step_by(page_size) {
        if data.get(base + 25).copied() != Some(BDB_PAGE_HASH) {
            continue;
        }
        let Some(n_ent) = bdb_u16(data, base + 20, swap) else {
            continue;
        };
        for i in 0..n_ent as usize {
            let Some(item_off) = bdb_u16(data, base + 26 + i * 2, swap) else {
                continue;
            };
            let io = base + item_off as usize;
            // Only H_OFFPAGE data items hold (large) rpm header blobs.
            if data.get(io).copied() != Some(BDB_H_OFFPAGE) {
                continue;
            }
            let (Some(pgno), Some(tlen)) =
                (bdb_u32(data, io + 4, swap), bdb_u32(data, io + 8, swap))
            else {
                continue;
            };
            let blob = bdb_read_overflow(data, pgno, tlen as usize, page_size, swap);
            if let Some(h) = parse_rpm_header(&blob) {
                emit_header(&h, out);
            }
        }
    }
}

/// Fields of interest extracted from one RPM header blob.
struct RpmHeader {
    name: String,
    epoch: Option<u32>,
    version: String,
    release: String,
}

impl RpmHeader {
    /// Advisory-key EVR form `EPOCH:VERSION-RELEASE` (epoch defaults to 0),
    /// matching the text-manifest reader and OSV's Red Hat keys.
    fn evr(&self) -> String {
        format!(
            "{}:{}-{}",
            self.epoch.unwrap_or(0),
            self.version,
            self.release
        )
    }
}

// RPM header tag numbers (rpmtag.h).
const RPMTAG_NAME: u32 = 1000;
const RPMTAG_VERSION: u32 = 1001;
const RPMTAG_RELEASE: u32 = 1002;
const RPMTAG_EPOCH: u32 = 1003;
// RPM header data types (rpmtd.h).
const RPM_INT32_TYPE: u32 = 4;
const RPM_STRING_TYPE: u32 = 6;

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Parse an RPM header blob (the documented `headerExport` layout):
/// `il`(BE u32 index-entry count) + `dl`(BE u32 data length) + `il`×16-byte
/// index entries (tag, type, offset, count, all BE u32) + a `dl`-byte data
/// store. An optional 8-byte header magic lead is skipped if present. Returns
/// `None` on malformed/truncated input (never panics).
fn parse_rpm_header(blob: &[u8]) -> Option<RpmHeader> {
    // Some exporters prefix the 8-byte HEADER_MAGIC (0x8e 0xad 0xe8 0x01 ...).
    let body = if blob.len() >= 8 && blob[0..3] == [0x8e, 0xad, 0xe8] {
        &blob[8..]
    } else {
        blob
    };

    let il = be_u32(body, 0)? as usize;
    let dl = be_u32(body, 4)? as usize;
    let index_start = 8usize;
    let store_start = index_start.checked_add(il.checked_mul(16)?)?;
    // The store must fit; bail on a truncated/forged header.
    if body.len() < store_start || body.len() < store_start.checked_add(dl)? {
        return None;
    }
    let store = &body[store_start..store_start + dl];

    let mut name = None;
    let mut version = None;
    let mut release = None;
    let mut epoch = None;

    for i in 0..il {
        let entry = index_start + i * 16;
        let tag = be_u32(body, entry)?;
        let dtype = be_u32(body, entry + 4)?;
        let offset = be_u32(body, entry + 8)? as usize;

        match tag {
            RPMTAG_NAME if dtype == RPM_STRING_TYPE => name = read_cstring(store, offset),
            RPMTAG_VERSION if dtype == RPM_STRING_TYPE => version = read_cstring(store, offset),
            RPMTAG_RELEASE if dtype == RPM_STRING_TYPE => release = read_cstring(store, offset),
            RPMTAG_EPOCH if dtype == RPM_INT32_TYPE => epoch = be_u32(store, offset),
            _ => {}
        }
    }

    Some(RpmHeader {
        name: name?,
        epoch,
        version: version?,
        release: release?,
    })
}

/// Read a NUL-terminated UTF-8 string from `store` starting at `offset`.
fn read_cstring(store: &[u8], offset: usize) -> Option<String> {
    let rest = store.get(offset..)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    std::str::from_utf8(&rest[..end]).ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageRef;

    /// Run a target's `emit` against a real on-disk file, collecting packages.
    fn emit_packages(target: &dyn ScanTarget, path: &Path) -> Vec<PackageRef> {
        let mut packages = Vec::new();
        let mut warnings = Vec::new();
        let mut out = Emitter::new("rpm", path, &mut packages, &mut warnings);
        target.parse(path, &mut out);
        assert_eq!(warnings, Vec::<String>::new(), "no warnings expected");
        packages
    }

    /// Build a minimal valid RPM header blob carrying NAME/EPOCH/VERSION/RELEASE.
    fn build_header(name: &str, epoch: Option<u32>, version: &str, release: &str) -> Vec<u8> {
        let mut store: Vec<u8> = Vec::new();
        let mut entries: Vec<(u32, u32, u32, u32)> = Vec::new(); // tag, type, offset, count

        if let Some(e) = epoch {
            // INT32 must be 4-byte aligned in the store.
            while !store.len().is_multiple_of(4) {
                store.push(0);
            }
            let off = store.len() as u32;
            store.extend_from_slice(&e.to_be_bytes());
            entries.push((RPMTAG_EPOCH, RPM_INT32_TYPE, off, 1));
        }
        let mut push_str = |s: &str, tag: u32, entries: &mut Vec<(u32, u32, u32, u32)>| {
            let off = store.len() as u32;
            store.extend_from_slice(s.as_bytes());
            store.push(0);
            entries.push((tag, RPM_STRING_TYPE, off, 1));
        };
        push_str(name, RPMTAG_NAME, &mut entries);
        push_str(version, RPMTAG_VERSION, &mut entries);
        push_str(release, RPMTAG_RELEASE, &mut entries);

        let il = entries.len() as u32;
        let dl = store.len() as u32;
        let mut blob = Vec::new();
        blob.extend_from_slice(&il.to_be_bytes());
        blob.extend_from_slice(&dl.to_be_bytes());
        for (tag, ty, off, count) in entries {
            blob.extend_from_slice(&tag.to_be_bytes());
            blob.extend_from_slice(&ty.to_be_bytes());
            blob.extend_from_slice(&off.to_be_bytes());
            blob.extend_from_slice(&count.to_be_bytes());
        }
        blob.extend_from_slice(&store);
        blob
    }

    #[test]
    fn parses_header_with_epoch_and_family() {
        let blob = build_header("openssl", Some(1), "3.0.7", "18.el9_2");
        let h = parse_rpm_header(&blob).expect("header");
        assert_eq!(h.name, "openssl");
        assert_eq!(h.evr(), "1:3.0.7-18.el9_2");
        assert_eq!(rpm_family(&h.release), "redhat");
    }

    #[test]
    fn parses_header_without_epoch() {
        let blob = build_header("bash", None, "5.2.15", "2.fc38");
        let h = parse_rpm_header(&blob).expect("header");
        assert_eq!(h.evr(), "0:5.2.15-2.fc38");
        assert_eq!(rpm_family(&h.release), "fedora");
    }

    #[test]
    fn rejects_truncated_blob() {
        assert!(parse_rpm_header(&[0, 0, 0, 1]).is_none());
        assert!(parse_rpm_header(&[]).is_none());
    }

    #[test]
    fn reads_rpmdb_sqlite_end_to_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("rpmdb.sqlite");
        let conn = Connection::open(&db).expect("open");
        conn.execute_batch(
            "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB);",
        )
        .expect("schema");
        for (n, e, v, r) in [
            ("openssl", Some(1u32), "3.0.7", "18.el9_2"),
            ("gpg-pubkey", None, "fd431d51", "4ae0493b"), // must be skipped
        ] {
            conn.execute(
                "INSERT INTO Packages (blob) VALUES (?1)",
                [build_header(n, e, v, r)],
            )
            .expect("insert");
        }
        drop(conn);

        let pkgs = emit_packages(&RpmSqliteTarget, &db);
        assert_eq!(pkgs.len(), 1, "gpg-pubkey filtered out");
        assert_eq!(pkgs[0].name, "openssl");
        assert_eq!(pkgs[0].version, "1:3.0.7-18.el9_2");
        assert_eq!(pkgs[0].ecosystem, "redhat");
    }

    /// Wrap a magic-less rpm header in the on-disk ndb layout reverse-engineered
    /// from a real openSUSE 15.6 `Packages.db`: 16-byte `RpmP` header
    /// (slotNPages=1), a 4096-byte slot page with one `Slot` entry, and a `BlbS`
    /// blob at `blkOffset * 16`.
    fn build_ndb(headers: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        // ndb header: magic, version, generation, slotNPages = 1 (LE).
        out.extend_from_slice(b"RpmP");
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());

        // One 4096-byte slot page starts at offset 16; blobs follow it.
        let blobs_start = 16 + 4096;
        let mut slot_page = vec![0u8; 4096];
        let mut blobs = Vec::new();
        for (i, header) in headers.iter().enumerate() {
            let blob_offset = blobs_start + blobs.len();
            // BlbS blob header: magic, pkgIndex, gen, blobLen (all LE), + header.
            blobs.extend_from_slice(b"BlbS");
            blobs.extend_from_slice(&((i as u32) + 1).to_le_bytes());
            blobs.extend_from_slice(&1u32.to_le_bytes());
            blobs.extend_from_slice(&(header.len() as u32).to_le_bytes());
            blobs.extend_from_slice(header);
            // Blobs are aligned to NDB_BLK_SIZE (16) so blkOffset is exact.
            while !blobs.len().is_multiple_of(16) {
                blobs.push(0);
            }
            // Slot entry: magic, pkgIndex, blkOffset (in 16-byte blocks), blkCount.
            let entry = i * 16;
            slot_page[entry..entry + 4].copy_from_slice(b"Slot");
            slot_page[entry + 4..entry + 8].copy_from_slice(&((i as u32) + 1).to_le_bytes());
            slot_page[entry + 8..entry + 12]
                .copy_from_slice(&((blob_offset / 16) as u32).to_le_bytes());
            slot_page[entry + 12..entry + 16].copy_from_slice(&1u32.to_le_bytes());
        }
        out.extend_from_slice(&slot_page);
        out.extend_from_slice(&blobs);
        out
    }

    #[test]
    fn reads_ndb_packages_db_end_to_end() {
        let ndb = build_ndb(&[
            build_header("openssl", Some(1), "3.0.7", "18.el9_2"),
            build_header("gpg-pubkey", None, "fd431d51", "4ae0493b"), // skipped
            build_header("bash", None, "5.2.15", "2.fc38"),
        ]);
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("Packages.db");
        std::fs::write(&db, &ndb).expect("write");

        let pkgs = emit_packages(&RpmNdbTarget, &db);
        let names: Vec<_> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"openssl"), "got {names:?}");
        assert!(names.contains(&"bash"));
        assert!(!names.contains(&"gpg-pubkey"), "gpg-pubkey filtered out");
        let openssl = pkgs.iter().find(|p| p.name == "openssl").unwrap();
        assert_eq!(openssl.version, "1:3.0.7-18.el9_2");
        assert_eq!(openssl.ecosystem, "redhat");
    }

    /// Build a minimal Berkeley-DB hash file in the layout reverse-engineered
    /// from a real CentOS 7 `Packages`: page 0 metadata (`0x00061561`), page 1 a
    /// hash page with one (key, `H_OFFPAGE`-data) pair per header, and one
    /// overflow page per header holding the (small) rpm header.
    fn build_bdb(headers: &[Vec<u8>]) -> Vec<u8> {
        const PS: usize = 4096;
        let mut meta = vec![0u8; PS];
        meta[12..16].copy_from_slice(&BDB_HASH_MAGIC.to_le_bytes());
        meta[20..24].copy_from_slice(&(PS as u32).to_le_bytes());
        meta[25] = 9; // P_HASHMETA

        let mut hash = vec![0u8; PS];
        hash[25] = BDB_PAGE_HASH;
        hash[20..22].copy_from_slice(&((headers.len() * 2) as u16).to_le_bytes());

        let mut overflow = Vec::new();
        let mut write_pos = PS; // items are written downward from the page end
        for (i, header) in headers.iter().enumerate() {
            // Key item (H_KEYDATA: type 1 + a 4-byte record number).
            let key = [1u8, 0, 0, 0, (i as u8) + 1, 0, 0, 0];
            write_pos -= key.len();
            hash[write_pos..write_pos + key.len()].copy_from_slice(&key);
            hash[26 + i * 4..26 + i * 4 + 2].copy_from_slice(&(write_pos as u16).to_le_bytes());
            // Data item (H_OFFPAGE: type 3, 3 pad, pgno, total length).
            let ovf_pgno = 2u32 + i as u32;
            let mut item = vec![3u8, 0, 0, 0];
            item.extend_from_slice(&ovf_pgno.to_le_bytes());
            item.extend_from_slice(&(header.len() as u32).to_le_bytes());
            write_pos -= item.len();
            hash[write_pos..write_pos + item.len()].copy_from_slice(&item);
            hash[26 + i * 4 + 2..26 + i * 4 + 4].copy_from_slice(&(write_pos as u16).to_le_bytes());
            // Overflow page holding the header (fits in one page for the test).
            let mut ov = vec![0u8; PS];
            ov[16..20].copy_from_slice(&0u32.to_le_bytes()); // next_pgno = 0
            ov[22..24].copy_from_slice(&(header.len() as u16).to_le_bytes());
            ov[25] = 7; // P_OVERFLOW
            ov[26..26 + header.len()].copy_from_slice(header);
            overflow.push(ov);
        }
        let mut out = meta;
        out.extend_from_slice(&hash);
        for ov in overflow {
            out.extend_from_slice(&ov);
        }
        out
    }

    /// A Berkeley-DB file whose single `H_OFFPAGE` item claims a `u32::MAX`
    /// total length and whose overflow page chains to itself. Both numbers are
    /// legal on the wire and neither can be satisfied by a 12 KB file.
    fn build_hostile_bdb() -> Vec<u8> {
        const PS: usize = 4096;
        let mut meta = vec![0u8; PS];
        meta[12..16].copy_from_slice(&BDB_HASH_MAGIC.to_le_bytes());
        meta[20..24].copy_from_slice(&(PS as u32).to_le_bytes());
        meta[25] = 9;

        let mut hash = vec![0u8; PS];
        hash[25] = BDB_PAGE_HASH;
        hash[20..22].copy_from_slice(&2u16.to_le_bytes());
        let key = [1u8, 0, 0, 0, 1, 0, 0, 0];
        let key_pos = PS - key.len();
        hash[key_pos..PS].copy_from_slice(&key);
        hash[26..28].copy_from_slice(&(key_pos as u16).to_le_bytes());
        let mut item = vec![BDB_H_OFFPAGE, 0, 0, 0];
        item.extend_from_slice(&2u32.to_le_bytes()); // overflow page 2
        item.extend_from_slice(&u32::MAX.to_le_bytes()); // forged total length
        let item_pos = key_pos - item.len();
        hash[item_pos..item_pos + item.len()].copy_from_slice(&item);
        hash[28..30].copy_from_slice(&(item_pos as u16).to_le_bytes());

        let mut overflow = vec![0x41u8; PS];
        overflow[16..20].copy_from_slice(&2u32.to_le_bytes()); // next_pgno = itself
        overflow[22..24].copy_from_slice(&((PS - BDB_PAGE_OVERFLOW_HDR) as u16).to_le_bytes());
        overflow[25] = 7;

        let mut out = meta;
        out.extend_from_slice(&hash);
        out.extend_from_slice(&overflow);
        out
    }

    #[test]
    fn hostile_bdb_cannot_allocate_more_than_the_file_it_came_from() {
        // Every length here is attacker-controlled: any scanned repository can
        // hold a crafted file at `<anything>/rpm/Packages` whose self-looping
        // overflow chain would otherwise grow a multi-gigabyte Vec.
        let data = build_hostile_bdb();
        assert_eq!(data.len(), 3 * 4096);
        let blob = bdb_read_overflow(&data, 2, u32::MAX as usize, 4096, false);
        assert!(
            blob.len() <= data.len(),
            "assembled {} bytes from a {} byte file",
            blob.len(),
            data.len()
        );

        let mut packages = Vec::new();
        let mut warnings = Vec::new();
        let path = Path::new("/repo/rpm/Packages");
        let mut out = Emitter::new("rpm", path, &mut packages, &mut warnings);
        parse_bdb(&data, &mut out);
        assert!(packages.is_empty(), "the forged blob is not a valid header");
    }

    #[test]
    fn oversized_binary_database_is_skipped_with_a_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("Packages");
        let file = std::fs::File::create(&db).expect("create");
        file.set_len(crate::scan::targets::support::MAX_MANIFEST_BYTES + 1)
            .expect("size");
        drop(file);

        let mut packages = Vec::new();
        let mut warnings = Vec::new();
        let mut out = Emitter::new("rpm", &db, &mut packages, &mut warnings);
        RpmBdbTarget.parse(&db, &mut out);
        assert!(packages.is_empty());
        assert_eq!(warnings.len(), 1, "the skip must be visible: {warnings:?}");
        assert!(warnings[0].contains("skipped"), "{warnings:?}");
    }

    #[test]
    fn reads_bdb_packages_end_to_end() {
        let bdb = build_bdb(&[
            build_header("openssl", Some(1), "3.0.7", "18.el9_2"),
            build_header("gpg-pubkey", None, "fd431d51", "4ae0493b"), // skipped
            build_header("bash", None, "4.2.46", "34.el7"),
        ]);
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("Packages");
        std::fs::write(&db, &bdb).expect("write");

        let pkgs = emit_packages(&RpmBdbTarget, &db);
        let names: Vec<_> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"openssl"), "got {names:?}");
        assert!(names.contains(&"bash"));
        assert!(!names.contains(&"gpg-pubkey"));
        let bash = pkgs.iter().find(|p| p.name == "bash").unwrap();
        assert_eq!(bash.version, "0:4.2.46-34.el7");
        assert_eq!(bash.ecosystem, "redhat");
    }
}
