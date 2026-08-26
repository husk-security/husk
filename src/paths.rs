//! The husk home directory (`~/.husk`) and shared filesystem primitives.
//!
//! Every feature that keeps durable per-user state (the trust ledger, daemon
//! state, cloud config/credentials) resolves its
//! location through [`husk_home`] so the path exists in exactly one place.
//! Strictly-local features must never depend on cloud code for their own
//! state directory; this module is the neutral home both sides share.
//! (Re-fetchable data belongs in the XDG cache directory instead; see
//! [`crate::cache`].)

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Environment override for the state directory (tests, sandboxes, CI). When
/// set and non-empty, `HUSK_HOME` replaces `~/.husk` wholesale, so a run can
/// be pointed at ephemeral state without touching the developer's real files.
pub const HOME_ENV: &str = "HUSK_HOME";

/// The husk state directory, `~/.husk` (or [`HOME_ENV`] when set). Not created
/// until first write.
pub fn husk_home() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(HOME_ENV).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    let home = dirs::home_dir().context("could not locate home directory")?;
    Ok(home.join(".husk"))
}

/// Create `dir` (and parents) if missing and enforce owner-only permissions
/// (0700 on Unix), also on a pre-existing directory, so a loosened state dir
/// is tightened again on the next use. The path must resolve to a real
/// directory; a user-managed symlink is followed (its target is what gets
/// permission-checked), matching how the credential files themselves are
/// validated per-file on read.
pub fn ensure_dir_private(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let metadata = fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    if !metadata.is_dir() {
        anyhow::bail!("{} is not a directory", dir.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("restrict permissions on {}", dir.display()))?;
        }
    }
    Ok(())
}

/// Tighten an existing file to owner-only (0600) on Unix, for files husk does
/// not create itself and so cannot open with a mode ([`write_private`] covers
/// the files it does). SQLite creates its database with the process umask, so
/// the private directory would be the only protection otherwise; a defence in
/// depth that survives the file being copied out or the directory loosened.
/// A missing file is not an error: sidecars appear only once written.
pub fn restrict_existing_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restrict permissions on {}", path.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Write `contents` to `path` atomically (unique temp file + rename), so a
/// crash or a concurrent writer can never leave a torn file behind. The
/// parent directory must already exist.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    write_exclusive(path, contents, None)
}

/// [`write_atomic`], but the rewritten file keeps `mode` instead of taking the
/// process umask. Rewriting a 0600 config must not leave it world-readable.
pub fn write_atomic_mode(path: &Path, contents: &[u8], mode: Option<u32>) -> Result<()> {
    #[cfg(unix)]
    return write_exclusive(path, contents, mode);
    #[cfg(not(unix))]
    {
        let _ = mode;
        return write_exclusive(path, contents, None);
    }
}

/// [`write_atomic`], but the file is created owner-only (0600) and verified
/// to be a freshly created regular file before any byte is written. Use for
/// credentials and other secrets. On non-Unix platforms this is a plain
/// atomic write; the user-profile directory is the protection boundary there.
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    return write_exclusive(path, contents, Some(0o600));
    #[cfg(not(unix))]
    return write_exclusive(path, contents, None);
}

/// Exclusive-create a unique temp file next to `path`, write, then rename.
/// `create_new` (O_EXCL|O_CREAT) refuses to follow a pre-placed symlink and
/// refuses to reuse a stale temp file, closing the symlink-swap TOCTOU
/// window; the unique temp name keeps concurrent writers off the same path.
/// On the rare name collision, remove the stale temp and retry.
///
/// What a crash can leave behind, once this returns: `path` holds either the
/// complete previous contents or the complete new ones, never a mix and never
/// a zero-length file, because the bytes are flushed to the device before the
/// rename publishes them. What is **not** guaranteed: that the rename itself
/// survived (the directory sync below is best effort), and nothing here says
/// anything about the durability of the underlying device's own write cache.
fn write_exclusive(path: &Path, contents: &[u8], mode: Option<u32>) -> Result<()> {
    use std::io::Write;

    let mut file = None;
    let mut temp = PathBuf::new();
    for attempt in 0..16 {
        temp = temp_path(path);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        match options.open(&temp) {
            Ok(handle) => {
                file = Some(handle);
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                // A stale temp from a crashed writer; clear it and retry with
                // a fresh unique name on the next iteration.
                let _ = fs::remove_file(&temp);
                if attempt == 15 {
                    return Err(err).with_context(|| format!("open {}", temp.display()));
                }
            }
            Err(err) => return Err(err).with_context(|| format!("open {}", temp.display())),
        }
    }
    let mut file = file.expect("temp file opened");
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        // Verify the opened descriptor refers to a freshly created regular
        // file via fstat, not a symlink target, before writing any secret
        // bytes, and re-assert the mode in case of an unusual umask.
        let metadata = file
            .metadata()
            .with_context(|| format!("stat {}", temp.display()))?;
        if !metadata.is_file() {
            anyhow::bail!(
                "{} is not a regular file after opening; refusing to write",
                temp.display()
            );
        }
        file.set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("restrict permissions on {}", temp.display()))?;
    }
    file.write_all(contents)
        .with_context(|| format!("write {}", temp.display()))?;
    // Force the bytes out before the rename makes the temp file reachable
    // under `path`. Without this the rename can be durable while its contents
    // are not, which for `husk fix` means losing the user's file *and* the
    // backup copy taken from it.
    file.sync_all()
        .with_context(|| format!("flush {}", temp.display()))?;
    drop(file);
    fs::rename(&temp, path).with_context(|| format!("rename {}", path.display()))?;
    sync_parent_dir(path);
    Ok(())
}

/// Flush the directory entry the rename created, so a crash cannot leave the
/// old name pointing at the old inode. Best effort: a failure costs the
/// durability of the *rename*, not of the data, which `sync_all` already
/// forced, and directories are not openable everywhere.
#[cfg(unix)]
fn sync_parent_dir(path: &Path) {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) {}

/// A process-unique temp path next to `path`. Combining the pid, a
/// per-process counter, and a high-resolution timestamp keeps concurrent
/// writers (and retries after a collision) on distinct paths; `create_new`
/// provides the real exclusivity guarantee.
fn temp_path(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let suffix = format!(".{}.{nonce}.{nanos}.tmp", std::process::id());
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(&suffix);
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_round_trips_and_leaves_no_temp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        write_atomic(&path, b"first").expect("write");
        write_atomic(&path, b"second").expect("overwrite");
        assert_eq!(fs::read(&path).expect("read"), b"second");
        let leftovers = fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(leftovers, 0, "no temp files left behind");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("credentials.json");
        write_private(&path, b"secret").expect("write");
        let mode = fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dir_private_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("state");
        ensure_dir_private(&target).expect("create");
        let mode = fs::metadata(&target).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dir_private_tightens_an_existing_loose_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("state");
        fs::create_dir(&target).expect("create loose");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).expect("loosen");
        ensure_dir_private(&target).expect("tighten");
        let mode = fs::metadata(&target).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "existing 0777 dir must be re-tightened"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restrict_existing_file_tightens_a_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache.db");
        fs::write(&path, b"findings").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");
        restrict_existing_file(&path).expect("tighten");
        let mode = fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // A sidecar that does not exist yet is not an error.
        restrict_existing_file(&dir.path().join("cache.db-wal")).expect("absent is fine");
    }

    #[test]
    fn ensure_dir_private_rejects_a_file_at_the_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("state");
        fs::write(&target, b"not a dir").expect("write file");
        assert!(ensure_dir_private(&target).is_err());
    }
}
