//! Three-layer lock system for daemon instance protection.
//!
//! ## Lock hierarchy (acquisition order):
//! 1. **Provisional path lock** — `sha256(canonical_path)` — serializes first-start
//!    and token side effects. Acquired *before* DB open.
//! 2. **File identity lock** — `sha256(platform_file_identity)` — guards against
//!    hardlink/rename aliases. Acquired *after* no-follow DB verify handle.
//! 3. **Authority lock** — `sha256(authority_id)` — guards separate copies of the
//!    same Event Log. Acquired *after* reading `_authority` from schema v7 DB.
//!
//! ## Lock metadata format (25 bytes, written into path-lock file):
//! ```text
//! [version: u8] [length: u32 LE] [payload: 16 bytes] [crc32: u32 LE]
//! ```
//! `length` is always 16. `crc32` covers version + length + payload.

use crate::error::DaemonError;
use fs2::FileExt;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// ── Platform constants ────────────────────────────────────────────────

#[cfg(target_os = "macos")]
pub const O_NOFOLLOW_VAL: i32 = 0x0100;

#[cfg(all(target_os = "linux", not(target_os = "macos")))]
pub const O_NOFOLLOW_VAL: i32 = 0o400000; // 0x20000

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const O_NOFOLLOW_VAL: i32 = 0;

#[cfg(unix)]
const O_CLOEXEC: i32 = 0x1000000; // 0o2000000

// ── LockGuard ─────────────────────────────────────────────────────────

/// A held exclusive file lock.
///
/// The lock is released when the guard is dropped (the file descriptor is
/// closed). `LockGuard` is not `Clone` — at most one guard exists per lock file.
#[derive(Debug)]
pub struct LockGuard(std::fs::File);

impl LockGuard {
    /// Create a guard wrapping an already-locked file.
    fn new(file: std::fs::File) -> Self {
        Self(file)
    }

    /// Borrow the underlying file handle for metadata I/O.
    pub fn file(&self) -> &std::fs::File {
        &self.0
    }
}

// ── Metadata snapshot ─────────────────────────────────────────────────

/// The result of reading lock metadata from the path-lock file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataSnapshot {
    /// File is exactly 0 bytes — no previous daemon wrote metadata.
    Empty,
    /// Valid metadata record. Contains the authority_id.
    Valid { authority_id: [u8; 16] },
    /// Non-empty file with an invalid record — torn write, corruption, or
    /// old format.
    Malformed,
}

// ── Lock metadata (on-disk format) ────────────────────────────────────

/// The 25-byte lock metadata record stored inside the path-lock file.
struct LockMetadata {
    authority_id: [u8; 16],
}

impl LockMetadata {
    /// Total record size in bytes.
    const RECORD_SIZE: usize = 25;
    /// Constant payload length.
    const PAYLOAD_LEN: u32 = 16;
    /// Current format version.
    const VERSION: u8 = 1;

    /// Serialise to 25 bytes: `version || length(LE) || payload || crc32(LE)`.
    fn to_bytes(&self) -> [u8; Self::RECORD_SIZE] {
        let mut buf = [0u8; Self::RECORD_SIZE];
        buf[0] = Self::VERSION;
        buf[1..5].copy_from_slice(&Self::PAYLOAD_LEN.to_le_bytes());
        buf[5..21].copy_from_slice(&self.authority_id);
        let crc = crc32(&buf[0..21]);
        buf[21..25].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Deserialise from 25 bytes. Returns `None` if the record is invalid.
    fn from_bytes(data: &[u8; Self::RECORD_SIZE]) -> Option<Self> {
        // Check version
        if data[0] != Self::VERSION {
            return None;
        }
        // Check length field
        let stored_len = u32::from_le_bytes(data[1..5].try_into().unwrap());
        if stored_len != Self::PAYLOAD_LEN {
            return None;
        }
        // Verify CRC
        let stored_crc = u32::from_le_bytes(data[21..25].try_into().unwrap());
        let computed_crc = crc32(&data[0..21]);
        if stored_crc != computed_crc {
            return None;
        }
        let mut authority_id = [0u8; 16];
        authority_id.copy_from_slice(&data[5..21]);
        Some(Self { authority_id })
    }
}

// ── LockSet ───────────────────────────────────────────────────────────

/// The three-layer lock set for a daemon instance.
///
/// Acquire order: path → (open DB →) file → (read authority →) authority.
/// All locks are held until `LockSet` is dropped.
#[derive(Debug)]
pub struct LockSet {
    /// Provisional path lock — always present.
    pub path_lock: LockGuard,
    /// File identity lock — `None` until DB is opened and verified.
    pub file_lock: Option<LockGuard>,
    /// Authority lock — `None` until `_authority` is read from DB.
    pub authority_lock: Option<LockGuard>,
}

impl LockSet {
    // ── Step 1: acquire path lock ─────────────────────────────────

    /// Acquire the provisional path lock.
    ///
    /// `db_path` is the raw path from configuration (may contain symlinks).
    /// `runtime_dir` is where `gocode-daemon/` lock files are stored.
    ///
    /// This must be the first lock acquired — before the DB is opened.
    pub fn acquire_path(db_path: &Path, runtime_dir: &Path) -> Result<Self, DaemonError> {
        let canonical = canonicalize_path(db_path)?;
        let path_hash = sha256_hex(canonical.to_str().unwrap_or("").as_bytes());
        let lock_dir = runtime_dir.join("gocode-daemon");
        let lock_path = lock_dir.join(format!("path-{path_hash}.lock"));

        fs::create_dir_all(&lock_dir)
            .map_err(|e| DaemonError::Lock(format!("failed to create lock directory: {e}")))?;

        let file = open_or_create_lockfile(&lock_path)?;

        file.try_lock_exclusive().map_err(|e| {
            DaemonError::Lock(format!(
                "failed to acquire exclusive lock on {path}: {e}",
                path = lock_path.display()
            ))
        })?;

        Ok(Self {
            path_lock: LockGuard::new(file),
            file_lock: None,
            authority_lock: None,
        })
    }

    // ── Metadata I/O on the path lock ────────────────────────────

    /// Read the metadata snapshot from the path-lock file.
    ///
    /// Reads exactly 25 bytes (or detects empty/malformed state).
    /// Called **before** opening the DB to determine startup scenario.
    pub fn read_metadata_snapshot(&self) -> Result<MetadataSnapshot, DaemonError> {
        read_lock_metadata(self.path_lock.file())
    }

    /// Write authority metadata into the path-lock file.
    ///
    /// Uses `set_len(0)` + `write_all` + `sync_all` for atomic-like update.
    pub fn write_metadata(&self, authority_id: &[u8; 16]) -> Result<(), DaemonError> {
        let metadata = LockMetadata {
            authority_id: *authority_id,
        };
        write_lock_metadata(self.path_lock.file(), &metadata)
    }

    // ── Step 2: acquire file identity lock ───────────────────────

    /// Acquire the file identity lock.
    ///
    /// Must be called **after** obtaining a no-follow verify handle to the DB.
    /// Uses the platform-level file identity (inode/volume on Unix;
    /// volume serial + file ID on Windows) to detect hardlink/rename aliases.
    pub fn acquire_file_lock(
        &mut self,
        db_handle: &std::fs::File,
        runtime_dir: &Path,
    ) -> Result<(), DaemonError> {
        let identity = platform_file_identity(db_handle)?;
        let file_hash = sha256_hex(identity.as_bytes());
        let lock_dir = runtime_dir.join("gocode-daemon");
        let lock_path = lock_dir.join(format!("file-{file_hash}.lock"));

        let file = open_or_create_lockfile(&lock_path)?;
        file.try_lock_exclusive()
            .map_err(|e| DaemonError::Lock(format!("failed to acquire file identity lock: {e}")))?;

        self.file_lock = Some(LockGuard::new(file));
        Ok(())
    }

    // ── Step 3: acquire authority lock ───────────────────────────

    /// Acquire the authority lock.
    ///
    /// Must be called **after** reading `_authority` from a schema v7 DB (or
    /// generating it for a new DB). Uses the authority_id to guard separate
    /// copies of the same Event Log.
    pub fn acquire_authority_lock(
        &mut self,
        authority_id: &[u8; 16],
        runtime_dir: &Path,
    ) -> Result<(), DaemonError> {
        let auth_hash = sha256_hex(authority_id);
        let lock_dir = runtime_dir.join("gocode-daemon");
        let lock_path = lock_dir.join(format!("authority-{auth_hash}.lock"));

        let file = open_or_create_lockfile(&lock_path)?;
        file.try_lock_exclusive()
            .map_err(|e| DaemonError::Lock(format!("failed to acquire authority lock: {e}")))?;

        self.authority_lock = Some(LockGuard::new(file));
        Ok(())
    }
}

// ── Lockfile open/create with platform no-follow safety ────────────────

/// Open or atomically create a lock file with platform-appropriate no-follow
/// guarantees.
///
/// - If the file exists: open for read+write, verify it is a regular file
///   (not a symlink/reparse point).
/// - If the file does not exist: `create_new` to atomically ensure we're the
///   sole creator.
fn open_or_create_lockfile(path: &Path) -> Result<std::fs::File, DaemonError> {
    match create_no_follow(path) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = open_existing_no_follow(path)?;
            verify_regular_file(&file, path)?;
            Ok(file)
        }
        Err(e) => Err(DaemonError::Lock(format!(
            "failed to create lock file {path}: {e}",
            path = path.display()
        ))),
    }
}

/// Open existing lock file with no-follow, read+write.
fn open_existing_no_follow(path: &Path) -> Result<std::fs::File, DaemonError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(false);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NOFOLLOW_VAL | O_CLOEXEC);
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    let file = opts.open(path).map_err(|e| {
        DaemonError::Lock(format!(
            "failed to open existing lock file {path}: {e}",
            path = path.display()
        ))
    })?;

    #[cfg(windows)]
    {
        verify_not_reparse_point(&file, path)?;
    }

    Ok(file)
}

/// Atomically create a new lock file with no-follow.
fn create_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[allow(clippy::useless_conversion)]
        opts.custom_flags(if O_NOFOLLOW_VAL != 0 {
            O_NOFOLLOW_VAL | O_CLOEXEC
        } else {
            O_CLOEXEC
        });
        let file = opts.open(path)?;
        // Set permissions to 0600 on new file
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o600);
        let _ = file.set_permissions(perm);
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        opts.open(path)
    }
}

// ── File verification ─────────────────────────────────────────────────

/// Verify `file` is a regular file.
fn verify_regular_file(file: &std::fs::File, path: &Path) -> Result<(), DaemonError> {
    let meta = file.metadata().map_err(|e| {
        DaemonError::Lock(format!(
            "failed to read metadata of {path}: {e}",
            path = path.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(DaemonError::Lock(format!(
            "lock file {path} is not a regular file",
            path = path.display()
        )));
    }
    Ok(())
}

/// On Windows, verify the opened file is NOT a reparse point.
#[cfg(windows)]
fn verify_not_reparse_point(file: &std::fs::File, path: &Path) -> Result<(), DaemonError> {
    use std::os::windows::fs::MetadataExt;
    let meta = file.metadata().map_err(|e| {
        DaemonError::Lock(format!(
            "failed to read metadata of {path}: {e}",
            path = path.display()
        ))
    })?;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DaemonError::Lock(format!(
            "lock file {path} is a reparse point — rejected",
            path = path.display()
        )));
    }
    Ok(())
}

// ── Metadata I/O ──────────────────────────────────────────────────────

/// Read the 25-byte metadata record from a lock file.
///
/// Reads from the beginning of the file. Returns `Empty` for zero-length
/// files, `Malformed` for non-zero-length files that don't contain exactly
/// 25 bytes or have an invalid record.
fn read_lock_metadata(file: &std::fs::File) -> Result<MetadataSnapshot, DaemonError> {
    let meta = file
        .metadata()
        .map_err(|e| DaemonError::Lock(format!("failed to read lock file metadata: {e}")))?;

    let len = meta.len();
    if len == 0 {
        return Ok(MetadataSnapshot::Empty);
    }

    if len != LockMetadata::RECORD_SIZE as u64 {
        return Ok(MetadataSnapshot::Malformed);
    }

    // Seek to beginning and read exactly 25 bytes.
    // &File implements Seek since Rust 1.51.
    (&*file)
        .seek(SeekFrom::Start(0))
        .map_err(|e| DaemonError::Lock(format!("failed to seek lock file: {e}")))?;

    let mut buf = [0u8; LockMetadata::RECORD_SIZE];
    (&*file)
        .read_exact(&mut buf)
        .map_err(|e| DaemonError::Lock(format!("failed to read lock metadata: {e}")))?;

    match LockMetadata::from_bytes(&buf) {
        Some(meta) => Ok(MetadataSnapshot::Valid {
            authority_id: meta.authority_id,
        }),
        None => Ok(MetadataSnapshot::Malformed),
    }
}

/// Write metadata to a lock file.
///
/// Truncates the file, writes the 25-byte record, and syncs to disk.
fn write_lock_metadata(file: &std::fs::File, metadata: &LockMetadata) -> Result<(), DaemonError> {
    file.set_len(0)
        .map_err(|e| DaemonError::Lock(format!("failed to truncate lock file: {e}")))?;

    (&*file)
        .seek(SeekFrom::Start(0))
        .map_err(|e| DaemonError::Lock(format!("failed to seek lock file: {e}")))?;

    let bytes = metadata.to_bytes();
    (&*file)
        .write_all(&bytes)
        .map_err(|e| DaemonError::Lock(format!("failed to write lock metadata: {e}")))?;

    (&*file)
        .flush()
        .map_err(|e| DaemonError::Lock(format!("failed to flush lock metadata: {e}")))?;

    file.sync_all()
        .map_err(|e| DaemonError::Lock(format!("failed to sync lock file: {e}")))?;

    Ok(())
}

// ── Platform-independent helpers ──────────────────────────────────────

/// Canonicalise a path, resolving all symlinks.
fn canonicalize_path(path: &Path) -> Result<PathBuf, DaemonError> {
    fs::canonicalize(path).map_err(|e| {
        DaemonError::Lock(format!(
            "failed to canonicalise path {path}: {e}",
            path = path.display()
        ))
    })
}

/// Get a platform-level file identity string.
///
/// Unix: `"{dev}:{ino}"` (device + inode).
/// Windows: `"{vol_serial}:{file_id}"` (volume serial + file ID).
fn platform_file_identity(file: &std::fs::File) -> Result<String, DaemonError> {
    let meta = file
        .metadata()
        .map_err(|e| DaemonError::Lock(format!("failed to read file metadata: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dev = meta.dev();
        let ino = meta.ino();
        Ok(format!("{dev}:{ino}"))
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let vol_serial = meta.volume_serial_number();
        let file_index = meta.file_index();
        Ok(format!("{vol_serial}:{file_index}"))
    }
}

/// CRC32 checksum (IEEE 802.3 / gzip / CRC32fast).
fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// SHA-256 hex digest.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a runtime dir with an empty gocode-daemon subdir.
    fn runtime_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("gocode-daemon")).unwrap();
        dir
    }

    /// Helper: create a dummy file (act as DB path).
    fn dummy_db_file(dir: &TempDir) -> PathBuf {
        let path = dir.path().join("event-log.db");
        fs::File::create(&path).unwrap();
        path
    }

    #[test]
    fn acquire_path_creates_lock() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let locks = LockSet::acquire_path(&db, rt.path()).unwrap();
        // Check the lock file was created
        let canonical = canonicalize_path(&db).unwrap();
        let hash = sha256_hex(canonical.to_str().unwrap().as_bytes());
        let lock_path = rt
            .path()
            .join("gocode-daemon")
            .join(format!("path-{hash}.lock"));
        assert!(lock_path.exists());
        // Metadata should be Empty (new file, no write yet)
        let snap = locks.read_metadata_snapshot().unwrap();
        assert_eq!(snap, MetadataSnapshot::Empty);
    }

    #[test]
    fn acquire_path_conflict() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let _locks1 = LockSet::acquire_path(&db, rt.path()).unwrap();
        let result2 = LockSet::acquire_path(&db, rt.path());
        assert!(result2.is_err());
        let msg = format!("{}", result2.unwrap_err());
        assert!(
            msg.contains("lock error") || msg.contains("WouldBlock") || msg.contains("resource"),
            "got: {msg}"
        );
    }

    #[test]
    fn read_metadata_empty() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let locks = LockSet::acquire_path(&db, rt.path()).unwrap();
        let snap = locks.read_metadata_snapshot().unwrap();
        assert_eq!(snap, MetadataSnapshot::Empty);
    }

    #[test]
    fn write_and_read_metadata() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let locks = LockSet::acquire_path(&db, rt.path()).unwrap();
        let aid: [u8; 16] = [0xAA; 16];
        locks.write_metadata(&aid).unwrap();
        let snap = locks.read_metadata_snapshot().unwrap();
        assert_eq!(snap, MetadataSnapshot::Valid { authority_id: aid });
    }

    #[test]
    fn metadata_different_paths_independent() {
        let rt = runtime_dir();
        let db1 = rt.path().join("db1.db");
        fs::File::create(&db1).unwrap();
        let db2 = rt.path().join("db2.db");
        fs::File::create(&db2).unwrap();

        let locks1 = LockSet::acquire_path(&db1, rt.path()).unwrap();
        let locks2 = LockSet::acquire_path(&db2, rt.path()).unwrap();

        // Different locks should have different lock files
        let c1 = canonicalize_path(&db1).unwrap();
        let c2 = canonicalize_path(&db2).unwrap();
        assert_ne!(c1, c2);

        // Both should be Empty
        assert_eq!(
            locks1.read_metadata_snapshot().unwrap(),
            MetadataSnapshot::Empty
        );
        assert_eq!(
            locks2.read_metadata_snapshot().unwrap(),
            MetadataSnapshot::Empty
        );
    }

    #[test]
    fn file_identity_lock() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let mut locks = LockSet::acquire_path(&db, rt.path()).unwrap();

        let file = fs::File::open(&db).unwrap();
        locks.acquire_file_lock(&file, rt.path()).unwrap();
        assert!(locks.file_lock.is_some());
    }

    #[test]
    fn authority_lock() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let mut locks = LockSet::acquire_path(&db, rt.path()).unwrap();

        let aid: [u8; 16] = [0xBB; 16];
        locks.acquire_authority_lock(&aid, rt.path()).unwrap();
        assert!(locks.authority_lock.is_some());
    }

    #[test]
    fn malformed_metadata_detected() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);
        let locks = LockSet::acquire_path(&db, rt.path()).unwrap();

        // Write garbage to the lock file (simulate torn write)
        use std::io::Write;
        let mut file = locks.path_lock.file();
        file.set_len(0).unwrap();
        (&*file).seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&[0xFFu8; 25]).unwrap();
        file.sync_all().unwrap();

        let snap = locks.read_metadata_snapshot().unwrap();
        assert_eq!(snap, MetadataSnapshot::Malformed);
    }

    #[test]
    fn lock_released_on_drop() {
        let rt = runtime_dir();
        let db = dummy_db_file(&rt);

        {
            let _locks = LockSet::acquire_path(&db, rt.path()).unwrap();
        }
        // Should be able to re-acquire after drop
        let locks2 = LockSet::acquire_path(&db, rt.path());
        assert!(locks2.is_ok());
    }

    #[test]
    fn concurrent_lock_conflict() {
        use std::thread;

        let rt = runtime_dir();
        let db = dummy_db_file(&rt);

        let _locks = LockSet::acquire_path(&db, rt.path()).unwrap();

        let rt_path = rt.path().to_path_buf();
        let db_path = db.clone();

        let handle = thread::spawn(move || LockSet::acquire_path(&db_path, &rt_path));

        let result = handle.join().unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn hardlink_same_identity() {
        let rt = runtime_dir();
        let db1 = rt.path().join("original.db");
        fs::File::create(&db1).unwrap();
        let db2 = rt.path().join("hardlink.db");

        // Create hardlink
        fs::hard_link(&db1, &db2).unwrap();

        let f1 = fs::File::open(&db1).unwrap();
        let f2 = fs::File::open(&db2).unwrap();

        let id1 = platform_file_identity(&f1).unwrap();
        let id2 = platform_file_identity(&f2).unwrap();

        assert_eq!(
            id1, id2,
            "hardlinked files must have the same platform identity"
        );
    }
}
