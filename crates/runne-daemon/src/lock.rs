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

include!("lock/lock_set.rs");
include!("lock/filesystem.rs");
include!("lock/metadata.rs");
include!("lock/identity.rs");

#[cfg(test)]
mod tests {
    include!("lock/tests.rs");
}
