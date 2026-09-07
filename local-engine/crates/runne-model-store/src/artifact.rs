//! Content-addressed artifact storage: streaming into a quarantine temp
//! file, sha256, atomic rename into `blobs/<hex>`, read-only reopen.

use crate::error::StoreError;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

pub struct BlobStore {
    root: PathBuf,
}

pub struct StagedBlob {
    pub digest_hex: String,
    pub byte_len: u64,
    pub quarantine_path: PathBuf,
}

impl BlobStore {
    pub fn new(root: &Path) -> Result<Self, StoreError> {
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("quarantine"))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    pub fn quarantine_path(&self, name: &str) -> PathBuf {
        self.quarantine_dir().join(name)
    }

    /// The active `.part` quarantine file for a session name.
    pub fn quarantine_part_path(&self, name: &str) -> PathBuf {
        let mut p = self.quarantine_path(name);
        p.set_extension("part");
        p
    }

    pub fn blob_path(&self, digest_hex: &str) -> PathBuf {
        self.blobs_dir().join(digest_hex)
    }

    /// Refuses non-regular sources (symlinks, dirs, fifos) before any
    /// streaming; opens without following through the read path (the
    /// type check happens on the link target metadata).
    pub fn check_regular_file(path: &Path) -> Result<(), StoreError> {
        let meta = fs::symlink_metadata(path).map_err(StoreError::from)?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(StoreError::NonRegularFile);
        }
        Ok(())
    }

    /// Streams `source` (already positioned at its start) into a fresh
    /// quarantine file while hashing; returns digest/len/quarantine path.
    /// Caller then promotes it.
    pub fn stream_to_quarantine(
        &self,
        quarantine_name: &str,
        source: &mut (impl Read + Seek),
    ) -> Result<StagedBlob, StoreError> {
        let mut qpath = self.quarantine_path(quarantine_name);
        qpath.set_extension("part");
        let mut hasher = Sha256::new();
        let mut len: u64 = 0;
        let mut buf = [0u8; 64 * 1024];
        source.rewind().map_err(StoreError::from)?;
        loop {
            let n = source.read(&mut buf).map_err(StoreError::from)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            len += n as u64;
            // Append to quarantine (created on first chunk).
            use std::io::Write;
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&qpath)
                .map_err(StoreError::from)?;
            f.write_all(&buf[..n]).map_err(StoreError::from)?;
            f.sync_all().map_err(StoreError::from)?;
        }
        Ok(StagedBlob {
            digest_hex: hex::encode(hasher.finalize()),
            byte_len: len,
            quarantine_path: qpath,
        })
    }

    /// Atomically promotes a quarantine file into the content-addressed
    /// store (never overwrites an existing content address) and reopens
    /// read-only to force metadata durability.
    pub fn promote(&self, staged: &StagedBlob) -> Result<(), StoreError> {
        let dest = self.blob_path(&staged.digest_hex);
        if dest.exists() {
            // Identical content address already stored: keep it, drop the
            // quarantine copy.
            fs::remove_file(&staged.quarantine_path).map_err(StoreError::from)?;
            return Ok(());
        }
        fs::rename(&staged.quarantine_path, &dest).map_err(StoreError::from)?;
        OpenOptions::new()
            .read(true)
            .open(&dest)
            .map_err(StoreError::from)?
            .sync_all()
            .map_err(StoreError::from)?;
        Ok(())
    }

    /// Resumable chunk append into a quarantine file at an exact offset;
    /// returns the running sha256 over the committed prefix.
    pub fn append_chunk(
        &self,
        quarantine_name: &str,
        expected_offset: u64,
        chunk: &[u8],
    ) -> Result<(u64, String), StoreError> {
        let mut qpath = self.quarantine_path(quarantine_name);
        qpath.set_extension("part");
        let current_len = if qpath.exists() {
            fs::metadata(&qpath).map_err(StoreError::from)?.len()
        } else {
            0
        };
        if current_len != expected_offset {
            return Err(StoreError::OffsetMismatch {
                expected: current_len,
            });
        }
        use std::io::Write;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&qpath)
            .map_err(StoreError::from)?;
        f.write_all(chunk).map_err(StoreError::from)?;
        f.sync_all().map_err(StoreError::from)?;
        // Running prefix hash: re-read from zero (bounded by file size;
        // resume verification uses the committed prefix sha from the db).
        let mut file = fs::File::open(&qpath).map_err(StoreError::from)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf).map_err(StoreError::from)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let new_len = current_len + chunk.len() as u64;
        Ok((new_len, hex::encode(hasher.finalize())))
    }

    /// Verifies the committed prefix hash after a restart.
    pub fn verify_prefix(
        &self,
        quarantine_name: &str,
        committed_offset: u64,
        prefix_sha: &str,
    ) -> Result<(), StoreError> {
        let mut qpath = self.quarantine_path(quarantine_name);
        qpath.set_extension("part");
        if !qpath.exists() {
            if committed_offset == 0 {
                return Ok(());
            }
            return Err(StoreError::PrefixMismatch);
        }
        let file = fs::File::open(&qpath).map_err(StoreError::from)?;
        let mut reader = file.take(committed_offset);
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf).map_err(StoreError::from)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        if hex::encode(hasher.finalize()) != prefix_sha {
            return Err(StoreError::PrefixMismatch);
        }
        // Bytes beyond the committed offset are truncated (never trusted).
        let file = fs::File::options()
            .write(true)
            .open(&qpath)
            .map_err(StoreError::from)?;
        file.set_len(committed_offset).map_err(StoreError::from)?;
        Ok(())
    }

    pub fn delete_blob(&self, digest_hex: &str) -> Result<(), StoreError> {
        let path = self.blob_path(digest_hex);
        if path.exists() {
            fs::remove_file(path).map_err(StoreError::from)?;
        }
        Ok(())
    }
}
