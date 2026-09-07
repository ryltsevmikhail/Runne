//! The durable store handle: SQLite catalog + content-addressed blob
//! storage. The catalog is installation metadata, never TaskRun
//! authority.

use crate::artifact::BlobStore;
use crate::error::StoreError;
use crate::schema;
use rusqlite::Connection;
use std::path::{Path, PathBuf};

pub struct ModelArtifactStore {
    pub(crate) conn: Connection,
    pub(crate) blobs: BlobStore,
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportCandidate {
    pub candidate_id: String, // manifest digest
    pub manifest_digest: String,
    pub model_id: String,
    pub model_revision: String,
    pub license: String,
    pub capabilities_summary: String,
    pub artifact_digest: String,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledModel {
    pub installation_id: String, // manifest digest
    pub manifest_digest: String,
    pub model_id: String,
    pub model_revision: String,
    pub artifact_digest: String,
    pub byte_len: u64,
    pub active_refs: i64,
}

pub struct LicenseAcceptance {
    /// sha256 over the exact license string shown and accepted.
    pub license_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardDisposition {
    Discarded,
    AlreadyDiscarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveDisposition {
    Removed,
    CleanupPending,
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl ModelArtifactStore {
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(root)?;
        let conn = Connection::open(root.join("catalog.db"))?;
        schema::init(&conn)?;
        schema::check_version(&conn)?;
        let blobs = BlobStore::new(root)?;
        Ok(Self {
            conn,
            blobs,
            root: root.to_path_buf(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Catalog access for store-owned tooling (recovery, diagnostics).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}
