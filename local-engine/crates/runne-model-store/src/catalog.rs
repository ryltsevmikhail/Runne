//! Catalog: the durable store handle, typed records and lookups.
//! The catalog is installation metadata, never TaskRun authority.

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
    /// Pinned qualification-matrix revision; empty = unqualified
    /// install (cannot back a capability claim).
    pub matrix_revision: String,
}

/// Qualification-matrix binding pinned by `admit_qualified`
/// (Plan Task 22). Empty fields are reserved for the UNQUALIFIED path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixBinding {
    pub revision: &'static str,
    pub entry_id: &'static str,
    pub evidence_ref: &'static str,
}

impl MatrixBinding {
    /// Sentinel for plain admits without matrix qualification.
    pub const UNQUALIFIED: MatrixBinding = MatrixBinding {
        revision: "",
        entry_id: "",
        evidence_ref: "",
    };

    pub fn validate(&self) -> Result<(), crate::error::StoreError> {
        let ok = |s: &str| !s.is_empty() && s.len() <= 256;
        if ok(self.revision) && ok(self.entry_id) && ok(self.evidence_ref) {
            Ok(())
        } else {
            Err(crate::error::StoreError::Schema(
                "matrix binding fields must be non-empty".into(),
            ))
        }
    }
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

pub fn catalog_now() -> u64 {
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

    /// Deterministic order: by (model_id, model_revision, manifest_digest).
    pub fn list(&self) -> Result<Vec<InstalledModel>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT manifest_digest, model_id, model_revision, artifact_digest, byte_len,
                        active_refs, matrix_revision
                 FROM installations
                 ORDER BY model_id, model_revision, manifest_digest",
            )
            .map_err(StoreError::from)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(InstalledModel {
                    installation_id: row.get(0)?,
                    manifest_digest: row.get(0)?,
                    model_id: row.get(1)?,
                    model_revision: row.get(2)?,
                    artifact_digest: row.get(3)?,
                    byte_len: row.get::<_, i64>(4)? as u64,
                    active_refs: row.get(5)?,
                    matrix_revision: row.get(6)?,
                })
            })
            .map_err(StoreError::from)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(StoreError::from)?);
        }
        Ok(out)
    }

    pub fn get_exact_by_digest(
        &self,
        manifest_digest: &str,
    ) -> Result<Option<InstalledModel>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT manifest_digest, model_id, model_revision, artifact_digest, byte_len,
                        active_refs, matrix_revision
                 FROM installations
                 WHERE manifest_digest = ?1",
                [manifest_digest],
                |row| {
                    Ok(InstalledModel {
                        installation_id: row.get(0)?,
                        manifest_digest: row.get(0)?,
                        model_id: row.get(1)?,
                        model_revision: row.get(2)?,
                        artifact_digest: row.get(3)?,
                        byte_len: row.get::<_, i64>(4)? as u64,
                        active_refs: row.get(5)?,
                        matrix_revision: row.get(6)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        Ok(row)
    }

    pub fn get_exact(
        &self,
        model_id: &str,
        manifest_digest: &str,
    ) -> Result<Option<InstalledModel>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT manifest_digest, model_id, model_revision, artifact_digest, byte_len,
                        active_refs, matrix_revision
                 FROM installations
                 WHERE manifest_digest = ?1 AND model_id = ?2",
                rusqlite::params![manifest_digest, model_id],
                |row| {
                    Ok(InstalledModel {
                        installation_id: row.get(0)?,
                        manifest_digest: row.get(0)?,
                        model_id: row.get(1)?,
                        model_revision: row.get(2)?,
                        artifact_digest: row.get(3)?,
                        byte_len: row.get::<_, i64>(4)? as u64,
                        active_refs: row.get(5)?,
                        matrix_revision: row.get(6)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        Ok(row)
    }
}
