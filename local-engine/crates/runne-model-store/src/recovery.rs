//! Startup recovery: expired upload GC, tombstone cleanup completion,
//! orphan blob sweep. Deterministic and pathless (blob names are content
//! digests, never user input).

use crate::catalog::catalog_now;
use crate::error::StoreError;

impl crate::catalog::ModelArtifactStore {
    pub fn recover(&mut self) -> Result<RecoveryReport, StoreError> {
        let now = catalog_now();
        // 1) Expired upload sessions: drop quarantine files and rows.
        let expired: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare("SELECT artifact_digest FROM upload_sessions WHERE expires_at < ?1")?;
            let rows = stmt.query_map([now.to_string()], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)?
        };
        for digest in &expired {
            let q = self.blobs.quarantine_path(digest);
            let mut qp = q.clone();
            qp.set_extension("part");
            let _ = std::fs::remove_file(qp);
            self.conn
                .execute(
                    "DELETE FROM upload_sessions WHERE artifact_digest = ?1",
                    [digest],
                )
                .map_err(StoreError::from)?;
        }
        // 2) Tombstone cleanup completion (blob delete after crash).
        let pending: Vec<(String, String)> = {
            let mut stmt = self.conn.prepare(
                "SELECT manifest_digest, blob_ref FROM tombstones WHERE cleanup_done = 0",
            )?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(StoreError::from)?
        };
        let mut cleaned = 0usize;
        for (digest, blob_ref) in &pending {
            self.blobs.delete_blob(blob_ref)?;
            self.conn
                .execute(
                    "UPDATE tombstones SET cleanup_done = 1 WHERE manifest_digest = ?1",
                    [digest],
                )
                .map_err(StoreError::from)?;
            cleaned += 1;
        }
        // 3) Orphan blobs: present on disk, referenced by nothing.
        let mut referenced: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT blob_ref FROM candidates UNION SELECT blob_ref FROM installations",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for r in rows {
                referenced.insert(r.map_err(StoreError::from)?);
            }
        }
        let blobs_dir = self.root().join("blobs");
        let mut orphans = 0usize;
        for entry in std::fs::read_dir(blobs_dir).map_err(StoreError::from)? {
            let entry = entry.map_err(StoreError::from)?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !referenced.contains(&name) {
                std::fs::remove_file(entry.path()).map_err(StoreError::from)?;
                orphans += 1;
            }
        }
        Ok(RecoveryReport {
            expired_sessions: expired.len(),
            tombstones_cleaned: cleaned,
            orphan_blobs_removed: orphans,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    pub expired_sessions: usize,
    pub tombstones_cleaned: usize,
    pub orphan_blobs_removed: usize,
}
