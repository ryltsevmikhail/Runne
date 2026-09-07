//! Safe removal: refuse active references, transactional catalog removal,
//! then content-addressed blob deletion (recoverable, pathless).

use crate::catalog::RemoveDisposition;
use crate::catalog::catalog_now;
use crate::error::StoreError;

impl crate::catalog::ModelArtifactStore {
    pub fn remove(&mut self, installation_id: &str) -> Result<RemoveDisposition, StoreError> {
        let (active_refs, blob_ref): (i64, String) = self
            .conn
            .query_row(
                "SELECT active_refs, blob_ref FROM installations WHERE manifest_digest = ?1",
                [installation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| StoreError::CandidateMissing)?;
        if active_refs > 0 {
            return Err(StoreError::ActiveReferences);
        }
        let tx = self.conn.unchecked_transaction()?;
        let deleted = tx
            .execute(
                "DELETE FROM installations WHERE manifest_digest = ?1 AND active_refs = 0",
                [installation_id],
            )
            .map_err(StoreError::from)?;
        if deleted == 0 {
            return Err(StoreError::ActiveReferences);
        }
        tx.execute(
            "INSERT INTO tombstones(manifest_digest, blob_ref, cleanup_done, removed_at)
             VALUES (?1, ?2, 0, ?3)",
            rusqlite::params![installation_id, blob_ref, catalog_now().to_string()],
        )
        .map_err(StoreError::from)?;
        tx.commit().map_err(StoreError::from)?;
        // Blob deletion after commit; interrupted cleanup is recovered by
        // recovery::cleanup_tombstones on next open.
        self.blobs.delete_blob(&blob_ref)?;
        self.conn
            .execute(
                "UPDATE tombstones SET cleanup_done = 1 WHERE manifest_digest = ?1",
                [installation_id],
            )
            .map_err(StoreError::from)?;
        Ok(RemoveDisposition::Removed)
    }
}
