//! Upload sessions: begin/append/status/finalize/cancel with exact-offset
//! checkpoints and committed-prefix hash verification (Plan Task 4).

use crate::catalog::{ImportCandidate, ModelArtifactStore};
use crate::error::StoreError;
use runne_local_model::ModelManifestV1;

pub struct UploadSession {
    pub artifact_digest: String,
    pub declared_len: u64,
    pub committed_offset: u64,
}

impl ModelArtifactStore {
    /// Verifies the manifest first (canonical, artifact digest/length
    /// declared), then opens or RESUMES a quarantine session keyed by the
    /// declared artifact digest: an existing open, unexpired session keeps
    /// its committed offset; the committed prefix hash is re-verified and
    /// the untrusted tail truncated before any resume.
    pub fn begin_stage(
        &mut self,
        manifest_bytes: &[u8],
        declared_len: u64,
        expiry_secs: u64,
    ) -> Result<UploadSession, StoreError> {
        let manifest = ModelManifestV1::parse_and_verify(manifest_bytes)?;
        let artifact = manifest
            .artifacts()
            .first()
            .ok_or(StoreError::MalformedManifest)?;
        let sha_hex = artifact
            .digest()
            .as_str()
            .strip_prefix("sha256:")
            .ok_or(StoreError::MalformedManifest)?
            .to_string();
        let now = crate::catalog_now();
        // Resume: existing open session for the same artifact digest keeps
        // its committed offset after prefix revalidation.
        let existing: Option<(i64, String, String, i64)> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT committed_offset, prefix_sha, state, expires_at
                     FROM upload_sessions WHERE artifact_digest = ?1",
                )
                .map_err(StoreError::from)?;
            let mut rows = stmt.query_map([&sha_hex], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
            rows.next().transpose().map_err(StoreError::from)?
        };
        if let Some((offset_i, prefix_sha, state, expires_i)) = existing {
            if state == "open" && expires_i as u64 > now {
                let offset = offset_i as u64;
                self.blobs.verify_prefix(&sha_hex, offset, &prefix_sha)?;
                return Ok(UploadSession {
                    artifact_digest: sha_hex,
                    declared_len,
                    committed_offset: offset,
                });
            }
            self.conn
                .execute(
                    "DELETE FROM upload_sessions WHERE artifact_digest = ?1",
                    [&sha_hex],
                )
                .map_err(StoreError::from)?;
        }
        self.conn
            .execute(
                "INSERT INTO upload_sessions(artifact_digest, declared_len,
                 committed_offset, prefix_sha, state, quarantine_path, manifest_json,
                 expires_at, created_at)
                 VALUES (?1, ?2, 0, ?3, 'open', ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    sha_hex,
                    declared_len as i64,
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    self.blobs.quarantine_path(&sha_hex).to_string_lossy(),
                    String::from_utf8_lossy(manifest_bytes).to_string(),
                    (now + expiry_secs).to_string(),
                    now.to_string(),
                ],
            )
            .map_err(StoreError::from)?;
        Ok(UploadSession {
            artifact_digest: sha_hex,
            declared_len,
            committed_offset: 0,
        })
    }

    /// Appends at the exact committed offset: re-validates the committed
    /// prefix before extending, checkpoint advances only after the chunk
    /// is durable and the new full-content hash recorded.
    pub fn append_stage(
        &mut self,
        session: &mut UploadSession,
        exact_offset: u64,
        chunk: &[u8],
    ) -> Result<u64, StoreError> {
        let (committed, prefix): (i64, String) = self
            .conn
            .query_row(
                "SELECT committed_offset, prefix_sha FROM upload_sessions
                 WHERE artifact_digest = ?1 AND state = 'open'",
                [&session.artifact_digest],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| StoreError::SessionMissing)?;
        if committed != exact_offset as i64 {
            return Err(StoreError::OffsetMismatch {
                expected: committed as u64,
            });
        }
        self.blobs
            .verify_prefix(&session.artifact_digest, exact_offset, &prefix)?;
        let (new_offset, new_prefix) =
            self.blobs
                .append_chunk(&session.artifact_digest, exact_offset, chunk)?;
        self.conn
            .execute(
                "UPDATE upload_sessions SET committed_offset = ?1, prefix_sha = ?2
                 WHERE artifact_digest = ?3",
                rusqlite::params![new_offset as i64, new_prefix, session.artifact_digest],
            )
            .map_err(StoreError::from)?;
        session.committed_offset = new_offset;
        Ok(new_offset)
    }

    /// Finalizes: digest must match the declared manifest artifact; runs
    /// bounded GGUF inspection; publishes the staged candidate via the
    /// normal import path (admission still gated separately).
    pub fn finalize_stage(
        &mut self,
        session: &UploadSession,
    ) -> Result<ImportCandidate, StoreError> {
        let manifest_json: String = self
            .conn
            .query_row(
                "SELECT manifest_json FROM upload_sessions WHERE artifact_digest = ?1",
                [&session.artifact_digest],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::SessionMissing)?;
        let artifact_len = session.committed_offset;
        // Promote quarantine to blob (digest computed from content).
        let staged = self.blobs.stream_to_quarantine(
            &format!("finalize-{}", session.artifact_digest),
            &mut std::fs::File::open(self.blobs.quarantine_part_path(&session.artifact_digest))
                .map_err(StoreError::from)?,
        )?;
        if staged.byte_len != artifact_len || staged.byte_len != session.declared_len {
            return Err(StoreError::LengthMismatch);
        }
        if staged.digest_hex != session.artifact_digest {
            eprintln!(
                "FIN DBG staged={} want={} len={} declared={}",
                staged.digest_hex, session.artifact_digest, staged.byte_len, session.declared_len
            );
            return Err(StoreError::DigestMismatch);
        }
        // Bounded GGUF inspection before publication.
        let mut image = Vec::with_capacity(staged.byte_len as usize);
        let mut f = std::fs::File::open(&staged.quarantine_path).map_err(StoreError::from)?;
        std::io::Read::read_to_end(&mut f, &mut image).map_err(StoreError::from)?;
        runne_local_model::gguf::inspect(&image)?;
        self.blobs.promote(&staged)?;
        self.conn
            .execute(
                "UPDATE upload_sessions SET state = 'finalized' WHERE artifact_digest = ?1",
                [&session.artifact_digest],
            )
            .map_err(StoreError::from)?;
        let mut content = std::io::Cursor::new(image);
        self.stage_import(manifest_json.as_bytes(), &mut content)
    }

    pub fn cancel_stage(&mut self, session: &UploadSession) -> Result<(), StoreError> {
        let _ = std::fs::remove_file(self.blobs.quarantine_part_path(&session.artifact_digest));
        self.conn
            .execute(
                "DELETE FROM upload_sessions WHERE artifact_digest = ?1",
                [&session.artifact_digest],
            )
            .map_err(StoreError::from)?;
        Ok(())
    }
}
