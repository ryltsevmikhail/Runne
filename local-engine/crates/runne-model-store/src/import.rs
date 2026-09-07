//! Import pipeline: verified manifest + streamed artifact → staged
//! candidate → admitted installation (exactly-once, transactional).

use crate::catalog::MatrixBinding;
use crate::catalog::{
    DiscardDisposition, ImportCandidate, InstalledModel, LicenseAcceptance, ModelArtifactStore,
    catalog_now,
};
use crate::error::StoreError;

fn license_digest(license: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(license.as_bytes()))
}

impl ModelArtifactStore {
    /// Full streaming import: verified manifest + one streamed artifact →
    /// a staged candidate (digest/length/GGUF enforced; no inference of
    /// authority from filenames or arbitrary GGUF metadata).
    pub fn stage_import(
        &mut self,
        manifest_bytes: &[u8],
        artifact_source: &mut (impl std::io::Read + std::io::Seek),
    ) -> Result<ImportCandidate, StoreError> {
        let manifest = runne_local_model::ModelManifestV1::parse_and_verify(manifest_bytes)?;
        // Profile allowlist: at least one known Phase 1 profile.
        let known = manifest
            .compatibility()
            .backend_profiles()
            .iter()
            .any(|p| p.id() == "llama-cpp-cpu-macos-arm64-v1");
        if !known {
            return Err(StoreError::UnqualifiedProfile);
        }
        let artifact = manifest
            .artifacts()
            .first()
            .ok_or(StoreError::MalformedManifest)?;
        let staged = self
            .blobs
            .stream_to_quarantine(manifest.manifest_id(), artifact_source)?;
        eprintln!(
            "LEN DEBUG declared={} staged={}",
            artifact.byte_length(),
            staged.byte_len
        );
        if staged.byte_len != artifact.byte_length() {
            let _ = self.blobs.delete_blob(&staged.digest_hex);
            let _ = std::fs::remove_file(&staged.quarantine_path);
            return Err(StoreError::LengthMismatch);
        }
        if format!("sha256:{}", staged.digest_hex) != artifact.digest().as_str() {
            let _ = std::fs::remove_file(&staged.quarantine_path);
            return Err(StoreError::DigestMismatch);
        }
        // Bounded GGUF inspection before catalog publication.
        let file = std::fs::File::open(&staged.quarantine_path).map_err(StoreError::from)?;
        let mut image = Vec::with_capacity(staged.byte_len as usize);
        let mut f = file;
        std::io::Read::read_to_end(&mut f, &mut image).map_err(StoreError::from)?;
        runne_local_model::gguf::inspect(&image)?;
        self.blobs.promote(&staged)?;

        let manifest_digest = manifest
            .manifest_id()
            .rsplit(':')
            .next()
            .unwrap_or("")
            .to_string();
        let capabilities_summary = format!(
            "modalities={:?},streaming={},tools={}",
            manifest.capabilities().modalities(),
            manifest.capabilities().streaming(),
            manifest.capabilities().tools()
        );
        let tx = self.conn.unchecked_transaction()?;
        // Idempotent replay: same identity returns the existing candidate.
        let existing: Option<String> = tx
            .query_row(
                "SELECT state FROM candidates WHERE manifest_digest = ?1",
                [&manifest_digest],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        if existing.is_some() {
            tx.commit().map_err(StoreError::from)?;
            return Ok(ImportCandidate {
                candidate_id: manifest_digest.clone(),
                manifest_digest: manifest_digest.clone(),
                model_id: manifest.model_id().to_string(),
                model_revision: manifest.model_revision().to_string(),
                license: manifest.license().to_string(),
                capabilities_summary,
                artifact_digest: format!("sha256:{}", staged.digest_hex),
                byte_len: staged.byte_len,
            });
        }
        tx.execute(
            "INSERT INTO candidates(manifest_digest, manifest_json, model_id, model_revision,
             license, artifact_digest, byte_len, blob_ref, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'staged', ?9)",
            rusqlite::params![
                manifest_digest,
                String::from_utf8_lossy(manifest_bytes).to_string(),
                manifest.model_id(),
                manifest.model_revision(),
                manifest.license(),
                format!("sha256:{}", staged.digest_hex),
                staged.byte_len as i64,
                staged.digest_hex,
                catalog_now().to_string(),
            ],
        )
        .map_err(StoreError::from)?;
        tx.commit().map_err(StoreError::from)?;
        Ok(ImportCandidate {
            candidate_id: manifest_digest.clone(),
            manifest_digest,
            model_id: manifest.model_id().to_string(),
            model_revision: manifest.model_revision().to_string(),
            license: manifest.license().to_string(),
            capabilities_summary,
            artifact_digest: format!("sha256:{}", staged.digest_hex),
            byte_len: staged.byte_len,
        })
    }

    /// Publishes the immutable installation after explicit matching
    /// license acceptance (exactly-once, transactional).
    pub fn admit(
        &mut self,
        candidate_id: &str,
        acceptance: &LicenseAcceptance,
    ) -> Result<InstalledModel, StoreError> {
        self.admit_inner(candidate_id, acceptance, None)
    }

    /// Admits with a qualification-matrix binding pinned on the
    /// admission record (Plan Task 22). An unqualified install cannot
    /// back a capability claim; the binding is immutable — a revision
    /// bump on the same digest is an AdmissionConflict (traceable).
    pub fn admit_qualified(
        &mut self,
        candidate_id: &str,
        acceptance: &LicenseAcceptance,
        binding: &MatrixBinding,
    ) -> Result<InstalledModel, StoreError> {
        binding.validate()?;
        self.admit_inner(candidate_id, acceptance, Some(binding))
    }

    fn admit_inner(
        &mut self,
        candidate_id: &str,
        acceptance: &LicenseAcceptance,
        binding: Option<&MatrixBinding>,
    ) -> Result<InstalledModel, StoreError> {
        // Exactly-once: an existing installation with this identity is an
        // admission conflict, regardless of candidate state.
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT manifest_digest FROM installations WHERE manifest_digest = ?1",
                [candidate_id],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        if existing.is_some() {
            return Err(StoreError::AdmissionConflict);
        }
        let (license, artifact_digest, byte_len, blob_ref, model_id, model_revision): (
            String,
            String,
            i64,
            String,
            String,
            String,
        ) = self
            .conn
            .query_row(
                "SELECT license, artifact_digest, byte_len, blob_ref, model_id, model_revision
                 FROM candidates WHERE manifest_digest = ?1 AND state = 'staged'",
                [candidate_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(|_| StoreError::CandidateNotStaged)?;
        if license_digest(&license) != acceptance.license_digest {
            return Err(StoreError::LicenseMismatch);
        }
        if !self.blobs.blob_path(&blob_ref).exists() {
            return Err(StoreError::BlobMissing);
        }
        let tx = self.conn.unchecked_transaction()?;
        let empty = MatrixBinding::UNQUALIFIED;
        let b = binding.unwrap_or(&empty);
        tx.execute(
            "INSERT INTO installations(manifest_digest, model_id, model_revision, license,
             artifact_digest, byte_len, blob_ref, active_refs, license_acceptance_digest, admitted_at,
             matrix_revision, matrix_entry_id, matrix_evidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                candidate_id,
                model_id,
                model_revision,
                license,
                artifact_digest,
                byte_len,
                blob_ref,
                acceptance.license_digest,
                catalog_now().to_string(),
                b.revision,
                b.entry_id,
                b.evidence_ref,
            ],
        )
        .map_err(StoreError::from)?;
        tx.execute(
            "DELETE FROM candidates WHERE manifest_digest = ?1",
            [candidate_id],
        )
        .map_err(StoreError::from)?;
        tx.commit().map_err(StoreError::from)?;
        Ok(InstalledModel {
            installation_id: candidate_id.to_string(),
            manifest_digest: candidate_id.to_string(),
            model_id,
            model_revision,
            artifact_digest,
            byte_len: byte_len as u64,
            active_refs: 0,
            matrix_revision: b.revision.to_string(),
        })
    }

    pub fn discard(&mut self, candidate_id: &str) -> Result<DiscardDisposition, StoreError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM candidates WHERE manifest_digest = ?1 AND state = 'staged'",
                [candidate_id],
            )
            .map_err(StoreError::from)?;
        Ok(if n > 0 {
            DiscardDisposition::Discarded
        } else {
            DiscardDisposition::AlreadyDiscarded
        })
    }
}
