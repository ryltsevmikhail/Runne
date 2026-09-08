//! Local model source (Plan Task 15): the desktop-side bridge from the
//! file picker to the Local Engine model catalog.
//!
//! One call builds the deterministic candidate manifest from the picked
//! GGUF bytes, one call admits it after explicit license acceptance,
//! one call lists installations. No filesystem paths ever cross to the
//! renderer; all answers are metadata-only snapshots.

use runne_local_model::{BUILDER_CONTRACT_VERSION, UserSupplied, build_candidate_manifest};
use runne_model_store::{DiscardDisposition, LicenseAcceptance, ModelArtifactStore, StoreError};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Metadata-only candidate view safe for the renderer.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateView {
    pub candidate_id: String,
    pub manifest_digest: String,
    pub model_id: String,
    pub model_revision: String,
    pub license: String,
    pub artifact_digest: String,
    pub byte_len: u64,
}

/// Metadata-only installed view safe for the renderer.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledView {
    pub manifest_digest: String,
    pub model_id: String,
    pub model_revision: String,
    pub matrix_revision: String,
    pub active_refs: u32,
}

#[derive(Debug)]
pub enum LocalModelSourceError {
    /// Picked file could not be read (missing, unreadable, too large).
    SourceUnreadable,
    /// Store/Catalog authority refused (staged state, license, blob).
    Store(StoreError),
    /// Builder refused (license/provenance missing, bad GGUF, template
    /// missing, determinism floor).
    Builder(runne_local_model::BuilderError),
}

impl std::fmt::Display for LocalModelSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceUnreadable => f.write_str("picked model file is unreadable"),
            Self::Store(e) => write!(f, "catalog: {e:?}"),
            Self::Builder(e) => write!(f, "builder refused: {e}"),
        }
    }
}

impl std::error::Error for LocalModelSourceError {}

impl From<StoreError> for LocalModelSourceError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<runne_local_model::BuilderError> for LocalModelSourceError {
    fn from(e: runne_local_model::BuilderError) -> Self {
        Self::Builder(e)
    }
}

fn renderer_active_refs(active_refs: i64) -> Result<u32, LocalModelSourceError> {
    active_refs.try_into().map_err(|_| {
        LocalModelSourceError::Store(StoreError::Schema(
            "installation active reference count is outside the renderer range".to_owned(),
        ))
    })
}

/// Owner-supplied fields for one candidate build (all required except
/// the optional user chat-template file).
#[derive(Debug, Clone)]
pub struct PickerInput {
    pub model_id: String,
    pub model_revision: String,
    pub license: String,
    pub provenance_source_uri: String,
    pub provenance_publisher: String,
    pub provenance_acquired_at: String,
    pub template_path: Option<PathBuf>,
    pub min_compatible_runtime: Option<String>,
}

pub struct LocalModelSource {
    store: ModelArtifactStore,
}

impl LocalModelSource {
    /// Opens (creating on demand) the catalog rooted at `models_root`.
    ///
    /// # Errors
    ///
    /// Returns [`LocalModelSourceError::Store`] when the catalog
    /// cannot be created or opened.
    pub fn open(models_root: &Path) -> Result<Self, LocalModelSourceError> {
        Ok(Self {
            store: ModelArtifactStore::open(models_root)?,
        })
    }

    /// Picker → deterministic candidate. Reads the picked GGUF and the
    /// optional template file, builds the manifest, stages the blob.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when the source is unreadable, the
    /// builder refuses, or the catalog authority rejects the staging.
    pub fn stage_candidate(
        &mut self,
        gguf_path: &Path,
        input: &PickerInput,
    ) -> Result<CandidateView, LocalModelSourceError> {
        let mut artifact =
            std::fs::File::open(gguf_path).map_err(|_| LocalModelSourceError::SourceUnreadable)?;
        let template = input
            .template_path
            .as_ref()
            .map(|p| std::fs::read(p).map_err(|_| LocalModelSourceError::SourceUnreadable));
        let template = match template {
            Some(t) => Some(t?),
            None => None,
        };
        let user = UserSupplied {
            model_id: input.model_id.clone(),
            model_revision: input.model_revision.clone(),
            license: Some(input.license.clone()),
            provenance_source_uri: Some(input.provenance_source_uri.clone()),
            provenance_publisher: Some(input.provenance_publisher.clone()),
            provenance_acquired_at: Some(input.provenance_acquired_at.clone()),
            chat_template: template,
            min_compatible_runtime: input.min_compatible_runtime.clone(),
        };
        let candidate = build_candidate_manifest(&mut artifact, &user, BUILDER_CONTRACT_VERSION)?;
        let mut image = Vec::new();
        artifact
            .seek(SeekFrom::Start(0))
            .map_err(|_| LocalModelSourceError::SourceUnreadable)?;
        artifact
            .read_to_end(&mut image)
            .map_err(|_| LocalModelSourceError::SourceUnreadable)?;
        let staged = self.store.stage_import(
            candidate.canonical_bytes.as_slice(),
            &mut Cursor::new(image),
        )?;
        Ok(CandidateView {
            candidate_id: staged.candidate_id.clone(),
            manifest_digest: staged.manifest_digest.clone(),
            model_id: staged.model_id.clone(),
            model_revision: staged.model_revision.clone(),
            license: staged.license.clone(),
            artifact_digest: staged.artifact_digest.clone(),
            byte_len: staged.byte_len,
        })
    }

    /// Admits the staged candidate after the owner accepted the exact
    /// license text (digest is over the shown license bytes).
    ///
    /// # Errors
    ///
    /// Returns [`LocalModelSourceError::Store`] for a missing candidate,
    /// license mismatch or blob loss.
    pub fn admit(
        &mut self,
        candidate_id: &str,
        license_acceptance_digest: &str,
    ) -> Result<InstalledView, LocalModelSourceError> {
        let acceptance = LicenseAcceptance {
            license_digest: license_acceptance_digest.to_owned(),
        };
        let installed = self.store.admit(candidate_id, &acceptance)?;
        let active_refs = renderer_active_refs(installed.active_refs)?;
        Ok(InstalledView {
            manifest_digest: installed.manifest_digest,
            model_id: installed.model_id,
            model_revision: installed.model_revision,
            matrix_revision: installed.matrix_revision,
            active_refs,
        })
    }

    /// Drops a staged (not yet admitted) candidate.
    ///
    /// # Errors
    ///
    /// Returns [`LocalModelSourceError::Store`] on catalog failure.
    pub fn discard(&mut self, candidate_id: &str) -> Result<bool, LocalModelSourceError> {
        Ok(matches!(
            self.store.discard(candidate_id)?,
            DiscardDisposition::Discarded
        ))
    }

    /// Lists installed models (metadata-only snapshots).
    ///
    /// # Errors
    ///
    /// Returns [`LocalModelSourceError::Store`] on catalog failure.
    pub fn list(&self) -> Result<Vec<InstalledView>, LocalModelSourceError> {
        self.store
            .list()?
            .into_iter()
            .map(|i| -> Result<InstalledView, LocalModelSourceError> {
                Ok(InstalledView {
                    manifest_digest: i.manifest_digest,
                    model_id: i.model_id,
                    model_revision: i.model_revision,
                    matrix_revision: i.matrix_revision,
                    active_refs: renderer_active_refs(i.active_refs)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalModelSourceError, renderer_active_refs};
    use runne_model_store::StoreError;

    #[test]
    fn renderer_active_refs_rejects_database_values_outside_u32_range() {
        for active_refs in [-1, i64::from(u32::MAX) + 1] {
            assert!(matches!(
                renderer_active_refs(active_refs),
                Err(LocalModelSourceError::Store(StoreError::Schema(_)))
            ));
        }
    }
}
