// Local Engine model management commands (Plan Task 15): stage a
// picked GGUF through the deterministic builder, admit after explicit
// license acceptance, list installations, discard a staged candidate.
// All answers are metadata-only; renderer never sees paths.

use runne_platform_desktop::local_model_source::{
    CandidateView, InstalledView, LocalModelSource, LocalModelSourceError, PickerInput,
};
use std::path::PathBuf;
use std::sync::Mutex;

/// Lazily-opened catalog rooted under the app data directory.
pub struct LocalModelState {
    models_root: PathBuf,
    inner: Mutex<Option<LocalModelSource>>,
}

impl LocalModelState {
    pub fn new(models_root: PathBuf) -> Self {
        Self {
            models_root,
            inner: Mutex::new(None),
        }
    }

    fn with_source<R>(
        &self,
        f: impl FnOnce(&mut LocalModelSource) -> Result<R, LocalModelSourceError>,
    ) -> Result<R, IpcError> {
        let mut guard = self.inner.lock().map_err(|_| IpcError {
            code: "local_model_state_unavailable",
        })?;
        if guard.is_none() {
            *guard = Some(
                LocalModelSource::open(&self.models_root).map_err(|_| IpcError {
                    code: "local_model_catalog_unavailable",
                })?,
            );
        }
        f(guard.as_mut().expect("opened above")).map_err(|_| IpcError {
            code: "local_model_operation_refused",
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalModelStageInput {
    pub gguf_path: PathBuf,
    pub template_path: Option<PathBuf>,
    pub model_id: String,
    pub model_revision: String,
    pub license: String,
    pub provenance_source_uri: String,
    pub provenance_publisher: String,
    pub provenance_acquired_at: String,
    pub min_compatible_runtime: Option<String>,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn local_model_stage(
    state: State<'_, LocalModelState>,
    input: LocalModelStageInput,
) -> Result<CandidateView, IpcError> {
    let gguf_path = input.gguf_path.clone();
    let picker = PickerInput {
        model_id: input.model_id,
        model_revision: input.model_revision,
        license: input.license,
        provenance_source_uri: input.provenance_source_uri,
        provenance_publisher: input.provenance_publisher,
        provenance_acquired_at: input.provenance_acquired_at,
        template_path: input.template_path,
        min_compatible_runtime: input.min_compatible_runtime,
    };
    state
        .with_source(|source| source.stage_candidate(&gguf_path, &picker))
        .map_err(|_| IpcError {
            code: "local_model_stage_refused",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn local_model_admit(
    state: State<'_, LocalModelState>,
    candidate_id: String,
    license_digest: String,
) -> Result<InstalledView, IpcError> {
    state
        .with_source(|source| source.admit(&candidate_id, &license_digest))
        .map_err(|_| IpcError {
            code: "local_model_admit_refused",
        })
}

#[tauri::command]
fn local_model_list(state: State<'_, LocalModelState>) -> Result<Vec<InstalledView>, IpcError> {
    state.with_source(|source| source.list()).map_err(|_| IpcError {
        code: "local_model_list_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn local_model_discard(state: State<'_, LocalModelState>, candidate_id: String) -> Result<bool, IpcError> {
    state
        .with_source(|source| source.discard(&candidate_id))
        .map_err(|_| IpcError {
            code: "local_model_discard_refused",
        })
}
