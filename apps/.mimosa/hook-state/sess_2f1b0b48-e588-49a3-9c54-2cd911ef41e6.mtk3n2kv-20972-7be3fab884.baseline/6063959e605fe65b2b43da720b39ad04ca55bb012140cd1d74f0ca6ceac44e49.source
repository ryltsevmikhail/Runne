use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;

use runne_app_core::{AppCore, DiagnosticsSnapshot};
use serde::Serialize;
use tauri::{Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

const MAX_EXPORT_BYTES: usize = 128 * 1024;
const REDACTION_VERSION: u32 = 1;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsExportPreview {
    schema_version: u32,
    redaction_version: u32,
    categories: [&'static str; 2],
    estimated_bytes: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsExportResult {
    status: ExportStatus,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ExportStatus {
    Saved,
    Cancelled,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticsExportDocument {
    schema_version: u32,
    redaction_version: u32,
    categories: [&'static str; 2],
    diagnostics: DiagnosticsSnapshot,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn get_diagnostics_export_preview(
    state: State<'_, Arc<AppCore>>,
) -> Result<DiagnosticsExportPreview, crate::IpcError> {
    let bytes = export_bytes(&state)?;
    Ok(DiagnosticsExportPreview {
        schema_version: 1,
        redaction_version: REDACTION_VERSION,
        categories: ["application", "runtime"],
        estimated_bytes: bytes.len(),
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn export_diagnostics(
    window: WebviewWindow,
    state: State<'_, Arc<AppCore>>,
) -> Result<DiagnosticsExportResult, crate::IpcError> {
    if !window.is_focused().map_err(|_| crate::IpcError {
        code: "diagnostics_export_rejected",
    })? {
        return Err(crate::IpcError {
            code: "diagnostics_export_rejected",
        });
    }
    let bytes = export_bytes(&state)?;
    let selected = window
        .app_handle()
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Export redacted diagnostics")
        .set_file_name("runne-diagnostics.json")
        .add_filter("JSON", &["json"])
        .blocking_save_file();
    let Some(selected) = selected else {
        return Ok(DiagnosticsExportResult {
            status: ExportStatus::Cancelled,
        });
    };
    let path = selected.into_path().map_err(|_| crate::IpcError {
        code: "diagnostics_export_rejected",
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| crate::IpcError {
            code: "diagnostics_export_destination_rejected",
        })?;
    if file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(crate::IpcError {
            code: "diagnostics_export_write_failed",
        });
    }
    Ok(DiagnosticsExportResult {
        status: ExportStatus::Saved,
    })
}

fn export_bytes(state: &AppCore) -> Result<Vec<u8>, crate::IpcError> {
    let diagnostics = state
        .diagnostics(env!("CARGO_PKG_VERSION"), std::env::consts::OS)
        .map_err(|_| crate::IpcError {
            code: "diagnostics_unavailable",
        })?;
    let document = DiagnosticsExportDocument {
        schema_version: 1,
        redaction_version: REDACTION_VERSION,
        categories: ["application", "runtime"],
        diagnostics,
    };
    let bytes = serde_json::to_vec_pretty(&document).map_err(|_| crate::IpcError {
        code: "diagnostics_export_rejected",
    })?;
    if bytes.len() > MAX_EXPORT_BYTES || !redaction_is_valid(&bytes) {
        return Err(crate::IpcError {
            code: "diagnostics_redaction_failed",
        });
    }
    Ok(bytes)
}

fn redaction_is_valid(bytes: &[u8]) -> bool {
    [
        &b"credential"[..],
        &b"secret"[..],
        &b"token"[..],
        &b"private_path"[..],
    ]
    .iter()
    .all(|marker| !bytes.windows(marker.len()).any(|window| window == *marker))
}

#[cfg(test)]
mod tests {
    use super::redaction_is_valid;

    #[test]
    fn redaction_gate_rejects_sensitive_markers() {
        assert!(redaction_is_valid(br#"{"runtime":"safe"}"#));
        assert!(!redaction_is_valid(br#"{"token":"hidden"}"#));
    }
}
