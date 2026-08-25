#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LocaleSnapshot {
    locale: String,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_locale(
    state: tauri::State<'_, std::sync::Arc<AppCore>>,
) -> Result<LocaleSnapshot, IpcError> {
    state
        .locale()
        .map(|locale| LocaleSnapshot { locale })
        .map_err(|_| IpcError {
            code: "locale_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn set_locale(
    state: tauri::State<'_, std::sync::Arc<AppCore>>,
    locale: String,
) -> Result<LocaleSnapshot, IpcError> {
    state.set_locale(&locale).map_err(|_| IpcError {
        code: "locale_update_rejected",
    })?;
    get_locale(state)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_shortcuts(
    state: tauri::State<'_, std::sync::Arc<AppCore>>,
) -> Result<ShortcutSettings, IpcError> {
    state.shortcuts().map_err(|_| IpcError {
        code: "shortcuts_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn set_shortcuts(
    state: tauri::State<'_, std::sync::Arc<AppCore>>,
    shortcuts: ShortcutSettings,
) -> Result<ShortcutSettings, IpcError> {
    state.set_shortcuts(&shortcuts).map_err(|_| IpcError {
        code: "shortcuts_update_rejected",
    })?;
    get_shortcuts(state)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_device_status(
    state: tauri::State<'_, std::sync::Arc<AppCore>>,
) -> Result<RuntimeDeviceSnapshot, IpcError> {
    state.runtime_device().map_err(|_| IpcError {
        code: "device_status_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_provider_status(
    state: tauri::State<'_, std::sync::Arc<AppCore>>,
) -> Result<Vec<ProviderStatusSnapshotV1>, IpcError> {
    state.provider_statuses().map_err(|_| IpcError {
        code: "provider_status_unavailable",
    })
}

#[tauri::command]
async fn pair_provider_credential(
    state: tauri::State<'_, std::sync::Arc<AppCore>>,
    provider: String,
    credential: String,
) -> Result<runne_app_core::CanonicalProviderCredentialMutation, IpcError> {
    state
        .pair_provider_credential(&provider, credential.into_bytes())
        .await
        .map_err(|_| IpcError {
            code: "provider_credential_pair_rejected",
        })
}

#[tauri::command]
async fn revoke_provider_credential(
    state: tauri::State<'_, std::sync::Arc<AppCore>>,
    provider: String,
) -> Result<runne_app_core::CanonicalProviderCredentialMutation, IpcError> {
    state
        .revoke_provider_credential(&provider)
        .await
        .map_err(|_| IpcError {
            code: "provider_credential_revoke_rejected",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_update_status(state: tauri::State<'_, UpdateStatusStore>) -> UpdateStatusSnapshot {
    state.snapshot()
}

#[tauri::command]
async fn check_update(
    state: tauri::State<'_, UpdateStatusStore>,
) -> Result<UpdateStatusSnapshot, IpcError> {
    state.check_update().await.map_err(|()| IpcError {
        code: "update_check_unavailable",
    })?;
    Ok(state.snapshot())
}

#[tauri::command]
async fn download_update(
    state: tauri::State<'_, UpdateStatusStore>,
) -> Result<UpdateStatusSnapshot, IpcError> {
    state.download_update().await.map_err(|()| IpcError {
        code: "update_download_rejected",
    })?;
    Ok(state.snapshot())
}

#[tauri::command]
async fn prepare_update_install(
    state: tauri::State<'_, UpdateStatusStore>,
    core: tauri::State<'_, std::sync::Arc<AppCore>>,
    confirm_active_task_runs: bool,
) -> Result<UpdateStatusSnapshot, IpcError> {
    let active_task_runs = core.active_task_run_count().await.map_err(|_| IpcError {
        code: "update_active_task_runs_unavailable",
    })?;
    state
        .prepare_update_install(active_task_runs, confirm_active_task_runs)
        .map_err(|()| IpcError {
            code: "update_install_rejected",
        })?;
    Ok(state.snapshot())
}
