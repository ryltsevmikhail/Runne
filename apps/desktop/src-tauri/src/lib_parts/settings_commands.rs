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
async fn get_provider_credential_enrollment_status(
    state: tauri::State<'_, std::sync::Arc<AppCore>>,
    provider: runne_api::ProviderCredentialProviderV2,
) -> Result<runne_app_core::ProviderCredentialEnrollmentProjection, IpcError> {
    state
        .provider_credential_enrollment_status(provider)
        .await
        .map_err(|_| IpcError {
            code: "provider_credential_status_unavailable",
        })
}

#[tauri::command]
async fn request_provider_credential_intent(
    app: tauri::AppHandle,
    window: WebviewWindow,
    selections: tauri::State<'_, DirectorySelectionManager>,
    lifecycle: tauri::State<'_, RuntimeLifecycleManager>,
    updater: tauri::State<'_, UpdateStatusStore>,
    intents: tauri::State<'_, crate::provider_credential_enrollment::CredentialIntentRegistry>,
    request: crate::provider_credential_enrollment::CredentialIntentIpc,
) -> Result<crate::provider_credential_enrollment::CredentialIntentProjection, IpcError> {
    let focused = window.is_focused().map_err(|_| IpcError {
        code: "provider_credential_intent_rejected",
    })?;
    if !request.valid()
        || !credential_intent_window_is_current(
            focused,
            &selections,
            window.label(),
            request.renderer_generation,
        )
    {
        return Err(IpcError {
            code: "provider_credential_intent_rejected",
        });
    }
    // Trusted native chain only: leases, native prompt, exact daemon
    // confirmation, V3 transition with writer handoff. The renderer receives
    // just the closed projection; every failure is fail-closed and actionable.
    Box::pin(crate::provider_credential_enrollment::dispatch_credential_intent(
        &app,
        window,
        lifecycle.inner(),
        updater.inner(),
        intents.inner(),
        request,
    ))
    .await
    .map_err(|code| IpcError { code })
}

fn credential_intent_window_is_current(
    focused: bool,
    selections: &DirectorySelectionManager,
    label: &str,
    renderer_generation: u64,
) -> bool {
    focused
        && selections.renderer_generations().current(label).ok() == Some(renderer_generation)
}

#[cfg(test)]
mod provider_credential_intent_tests {
    use super::*;

    #[test]
    fn credential_intent_admission_requires_focused_exact_current_renderer() {
        let selections = DirectorySelectionManager::new(std::time::Duration::from_secs(30))
            .expect("selection manager");
        let current = selections
            .renderer_generations()
            .page_loaded("main")
            .expect("renderer generation");

        assert!(!credential_intent_window_is_current(false, &selections, "main", current));
        assert!(!credential_intent_window_is_current(true, &selections, "main", current + 1));
        assert!(credential_intent_window_is_current(true, &selections, "main", current));
        drop(selections);
    }
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
    app: tauri::AppHandle,
    state: tauri::State<'_, UpdateStatusStore>,
    core: tauri::State<'_, std::sync::Arc<AppCore>>,
    confirm_active_task_runs: bool,
) -> Result<UpdateStatusSnapshot, IpcError> {
    let active_task_runs = core.active_task_run_count().await.map_err(|_| IpcError {
        code: "update_active_task_runs_unavailable",
    })?;
    let record = state
        .prepare_update_install(active_task_runs, confirm_active_task_runs)
        .map_err(|()| IpcError {
            code: "update_install_rejected",
        })?;
    let Ok(current_executable) = std::env::current_exe() else {
        let _ = state.abort_update_install();
        return Err(IpcError {
            code: "update_install_rejected",
        });
    };
    if runne_platform_desktop::install_staged_update(
        &UpdateStatusStore::staged_update(&record),
        &current_executable,
    )
    .is_err()
    {
        let _ = state.abort_update_install();
        return Err(IpcError {
            code: "update_install_rejected",
        });
    }
    app.request_restart();
    Ok(state.snapshot())
}
