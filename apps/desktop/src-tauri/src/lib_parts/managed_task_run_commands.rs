#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn prepare_managed_task_run(
    state: State<'_, Arc<AppCore>>,
    project_id: String,
    workspace_id: String,
) -> Result<runne_app_core::ManagedTaskRunPreflight, IpcError> {
    state
        .prepare_managed_task_run(&project_id, &workspace_id)
        .await
        .map_err(|_| IpcError {
            code: "managed_task_run_preflight_unavailable",
        })
}

#[tauri::command]
async fn load_managed_task_draft(
    state: State<'_, Arc<AppCore>>,
    project_id: String,
    workspace_id: String,
) -> Result<runne_app_core::ManagedTaskDraft, IpcError> {
    state
        .load_managed_task_draft(&project_id, &workspace_id)
        .await
        .map_err(|_| IpcError {
            code: "managed_task_draft_unavailable",
        })
}

#[tauri::command]
async fn save_managed_task_draft(
    state: State<'_, Arc<AppCore>>,
    project_id: String,
    workspace_id: String,
    scope_token: String,
    expected_revision: u64,
    prompt: String,
) -> Result<runne_app_core::ManagedTaskDraft, IpcError> {
    state
        .save_managed_task_draft(
            &project_id,
            &workspace_id,
            &scope_token,
            expected_revision,
            &prompt,
        )
        .await
        .map_err(|error| map_managed_task_draft_error(&error))
}

#[tauri::command]
async fn clear_managed_task_draft(
    state: State<'_, Arc<AppCore>>,
    project_id: String,
    workspace_id: String,
    scope_token: String,
    expected_revision: u64,
) -> Result<runne_app_core::ManagedTaskDraft, IpcError> {
    state
        .clear_managed_task_draft(&project_id, &workspace_id, &scope_token, expected_revision)
        .await
        .map_err(|error| map_managed_task_draft_error(&error))
}

const fn map_managed_task_draft_error(error: &AppCoreError) -> IpcError {
    IpcError {
        code: match error {
            AppCoreError::ManagedDraftConflict => "managed_task_draft_conflict",
            AppCoreError::ManagedDraftScopeChanged => "managed_task_draft_scope_changed",
            AppCoreError::ManagedDraftCapacity => "managed_task_draft_capacity",
            _ => "managed_task_draft_unavailable",
        },
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn start_managed_task_run(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
    conversation_id: String,
    prompt: String,
    generation: u64,
    recovery_token: String,
) -> Result<runne_app_core::ManagedTaskRunStart, IpcError> {
    #[cfg(not(all(target_os = "linux", feature = "test-support")))]
    let _ = app;
    if prompt.trim().is_empty() || prompt.len() > 64 * 1024 {
        return Err(IpcError {
            code: "managed_task_run_prompt_rejected",
        });
    }
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    let fixture_control = app
        .try_state::<crate::gui_qualification::GuiQualificationControl>()
        .map(|control| control.inner().clone());
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    if let Some(control) = fixture_control.as_ref() {
        control.before_start().map_err(|_| IpcError {
            code: "gui_fixture_start_counter_failed",
        })?;
    }
    let result = state
        .start_managed_task_run(
            &workspace_id,
            &conversation_id,
            prompt,
            generation,
            &recovery_token,
        )
        .await
        .map_err(|_| IpcError {
            code: "managed_task_run_start_unavailable",
        })?;
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    if let Some(control) = fixture_control.as_ref() {
        control
            .after_start(&state, &result)
            .await
            .map_err(|_| IpcError {
                code: "gui_fixture_ack_hook_failed",
            })?;
    }
    Ok(result)
}

#[tauri::command]
async fn list_managed_task_runs(
    state: State<'_, Arc<AppCore>>,
) -> Result<runne_app_core::ManagedTaskRunList, IpcError> {
    Ok(state
        .list_managed_task_runs()
        .await
        .unwrap_or(runne_app_core::ManagedTaskRunList {
            status: "unavailable",
            task_runs: Vec::new(),
        }))
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn recover_managed_task_run(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppCore>>,
    recovery_token: String,
) -> Result<runne_app_core::ManagedTaskRunRecovery, IpcError> {
    #[cfg(not(all(target_os = "linux", feature = "test-support")))]
    let _ = app;
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    let fixture_control = app
        .try_state::<crate::gui_qualification::GuiQualificationControl>()
        .map(|control| control.inner().clone());
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    let replaying_original_token = fixture_control.is_some()
        && recovery_token == crate::gui_qualification::previous_token_sentinel();
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    let recovery_token = if replaying_original_token {
        fixture_control
            .as_ref()
            .ok_or(IpcError {
                code: "gui_fixture_unavailable",
            })?
            .recovery_token()
            .map_err(|_| IpcError {
                code: "gui_fixture_token_unavailable",
            })?
    } else {
        recovery_token
    };
    let result = state
        .recover_managed_task_run(&recovery_token)
        .await
        .unwrap_or(runne_app_core::ManagedTaskRunRecovery {
            status: "unavailable",
            task_run_id: None,
            stream_version: None,
            workspace_id: None,
            conversation_id: None,
        });
    #[cfg(all(target_os = "linux", feature = "test-support"))]
    if let Some(control) = fixture_control.as_ref() {
        let selector = if replaying_original_token {
            crate::gui_qualification::previous_token_sentinel()
        } else {
            &recovery_token
        };
        let _ = control.after_recovery(&state, selector, &result).await;
    }
    Ok(result)
}

#[tauri::command]
async fn get_managed_attention_snapshot(
    state: State<'_, Arc<AppCore>>,
) -> Result<runne_app_core::ManagedAttentionSnapshot, IpcError> {
    Ok(state.managed_attention_snapshot().await.unwrap_or(
        runne_app_core::ManagedAttentionSnapshot {
            status: "unavailable",
            complete: false,
            items: Vec::new(),
        },
    ))
}
