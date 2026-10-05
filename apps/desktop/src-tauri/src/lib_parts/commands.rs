fn require_runtime_admission(lifecycle: &RuntimeLifecycleManager) -> Result<(), IpcError> {
    if lifecycle.is_shutting_down() {
        return Err(IpcError { code: "runtime_shutdown_in_progress" });
    }
    Ok(())
}

include!("runtime_ipc_error.rs");
#[path = "project_trust_confirmation.rs"]
mod project_trust_confirmation;
include!("project_trust_control_commands.rs");

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_pending_external_activation(
    state: State<'_, external_activation::ActivationManager>,
) -> Option<external_activation::ActivationTarget> {
    state.take()
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_bootstrap(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
) -> Result<BootstrapState, IpcRuntimeError> {
    if lifecycle.is_shutting_down() {
        crate::runtime_status_qualification::record(
            crate::runtime_status_qualification::Operation::Bootstrap,
            crate::runtime_status_qualification::Outcome::Rejected,
            crate::runtime_status_qualification::Disposition::Terminal,
            None,
        );
        return Err(IpcRuntimeError { code: "runtime_shutdown_in_progress", disposition: "terminal" });
    }
    if let Ok(bootstrap) = state.bootstrap() {
        let runtime = bootstrap.runtime;
        crate::runtime_status_qualification::record(
            crate::runtime_status_qualification::Operation::Bootstrap,
            crate::runtime_status_qualification::Outcome::State,
            crate::runtime_status_qualification::disposition_for(Some(runtime)),
            Some(runtime),
        );
        Ok(bootstrap)
    } else {
        let runtime = state.runtime_availability().ok();
        let error = bootstrap_runtime_error_for(runtime);
        crate::runtime_status_qualification::record(
            crate::runtime_status_qualification::Operation::Bootstrap,
            crate::runtime_status_qualification::Outcome::Rejected,
            crate::runtime_status_qualification::disposition_from_ipc(error.disposition),
            runtime,
        );
        Err(error)
    }
}
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn set_theme(
    state: State<'_, Arc<AppCore>>,
    theme: String,
) -> Result<runne_app_core::ThemeAcknowledgement, IpcError> {
    state.set_theme(&theme).map_err(|_| IpcError { code: "theme_update_rejected" })
}
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn list_projects(state: State<'_, Arc<AppCore>>) -> Result<Vec<ProjectSummary>, IpcError> {
    state.list_projects().map_err(|_| IpcError {
        code: "projects_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn list_canonical_projects(state: State<'_, Arc<AppCore>>) -> Result<Vec<CanonicalProjectSummary>, IpcError> {
    state.list_canonical_projects().await.map_err(|_| IpcError { code: "projects_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_canonical_project(
    state: State<'_, Arc<AppCore>>,
    project_id: String,
) -> Result<CanonicalProjectDetails, IpcError> {
    state.get_canonical_project(&project_id).await.map_err(|_| IpcError { code: "project_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_canonical_workspace(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
) -> Result<CanonicalWorkspaceSummary, IpcError> {
    state.get_canonical_workspace(&workspace_id).await.map_err(|_| IpcError { code: "project_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_task_run_timeline(
    state: State<'_, Arc<AppCore>>,
    task_run_id: String,
) -> Result<runne_app_core::TaskRunTimelineSnapshot, IpcError> {
    state
        .get_task_run_timeline(&task_run_id)
        .await
        .map_err(|_| IpcError {
            code: "task_run_unavailable",
        })
}

#[tauri::command]
async fn resync_task_run_timeline(
    state: State<'_, Arc<AppCore>>,
    task_run_id: String,
) -> Result<runne_app_core::TaskRunTimelineSnapshot, IpcError> {
    state.resync_task_run_timeline(&task_run_id).await.map_err(|_| IpcError { code: "task_run_unavailable" })
}

include!("task_run_commands.rs");
include!("managed_task_run_commands.rs");
include!("managed_task_run_handler.rs");
include!("task_run_effects_command.rs");
include!("task_run_successor_command.rs");
include!("approval_commands.rs");
include!("conversation_commands.rs");
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn subscribe_task_run_timeline(
    window: WebviewWindow,
    state: State<'_, Arc<AppCore>>,
    subscriptions: State<'_, TaskRunSubscriptionManager>,
    task_run_id: String,
    on_update: tauri::ipc::Channel<task_run_channel::TaskRunChannelEvent>,
) -> Result<String, task_run_channel::TaskRunChannelError> {
    subscriptions.subscribe(Arc::clone(&*state), &task_run_id, window.label(), on_update)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn ack_task_run_update(
    window: WebviewWindow,
    subscriptions: State<'_, TaskRunSubscriptionManager>,
    subscription_id: String,
    projection_revision: u64,
) -> Result<(), task_run_channel::TaskRunChannelError> {
    subscriptions.ack(window.label(), &subscription_id, projection_revision)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn cancel_task_run_subscription(
    window: WebviewWindow,
    subscriptions: State<'_, TaskRunSubscriptionManager>,
    subscription_id: String,
) -> Result<(), task_run_channel::TaskRunChannelError> {
    subscriptions.cancel(window.label(), &subscription_id).await
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_project(
    state: State<'_, Arc<AppCore>>,
    project_id: String,
) -> Result<Vec<ProjectSummary>, IpcError> {
    state.get_project(&project_id).map_err(|_| IpcError {
        code: "project_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_workspace(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
) -> Result<Option<ProjectSummary>, IpcError> {
    state.get_workspace(&workspace_id).map_err(|_| IpcError { code: "project_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn acquire_renderer_generation(
    window: WebviewWindow,
    selections: State<'_, DirectorySelectionManager>,
) -> Result<u64, IpcError> {
    if !window.is_focused().map_err(|_| IpcError { code: "renderer_generation_rejected" })? {
        return Err(IpcError { code: "renderer_generation_rejected" });
    }
    selections
        .renderer_generations()
        .current(window.label())
        .map_err(|_| IpcError { code: "renderer_generation_rejected" })
}


#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn prepare_selected_workspace(
    window: WebviewWindow,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    selections: State<'_, DirectorySelectionManager>,
    prepared: State<'_, PreparedWorkspaceManager>,
    request: PrepareSelectedWorkspaceRequest,
) -> Result<PreparedWorkspaceResponse, IpcError> {
    let label = window.label();
    if !window.is_focused().map_err(|_| IpcError { code: "prepared_workspace_rejected" })? {
        return Err(IpcError { code: "prepared_workspace_rejected" });
    }
    let workspace_id = request
        .workspace_id
        .parse()
        .map_err(|_| IpcError { code: "prepared_workspace_rejected" })?;
    let now = std::time::Instant::now();
    let binding = PreparedWorkspaceBinding::new(
        label, request.renderer_generation, &request.request_id, workspace_id, request.expected_version,
    )
    .map_err(|_| IpcError { code: "prepared_workspace_rejected" })?;
    let reservation = prepared
        .reserve_guard(binding, now)
        .map_err(|_| IpcError { code: "prepared_workspace_rejected" })?;
    let root = selections
        .consume(
            &request.selection,
            label,
            request.renderer_generation,
            &request.request_id,
            now,
        )
        .map_err(|_| IpcError { code: "prepared_workspace_rejected" })?;
    let native_admission = lifecycle
        .prepare_root_admission(root, workspace_id, request.expected_version)
        .await
        .map_err(|_| IpcError { code: "prepared_workspace_rejected" })?;
    commit_prepared_admission(&prepared, reservation, native_admission, &lifecycle)
        .await
        .map_err(|()| IpcError { code: "prepared_workspace_rejected" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::significant_drop_tightening)] // root and permit intentionally span both mutations.
async fn open_selected_workspace(window: WebviewWindow, core: State<'_, Arc<AppCore>>, lifecycle: State<'_, RuntimeLifecycleManager>, prepared: State<'_, PreparedWorkspaceManager>, request: OpenSelectedWorkspaceRequest) -> Result<(), IpcError> {
    let attempt = prepared.begin_initial(&request.prepared, window.label(), request.renderer_generation, &request.request_id, std::time::Instant::now(), &lifecycle).map_err(|_| IpcError { code: "prepared_workspace_rejected" })?;
    open_prepared_workspace(&core, &lifecycle, attempt).await
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn retry_open_selected_workspace(window: WebviewWindow, core: State<'_, Arc<AppCore>>, lifecycle: State<'_, RuntimeLifecycleManager>, prepared: State<'_, PreparedWorkspaceManager>, request: RetryOpenSelectedWorkspaceRequest) -> Result<(), IpcError> {
    let attempt = prepared.begin_retry(&request.prepared, window.label(), request.renderer_generation, &request.request_id, std::time::Instant::now(), &lifecycle).map_err(|_| IpcError { code: "prepared_workspace_rejected" })?;
    open_prepared_workspace(&core, &lifecycle, attempt).await
}

async fn open_prepared_workspace(core: &AppCore, _lifecycle: &RuntimeLifecycleManager, mut attempt: crate::prepared_workspace::PreparedWorkspaceOpenAttempt) -> Result<(), IpcError> {
    if attempt.prepare(core).await.is_err() {
        attempt.reap().await;
        return Err(IpcError { code: "prepared_workspace_rejected" });
    }
    if let Err(error) = attempt.dispatch(core).await {
        if attempt.possible_send() {
            return Err(IpcError { code: if attempt.retain() == crate::prepared_workspace::PreparedWorkspaceRestoreOutcome::Retained { "prepared_workspace_retryable" } else { "prepared_workspace_rejected" } });
        }
        if error.disposition() == runne_app_core::NativeAuthorityDisposition::ReapBeforeDispatch {
            attempt.reap().await;
        }
        return Err(IpcError { code: "prepared_workspace_rejected" });
    }
    attempt.opened();
    Ok(())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_diagnostics(state: State<'_, Arc<AppCore>>) -> Result<DiagnosticsSnapshot, IpcError> {
    state
        .diagnostics(env!("CARGO_PKG_VERSION"), std::env::consts::OS)
        .map_err(|_| IpcError {
            code: "diagnostics_unavailable",
        })
}

include!("runtime_connect.rs");

include!("destructive_commands.rs");

include!("local_model_commands.rs");
