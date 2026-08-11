fn require_runtime_admission(lifecycle: &RuntimeLifecycleManager) -> Result<(), IpcError> {
    if lifecycle.is_shutting_down() {
        return Err(IpcError {
            code: "runtime_shutdown_in_progress",
        });
    }
    Ok(())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn get_bootstrap(state: State<'_, Arc<AppCore>>) -> Result<BootstrapState, IpcError> {
    state.bootstrap().map_err(|_| IpcError {
        code: "bootstrap_unavailable",
    })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn set_theme(state: State<'_, Arc<AppCore>>, theme: String) -> Result<(), IpcError> {
    state.set_theme(&theme).map_err(|_| IpcError {
        code: "theme_update_rejected",
    })
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
fn get_project(
    state: State<'_, Arc<AppCore>>,
    id: i64,
) -> Result<Option<ProjectSummary>, IpcError> {
    state.get_project(id).map_err(|_| IpcError {
        code: "project_unavailable",
    })
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
fn request_directory_selection(
    window: WebviewWindow,
    selections: State<'_, DirectorySelectionManager>,
    renderer_generation: u64,
    request_id: String,
) -> Result<Option<DirectorySelectionResponse>, IpcError> {
    let label = window.label();
    if !window.is_focused().map_err(|_| IpcError { code: "directory_selection_rejected" })?
        || selections.renderer_generations().current(label).ok() != Some(renderer_generation)
    {
        return Err(IpcError { code: "directory_selection_rejected" });
    }
    let selected = window
        .app_handle()
        .dialog()
        .file()
        .set_parent(&window)
        .set_title("Open local project")
        .blocking_pick_folder();
    let Some(selected) = selected else { return Ok(None) };
    if !window.is_focused().map_err(|_| IpcError { code: "directory_selection_rejected" })?
        || selections.renderer_generations().current(label).ok() != Some(renderer_generation)
    {
        return Err(IpcError { code: "directory_selection_rejected" });
    }
    let path = selected.into_path().map_err(|_| IpcError { code: "directory_selection_rejected" })?;
    let root = VerifiedRootHandle::open(&path)
        .map_err(|_| IpcError { code: "directory_selection_rejected" })?;
    selections
        .issue(label, renderer_generation, &request_id, root, std::time::Instant::now())
        .map(DirectorySelectionResponse::new)
        .map(Some)
        .map_err(|_| IpcError { code: "directory_selection_rejected" })
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
        label,
        request.renderer_generation,
        &request.request_id,
        workspace_id,
        request.expected_version,
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
fn get_diagnostics(state: State<'_, Arc<AppCore>>) -> Result<DiagnosticsSnapshot, IpcError> {
    state
        .diagnostics(env!("CARGO_PKG_VERSION"), std::env::consts::OS)
        .map_err(|_| IpcError {
            code: "diagnostics_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn connect_runtime(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
) -> Result<RuntimeAvailability, IpcError> {
    require_runtime_admission(&lifecycle)?;
    lifecycle
        .connect_runtime(&state)
        .await
        .map_err(|_| IpcError {
            code: "runtime_connection_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn open_project_conversation(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    project_id: i64,
) -> Result<ConversationSnapshot, IpcError> {
    require_runtime_admission(&lifecycle)?;
    state
        .open_project_conversation(project_id)
        .await
        .map_err(|_| IpcError {
            code: "conversation_unavailable",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn resync_project_conversation(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    project_id: i64,
) -> Result<ConversationSnapshot, IpcError> {
    require_runtime_admission(&lifecycle)?;
    state
        .resync_project_conversation(project_id)
        .await
        .map_err(|_| IpcError {
            code: "replay_resync_required",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn send_project_message(
    state: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    project_id: i64,
    text: String,
) -> Result<ConversationSnapshot, IpcError> {
    require_runtime_admission(&lifecycle)?;
    state
        .send_project_message(project_id, &text)
        .await
        .map_err(|_| IpcError {
            code: "conversation_message_rejected",
        })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn subscribe_project_conversation(
    window: WebviewWindow,
    core: State<'_, Arc<AppCore>>,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    project_id: i64,
    on_update: Channel<ConversationChannelEvent>,
) -> Result<String, ConversationChannelError> {
    if lifecycle.is_shutting_down() {
        return Err(ConversationChannelError::unavailable());
    }
    subscriptions.subscribe(
        Arc::clone(core.inner()),
        project_id,
        window.label(),
        on_update,
    )
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn ack_conversation_update(
    window: WebviewWindow,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    subscription_id: String,
    projection_revision: u64,
) -> Result<(), ConversationChannelError> {
    if lifecycle.is_shutting_down() {
        return Err(ConversationChannelError::unavailable());
    }
    subscriptions.ack(window.label(), &subscription_id, projection_revision)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn cancel_conversation_subscription(
    window: WebviewWindow,
    lifecycle: State<'_, RuntimeLifecycleManager>,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    subscription_id: String,
) -> Result<(), ConversationChannelError> {
    if lifecycle.is_shutting_down() {
        return Err(ConversationChannelError::unavailable());
    }
    subscriptions.cancel(window.label(), &subscription_id)
}
