#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn start_process(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
    task_run_id: String,
    attempt_id: String,
    invocation_id: String,
) -> Result<CanonicalProcessSnapshot, IpcError> {
    state
        .start_process(&workspace_id, &task_run_id, &attempt_id, &invocation_id)
        .await
        .map_err(|_| IpcError { code: "process_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn get_process(
    state: State<'_, Arc<AppCore>>,
    process_id: String,
) -> Result<CanonicalProcessSnapshot, IpcError> {
    state
        .get_process(&process_id)
        .await
        .map_err(|_| IpcError { code: "process_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn read_process_output(
    state: State<'_, Arc<AppCore>>,
    process_id: String,
    after_sequence: u64,
    limit: u16,
) -> Result<CanonicalProcessOutputPage, IpcError> {
    state
        .read_process_output(&process_id, after_sequence, limit)
        .await
        .map_err(|_| IpcError { code: "process_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn stop_process(
    state: State<'_, Arc<AppCore>>,
    process_id: String,
    expected_version: u64,
) -> Result<CanonicalProcessSnapshot, IpcError> {
    state
        .stop_process(&process_id, expected_version)
        .await
        .map_err(|_| IpcError { code: "process_unavailable" })
}
