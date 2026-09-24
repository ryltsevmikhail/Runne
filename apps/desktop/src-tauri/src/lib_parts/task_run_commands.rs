#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunCancellationResponse {
    task_run_id: String,
    stream_version: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunSubmissionResponse {
    task_run_id: String,
    stream_version: u64,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn submit_task_run(
    state: State<'_, Arc<AppCore>>,
    conversation_id: String,
    workspace_id: String,
    prompt: String,
) -> Result<TaskRunSubmissionResponse, IpcError> {
    if prompt.trim().is_empty() || prompt.len() > 64 * 1024 {
        return Err(IpcError { code: "task_run_prompt_rejected" });
    }
    let conversation_id = runne_app_core::CanonicalId::parse(&conversation_id)
        .map_err(|_| IpcError { code: "task_run_submission_rejected" })?;
    let workspace_id = runne_app_core::CanonicalId::parse(&workspace_id)
        .map_err(|_| IpcError { code: "task_run_submission_rejected" })?;
    let acknowledgement = state
        .submit_task_run(conversation_id, workspace_id, prompt)
        .await
        .map_err(|_| IpcError { code: "task_run_submission_unavailable" })?;
    Ok(TaskRunSubmissionResponse {
        task_run_id: acknowledgement.task_run_id().to_string(),
        stream_version: acknowledgement.stream_version(),
    })
}

#[tauri::command]
async fn cancel_task_run(
    state: State<'_, Arc<AppCore>>,
    task_run_id: String,
    expected_version: u64,
) -> Result<TaskRunCancellationResponse, IpcError> {
    let acknowledgement = state
        .cancel_task_run(&task_run_id, expected_version)
        .await
        .map_err(|_| IpcError { code: "task_run_cancel_unavailable" })?;
    Ok(TaskRunCancellationResponse {
        task_run_id: acknowledgement.task_run_id().to_string(),
        stream_version: acknowledgement.stream_version(),
    })
}
