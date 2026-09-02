#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskRunCancellationResponse {
    task_run_id: String,
    stream_version: u64,
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
