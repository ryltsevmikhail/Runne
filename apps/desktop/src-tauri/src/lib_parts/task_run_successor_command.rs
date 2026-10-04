#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SupersedeUnknownTaskRunIpcRequest {
    task_run_id: String,
    expected_version: u64,
    acknowledge_duplicate_execution_and_cost: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SupersedeUnknownTaskRunIpcResponse {
    predecessor_task_run_id: String,
    predecessor_version: u64,
    task_run_id: String,
    stream_version: u64,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn supersede_unknown_task_run(
    state: State<'_, Arc<AppCore>>,
    request: SupersedeUnknownTaskRunIpcRequest,
) -> Result<SupersedeUnknownTaskRunIpcResponse, IpcError> {
    if !request.acknowledge_duplicate_execution_and_cost {
        return Err(IpcError { code: "duplicate_execution_acknowledgment_required" });
    }
    let value = state.supersede_unknown_task_run(
        &request.task_run_id,
        request.expected_version,
        runne_app_core::UnknownSuccessorAcknowledgment::DuplicateExecutionAndCostV1,
    ).await.map_err(|_| IpcError { code: "task_run_successor_unavailable" })?;
    Ok(SupersedeUnknownTaskRunIpcResponse {
        predecessor_task_run_id: value.predecessor_task_run_id().to_string(),
        predecessor_version: value.predecessor_version(),
        task_run_id: value.successor_task_run_id().to_string(),
        stream_version: value.stream_version(),
    })
}
