async fn list_task_runs<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(request_id): Extension<RequestId>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    match state.host.list_task_runs().await {
        Ok(task_runs) => (
            StatusCode::OK,
            Json(TaskRunListWire {
                task_runs: task_runs.into_iter().map(snapshot_to_wire).collect(),
            }),
        )
            .into_response(),
        Err(error) => host_error_response(error, &request_id),
    }
}
