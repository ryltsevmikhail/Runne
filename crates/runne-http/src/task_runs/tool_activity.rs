async fn get_task_run_tool_activity<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
) -> Response
where
    H: TaskRunQueryHostPort,
{
    let Ok(taskrun_id) = taskrun_id.parse::<TaskRunId>() else {
        return bad_request("invalid_task_run_id", &request_id);
    };
    match state
        .host
        .get_task_run_tool_activity(principal.as_api_principal().clone(), taskrun_id)
        .await
    {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => effect_error(error, &request_id),
    }
}
