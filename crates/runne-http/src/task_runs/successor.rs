#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UnknownSuccessorBody {
    expected_version: u64,
    acknowledgment: String,
}

async fn supersede_unknown_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<UnknownSuccessorBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
    };
    let predecessor_taskrun_id = match taskrun_id.parse::<TaskRunId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_task_run_id", &request_id),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    if body.acknowledgment != UnknownSuccessorAcknowledgment::CODE {
        return bad_request("invalid_successor_acknowledgment", &request_id);
    }
    let result = state
        .host
        .supersede_unknown_task_run(
            context,
            SupersedeUnknownTaskRunCommand {
                predecessor_taskrun_id,
                expected_predecessor_version: body.expected_version,
                acknowledgment: UnknownSuccessorAcknowledgment::DuplicateExecutionAndCostV1,
            },
        )
        .await;
    command_response(result, &request_id)
}
