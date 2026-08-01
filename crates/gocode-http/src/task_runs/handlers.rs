/// Builds the real canonical TaskRun route set.
pub fn task_run_router<H>(state: TaskRunHttpState<H>) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    Router::new()
        .route("/v1/task-runs", post(create_task_run::<H>))
        .route("/v1/task-runs/{taskrun_id}", get(get_task_run::<H>))
        .route(
            "/v1/task-runs/{taskrun_id}/queue",
            post(queue_task_run::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/admit",
            post(admit_task_run::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/attempts",
            post(start_attempt::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/complete",
            post(complete_task_run::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_TASK_RUN_BODY_BYTES))
        .with_state(state)
}

async fn create_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Json<CreateTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let conversation_id = match body.conversation_id.parse::<ConversationId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_conversation_id", &request_id),
    };
    let workspace_id = match body.workspace_id.parse::<WorkspaceId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_workspace_id", &request_id),
    };

    command_response(
        state
            .host
            .create_task_run(
                context,
                CreateTaskRunCommand {
                    conversation_id,
                    workspace_id,
                },
            )
            .await,
        &request_id,
    )
}

async fn queue_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    existing_command(
        state,
        principal,
        request_id,
        taskrun_id,
        headers,
        body,
        ExistingOperation::Queue,
    )
    .await
}

async fn admit_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    existing_command(
        state,
        principal,
        request_id,
        taskrun_id,
        headers,
        body,
        ExistingOperation::Admit,
    )
    .await
}

async fn start_attempt<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ExistingTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    existing_command(
        state,
        principal,
        request_id,
        taskrun_id,
        headers,
        body,
        ExistingOperation::StartAttempt,
    )
    .await
}

#[derive(Clone, Copy)]
enum ExistingOperation {
    Queue,
    Admit,
    StartAttempt,
}

#[allow(clippy::too_many_arguments)]
async fn existing_command<H>(
    state: TaskRunHttpState<H>,
    principal: AuthenticatedPrincipal,
    request_id: RequestId,
    taskrun_id: String,
    headers: HeaderMap,
    body: Result<Json<ExistingTaskRunBody>, JsonRejection>,
    operation: ExistingOperation,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
    };
    let taskrun_id = match taskrun_id.parse::<TaskRunId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_task_run_id", &request_id),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let command = ExistingTaskRunCommand {
        taskrun_id,
        expected_version: body.expected_version,
    };
    let result = match operation {
        ExistingOperation::Queue => state.host.queue_task_run(context, command).await,
        ExistingOperation::Admit => state.host.admit_task_run(context, command).await,
        ExistingOperation::StartAttempt => state.host.start_attempt(context, command).await,
    };
    command_response(result, &request_id)
}

async fn complete_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<CompleteTaskRunBody>, JsonRejection>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
    };
    let taskrun_id = match taskrun_id.parse::<TaskRunId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_task_run_id", &request_id),
    };
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    let result = match body.result {
        TerminalResultWire::Success => CanonicalTerminalResult::Success,
        TerminalResultWire::Failure { reason } => {
            if reason.len() > MAX_CANONICAL_TERMINAL_REASON_BYTES {
                return bad_request("invalid_terminal_reason", &request_id);
            }
            CanonicalTerminalResult::Failure { reason }
        }
    };

    command_response(
        state
            .host
            .complete_task_run(
                context,
                CompleteTaskRunCommand {
                    taskrun_id,
                    expected_version: body.expected_version,
                    result,
                },
            )
            .await,
        &request_id,
    )
}

async fn get_task_run<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(request_id): Extension<RequestId>,
    Path(taskrun_id): Path<String>,
) -> Response
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort,
{
    let taskrun_id = match taskrun_id.parse::<TaskRunId>() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_task_run_id", &request_id),
    };
    match state.host.get_task_run(taskrun_id).await {
        Ok(snapshot) => (StatusCode::OK, Json(snapshot_to_wire(snapshot))).into_response(),
        Err(error) => host_error_response(error, &request_id),
    }
}
