#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubmitTaskRunBody {
    conversation_id: String,
    workspace_id: String,
    prompt: String,
}

/// Client-facing atomic submit: the runtime commits Created+Queued as one
/// unit of work and answers with a `submitted` acknowledgement.
async fn submit_task_run_v2<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Json<SubmitTaskRunBody>, JsonRejection>,
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
    let input = match runne_domain::task_run::TaskRunInput::new(body.prompt) {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_task_run_input", &request_id),
    };

    command_response(
        state
            .host
            .submit_task_run(
                context,
                SubmitTaskRunCommand {
                    conversation_id,
                    workspace_id,
                    input,
                },
            )
            .await,
        &request_id,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacySubmitTaskRunBody {
    conversation_id: String,
    workspace_id: String,
}

/// Published v1 submit. Its IDs-only request keeps the historical fingerprint
/// and Created + Queued receipt semantics.
async fn submit_task_run_v1<H>(
    State(state): State<TaskRunHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Result<Json<LegacySubmitTaskRunBody>, JsonRejection>,
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
        state.host.submit_task_run_legacy(context, LegacySubmitTaskRunCommand { conversation_id, workspace_id }).await,
        &request_id,
    )
}
