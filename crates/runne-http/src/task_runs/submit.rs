#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubmitTaskRunBody {
    conversation_id: String,
    workspace_id: String,
    prompt: String,
    model: Option<String>,
    profile: Option<SelectedProfileWire>,
    local_command: Option<LocalCommandWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalCommandWire {
    executable: LocalExecutableWire,
    cwd: String,
    argv: Vec<String>,
    env: Vec<LocalEnvironmentWire>,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum LocalExecutableWire {
    WorkspaceRelative(String),
    SystemProgram(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalEnvironmentWire {
    key: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectedProfileWire {
    profile_id: String,
    profile_digest: String,
}

/// Exact-model admission: a request must match the model pinned to its exact
/// selected profile; an omitted profile uses the runtime's primary model.
/// Missing pins fail closed before command identity or durable work is used.
fn admit_requested_model(
    state: &TaskRunHttpState<impl TaskRunCommandHostPort>,
    requested: Option<&str>,
    selected_profile: Option<&runne_domain::task_run::SelectedProviderProfile>,
    request_id: &RequestId,
) -> Option<Response> {
    let requested = requested?;
    match state.model_for_profile(selected_profile) {
        Some(pinned) if pinned == requested => None,
        _ => Some(canonical_error_response(
            StatusCode::CONFLICT,
            "model_mismatch",
            request_id,
        )),
    }
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
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return bad_request("invalid_request", &request_id),
    };
    if body.local_command.is_some()
        && !local_command_content_allowed(&state, &body.prompt, body.local_command.as_ref())
    {
        return canonical_error_response(
            StatusCode::BAD_REQUEST,
            "prohibited_command_input",
            &request_id,
        );
    }
    let selected_profile = match body.profile {
        None => None,
        Some(wire) => match decode_profile(wire) {
            Some(profile) if state.profile_is_allowed(&profile) => Some(profile),
            _ => {
                return canonical_error_response(
                    StatusCode::CONFLICT,
                    "profile_not_available",
                    &request_id,
                );
            }
        },
    };
    // Model admission follows exact profile validation, but still precedes
    // command-context validation and every durable operation.
    if let Some(response) = admit_requested_model(
        &state,
        body.model.as_deref(),
        selected_profile.as_ref(),
        &request_id,
    ) {
        return response;
    }
    let context = match command_context(&headers, &principal, &state.actor) {
        Ok(context) => context,
        Err(code) => return bad_request(code, &request_id),
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
    let input = match body.model {
        Some(model) => match input.with_requested_model(model) {
            Ok(input) => input,
            Err(_) => return bad_request("invalid_requested_model", &request_id),
        },
        None => input,
    };
    if body.local_command.is_some()
        && (input.requested_model().is_some() || selected_profile.is_some())
    {
        return bad_request("invalid_task_run_input", &request_id);
    }
    let input = if let Some(profile) = selected_profile {
        match input.with_selected_profile(profile) {
            Ok(input) => input,
            Err(_) => return bad_request("invalid_task_run_input", &request_id),
        }
    } else {
        input
    };
    let input = if let Some(command) = body.local_command {
        let executable = match command.executable {
            LocalExecutableWire::WorkspaceRelative(value) => {
                runne_domain::task_run::TaskRunExecutable::workspace_relative(value)
            }
            LocalExecutableWire::SystemProgram(value) => {
                runne_domain::task_run::TaskRunExecutable::system_program(value)
            }
        };
        let executable = match executable {
            Ok(value) => value,
            Err(_) => return bad_request("invalid_local_command", &request_id),
        };
        let env = command
            .env
            .into_iter()
            .map(|entry| (entry.key, entry.value))
            .collect();
        let command = match runne_domain::task_run::TaskRunLocalCommand::new(
            executable,
            command.cwd,
            command.argv,
            env,
        ) {
            Ok(value) => value,
            Err(_) => return bad_request("invalid_local_command", &request_id),
        };
        match input.with_local_command(command) {
            Ok(value) => value,
            Err(_) => return bad_request("invalid_local_command", &request_id),
        }
    } else {
        input
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

fn decode_profile(
    wire: SelectedProfileWire,
) -> Option<runne_domain::task_run::SelectedProviderProfile> {
    let raw = wire.profile_digest.as_bytes();
    if raw.len() != 64 || !raw.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(
            std::str::from_utf8(&raw[index * 2..index * 2 + 2]).ok()?,
            16,
        )
        .ok()?;
    }
    runne_domain::task_run::SelectedProviderProfile::new(wire.profile_id, digest).ok()
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
        state
            .host
            .submit_task_run_legacy(
                context,
                LegacySubmitTaskRunCommand {
                    conversation_id,
                    workspace_id,
                },
            )
            .await,
        &request_id,
    )
}
