#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateConversationWire {
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    scope: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateTextWire<'a> {
    expected_version: u64,
    text: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExistingTaskRunWire {
    expected_version: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationCreatedWire {
    conversation_id: CanonicalId,
    workspace_id: CanonicalId,
    stream_version: u64,
    committed_at: u64,
}

impl From<ConversationCreatedWire> for ConversationCreated {
    fn from(wire: ConversationCreatedWire) -> Self {
        Self {
            conversation_id: wire.conversation_id,
            workspace_id: wire.workspace_id,
            stream_version: wire.stream_version,
            committed_at: wire.committed_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConversationMessageRoleWire {
    User,
    Assistant,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationMessageWire {
    message_id: CanonicalId,
    role: ConversationMessageRoleWire,
    task_run_id: CanonicalId,
    attempt_id: CanonicalId,
    text: String,
    committed_at: u64,
}

impl TryFrom<ConversationMessageWire> for ConversationMessage {
    type Error = RuntimeApiError;

    fn try_from(wire: ConversationMessageWire) -> Result<Self, Self::Error> {
        validate_message_text(&wire.text)?;
        Ok(Self {
            message_id: wire.message_id,
            role: match wire.role {
                ConversationMessageRoleWire::User => ConversationMessageRole::User,
                ConversationMessageRoleWire::Assistant => ConversationMessageRole::Assistant,
            },
            task_run_id: wire.task_run_id,
            attempt_id: wire.attempt_id,
            text: wire.text,
            committed_at: wire.committed_at,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationTextResultWire {
    conversation_id: CanonicalId,
    task_run_id: CanonicalId,
    attempt_id: CanonicalId,
    conversation_stream_version: u64,
    task_run_stream_version: u64,
    user_message: ConversationMessageWire,
    assistant_message: ConversationMessageWire,
}

impl TryFrom<ConversationTextResultWire> for ConversationTextResult {
    type Error = RuntimeApiError;

    fn try_from(wire: ConversationTextResultWire) -> Result<Self, Self::Error> {
        let user_message = ConversationMessage::try_from(wire.user_message)?;
        let assistant_message = ConversationMessage::try_from(wire.assistant_message)?;
        if user_message.role != ConversationMessageRole::User
            || assistant_message.role != ConversationMessageRole::Assistant
            || user_message.task_run_id != wire.task_run_id
            || assistant_message.task_run_id != wire.task_run_id
            || user_message.attempt_id != wire.attempt_id
            || assistant_message.attempt_id != wire.attempt_id
        {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse));
        }
        Ok(Self {
            conversation_id: wire.conversation_id,
            task_run_id: wire.task_run_id,
            attempt_id: wire.attempt_id,
            conversation_stream_version: wire.conversation_stream_version,
            task_run_stream_version: wire.task_run_stream_version,
            user_message,
            assistant_message,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationMessagesWire {
    conversation_id: CanonicalId,
    stream_version: u64,
    messages: Vec<ConversationMessageWire>,
}

impl TryFrom<ConversationMessagesWire> for ConversationMessages {
    type Error = RuntimeApiError;

    fn try_from(wire: ConversationMessagesWire) -> Result<Self, Self::Error> {
        let messages = wire
            .messages
            .into_iter()
            .map(ConversationMessage::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            conversation_id: wire.conversation_id,
            stream_version: wire.stream_version,
            messages,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorEnvelope {
    code: String,
    request_id: String,
}

async fn read_success_json<T>(
    response: reqwest::Response,
    expected_statuses: &[u16],
) -> Result<T, RuntimeApiError>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status().as_u16();
    if !expected_statuses.contains(&status) {
        return Err(read_error(response).await);
    }
    let body = read_bounded(response, MAXIMUM_CANONICAL_RESPONSE_BYTES).await?;
    serde_json::from_slice(&body)
        .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse))
}

async fn read_error(response: reqwest::Response) -> RuntimeApiError {
    let status = response.status().as_u16();
    let request_id_header = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| CanonicalId::parse(value).is_ok())
        .map(str::to_owned);
    let body = match read_bounded(response, MAXIMUM_ERROR_RESPONSE_BYTES).await {
        Ok(body) => body,
        Err(error) => return error,
    };
    let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(&body) else {
        return RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse);
    };
    if CanonicalId::parse(&envelope.request_id).is_err()
        || request_id_header.as_deref() != Some(envelope.request_id.as_str())
    {
        return RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse);
    }
    let kind = match (status, envelope.code.as_str()) {
        (
            400,
            "invalid_request"
            | "invalid_conversation_id"
            | "invalid_workspace_id"
            | "invalid_project_id"
            | "invalid_display_name"
            | "invalid_expected_version"
            | "invalid_page"
            | "invalid_root_admission"
            | "invalid_command_id"
            | "invalid_idempotency_key"
            | "invalid_task_run_id"
            | "invalid_attempt_id"
            | "invalid_invocation_id"
            | "message_text_empty"
            | "message_text_too_large"
            | "invalid_process_id"
            | "invalid_output_query"
            | "invalid_process_output_query"
            | "invalid_process_output_limit"
            | "invalid_process_output"
            | "invalid_provider"
            | "invalid_provider_credential",
        ) => RuntimeApiErrorKind::InvalidRequest,
        (401, "unauthorized") | (403, "forbidden" | "provider_credential_forbidden") => {
            RuntimeApiErrorKind::Unauthorized
        }
        (403, "managed_trust_policy") => RuntimeApiErrorKind::ManagedPolicy,
        (
            404,
            "conversation_not_found"
            | "task_run_not_found"
            | "project_workspace_not_found"
            | "process_not_found"
            | "workspace_diff_not_found",
        ) => RuntimeApiErrorKind::NotFound,
        (
            409,
            "conversation_conflict"
            | "conversation_writer_fenced"
            | "conversation_writer_lease_conflict"
            | "task_run_conflict"
            | "project_workspace_conflict"
            | "command_conflict"
            | "process_conflict"
            | "provider_credential_conflict"
            | "trust_control_conflict",
        ) => RuntimeApiErrorKind::Conflict,
        (409, "model_mismatch") => RuntimeApiErrorKind::ModelMismatch,
        (409, "trust_root_unavailable") => RuntimeApiErrorKind::RootUnavailable,
        (413, "process_output_too_large") => RuntimeApiErrorKind::ResponseTooLarge,
        (422, "prohibited_secret_material") => RuntimeApiErrorKind::ProhibitedInputRejected,
        (502, "conversation_outcome_unknown") => RuntimeApiErrorKind::OutcomeUnknown,
        (429, "runtime_backpressure") => RuntimeApiErrorKind::Backpressure,
        (
            503,
            "runtime_unavailable"
            | "provider_credential_unsupported"
            | "provider_credential_unavailable"
            | "trust_control_unavailable",
        ) => RuntimeApiErrorKind::Unavailable,
        _ => RuntimeApiErrorKind::InvalidResponse,
    };
    if kind == RuntimeApiErrorKind::InvalidResponse {
        return RuntimeApiError::new(kind);
    }
    RuntimeApiError {
        kind,
        request_id: Some(envelope.request_id),
    }
}

async fn read_bounded(
    mut response: reqwest::Response,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RuntimeApiError> {
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(maximum_bytes).unwrap_or(u64::MAX))
    {
        return Err(RuntimeApiError::new(RuntimeApiErrorKind::ResponseTooLarge));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_transport)? {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(RuntimeApiError::new(RuntimeApiErrorKind::ResponseTooLarge));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

const fn validate_message_text(text: &str) -> Result<(), RuntimeApiError> {
    if text.is_empty() || text.len() > MAXIMUM_MESSAGE_TEXT_BYTES {
        return Err(RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest));
    }
    Ok(())
}

fn map_transport(_: reqwest::Error) -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::Unavailable)
}
