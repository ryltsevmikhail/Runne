fn command_context(
    headers: &HeaderMap,
    principal: &AuthenticatedPrincipal,
    actor: &ApiActor,
) -> Result<ConversationCommandContext, &'static str> {
    let command_id = exactly_one_header(headers, "x-command-id")
        .and_then(|value| value.parse::<CommandId>().ok())
        .ok_or("invalid_command_id")?;
    let idempotency_key = exactly_one_header(headers, "idempotency-key")
        .and_then(|value| IdempotencyKey::new(value).ok())
        .ok_or("invalid_idempotency_key")?;
    Ok(ConversationCommandContext {
        command_id,
        idempotency_key,
        principal: principal.as_api_principal().clone(),
        actor: actor.clone(),
    })
}

fn exactly_one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn conversation_created_to_wire(ack: ConversationCreatedAck) -> ConversationCreatedWire {
    ConversationCreatedWire {
        conversation_id: ack.conversation_id.to_string(),
        workspace_id: ack.workspace_id.to_string(),
        stream_version: ack.stream_version,
        committed_at: ack.committed_at.as_i64(),
    }
}

fn message_to_wire(message: CanonicalConversationMessage) -> ConversationMessageWire {
    ConversationMessageWire {
        message_id: message.message_id.to_string(),
        role: message.role.as_str(),
        task_run_id: message.taskrun_id.to_string(),
        attempt_id: message.attempt_id.to_string(),
        text: message.text,
        committed_at: message.committed_at.as_i64(),
    }
}

fn text_result_to_wire(result: ConversationTextResult) -> ConversationTextResultWire {
    ConversationTextResultWire {
        conversation_id: result.conversation_id.to_string(),
        task_run_id: result.taskrun_id.to_string(),
        attempt_id: result.attempt_id.to_string(),
        conversation_stream_version: result.conversation_stream_version,
        task_run_stream_version: result.taskrun_stream_version,
        user_message: message_to_wire(result.user_message),
        assistant_message: message_to_wire(result.assistant_message),
    }
}

fn messages_to_wire(snapshot: ConversationMessagesSnapshot) -> ConversationMessagesWire {
    ConversationMessagesWire {
        conversation_id: snapshot.conversation_id.to_string(),
        stream_version: snapshot.stream_version,
        messages: snapshot.messages.into_iter().map(message_to_wire).collect(),
    }
}

fn host_error_response(error: ConversationHostError, request_id: &RequestId) -> Response {
    let status = match error {
        ConversationHostError::ProhibitedSecretMaterial => StatusCode::UNPROCESSABLE_ENTITY,
        ConversationHostError::ProviderOutputRejected => StatusCode::BAD_GATEWAY,
        ConversationHostError::NotFound => StatusCode::NOT_FOUND,
        ConversationHostError::Conflict => StatusCode::CONFLICT,
        ConversationHostError::Backpressure | ConversationHostError::Unavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        ConversationHostError::InvariantViolation => StatusCode::INTERNAL_SERVER_ERROR,
    };
    canonical_error_response(status, error.code(), request_id)
}

fn bad_request(code: &'static str, request_id: &RequestId) -> Response {
    canonical_error_response(StatusCode::BAD_REQUEST, code, request_id)
}
