fn validate_conversation_payload(
    event_type: &str,
    value: &serde_json::Value,
) -> Result<ConversationReplayPayload, ReplayClientError> {
    let object = payload_object(value)?;
    match event_type {
        "conversation.created" => {
            validate_exact_keys(object, &["type", "workspaceId"])?;
            Ok(ConversationReplayPayload::Created {
                workspace_id: uuid_field(object, "workspaceId")?,
            })
        }
        "conversation.message.appended" => {
            validate_exact_keys(
                object,
                &[
                    "attemptId",
                    "messageId",
                    "role",
                    "taskRunId",
                    "text",
                    "type",
                ],
            )?;
            let role = match string_field(object, "role")? {
                "user" => crate::ConversationMessageRole::User,
                "assistant" => crate::ConversationMessageRole::Assistant,
                _ => {
                    return Err(ReplayClientError::new(
                        ReplayClientErrorKind::SchemaMismatch,
                    ));
                }
            };
            let text = bounded_string_field(object, "text", MAXIMUM_TEXT_BYTES)?;
            Ok(ConversationReplayPayload::MessageAppended {
                role,
                message_id: uuid_field(object, "messageId")?,
                task_run_id: uuid_field(object, "taskRunId")?,
                attempt_id: uuid_field(object, "attemptId")?,
                text: text.to_owned(),
            })
        }
        "conversation.generation.failed" => {
            validate_exact_keys(object, &["attemptId", "reason", "taskRunId", "type"])?;
            Ok(ConversationReplayPayload::GenerationFailed {
                task_run_id: uuid_field(object, "taskRunId")?,
                attempt_id: uuid_field(object, "attemptId")?,
                reason: bounded_string_field(object, "reason", MAXIMUM_REASON_BYTES)?.to_owned(),
            })
        }
        "conversation.closed" => {
            validate_exact_keys(object, &["type"])?;
            Ok(ConversationReplayPayload::Closed)
        }
        _ => Err(ReplayClientError::new(
            ReplayClientErrorKind::SchemaMismatch,
        )),
    }
}
