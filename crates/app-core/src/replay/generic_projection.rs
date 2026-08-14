use crate::{
    AppCoreError, ConversationMessageSummary, ConversationRecoveryDisposition,
    ConversationSnapshot, StoredConversationReference,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalConversationPromotion {
    schema_version: u32,
    kind: String,
    aggregate_id: String,
    workspace_id: String,
    state: String,
    messages: Vec<LocalPromotionMessage>,
    active_generation: Option<LocalActiveGeneration>,
    projection_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalPromotionMessage {
    message_id: String,
    role: String,
    task_run_id: String,
    attempt_id: String,
    text: String,
    committed_at_micros: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct LocalActiveGeneration {
    user_message_id: String,
    task_run_id: String,
    attempt_id: String,
}

pub(super) fn conversation_snapshot(
    bytes: &[u8],
    revision: u64,
    sequence: u64,
    reference: &StoredConversationReference,
) -> Result<ConversationSnapshot, AppCoreError> {
    let value: LocalConversationPromotion =
        serde_json::from_slice(bytes).map_err(|_| AppCoreError::LocalProjectionUnavailable)?;
    if value.schema_version != 1
        || value.kind != "conversation"
        || canonical_id(&value.aggregate_id).as_deref()
            != Some(&reference.conversation_id().to_string())
        || canonical_id(&value.workspace_id).as_deref()
            != Some(&reference.workspace_id().to_string())
        || !matches!(value.state.as_str(), "active" | "closed")
        || !lower_hex_digest(&value.projection_digest)
    {
        return Err(AppCoreError::LocalProjectionUnavailable);
    }
    if let Some(active) = value.active_generation.as_ref()
        && [
            &active.user_message_id,
            &active.task_run_id,
            &active.attempt_id,
        ]
        .into_iter()
        .any(|id| canonical_id(id).is_none())
    {
        return Err(AppCoreError::LocalProjectionUnavailable);
    }
    let messages = value
        .messages
        .into_iter()
        .map(|message| {
            let committed_at = u64::try_from(message.committed_at_micros)
                .map_err(|_| AppCoreError::LocalProjectionUnavailable)?;
            let Some(message_id) = canonical_id(&message.message_id) else {
                return Err(AppCoreError::LocalProjectionUnavailable);
            };
            let Some(task_run_id) = canonical_id(&message.task_run_id) else {
                return Err(AppCoreError::LocalProjectionUnavailable);
            };
            let Some(attempt_id) = canonical_id(&message.attempt_id) else {
                return Err(AppCoreError::LocalProjectionUnavailable);
            };
            if !matches!(message.role.as_str(), "user" | "assistant")
                || message.text.len() > 64 * 1024
            {
                return Err(AppCoreError::LocalProjectionUnavailable);
            }
            Ok(ConversationMessageSummary {
                message_id,
                role: message.role,
                task_run_id,
                attempt_id,
                text: message.text,
                committed_at,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ConversationSnapshot {
        conversation_id: reference.conversation_id().to_string(),
        projection_revision: revision,
        stream_version: sequence,
        messages,
        recovery: ConversationRecoveryDisposition::Live,
    })
}

pub(super) fn legacy_projection(
    bytes: &[u8],
    revision: u64,
    sequence: u64,
    reference: &StoredConversationReference,
) -> Result<super::StoredConversationProjection, AppCoreError> {
    let snapshot = conversation_snapshot(bytes, revision, sequence, reference)?;
    let value: LocalConversationPromotion =
        serde_json::from_slice(bytes).map_err(|_| AppCoreError::LocalProjectionUnavailable)?;
    Ok(super::StoredConversationProjection {
        schema_version: super::PROJECTION_SCHEMA_VERSION,
        conversation_id: snapshot.conversation_id,
        workspace_id: reference.workspace_id().to_string(),
        projection_revision: snapshot.projection_revision,
        stream_version: snapshot.stream_version,
        messages: snapshot.messages,
        closed: value.state == "closed",
    })
}

fn canonical_id(hex: &str) -> Option<String> {
    (hex.len() == 32
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| {
        format!(
            "{}-{}-{}-{}-{}",
            &hex[..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..]
        )
    })
}

fn lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::conversation_snapshot;

    #[test]
    fn maps_complete_canonical_conversation_without_shadow_identity() {
        let reference = crate::parse_conversation_reference(
            r#"{"schemaVersion":1,"conversationId":"018f2e3a-7000-7000-8000-000000000011","workspaceId":"018f2e3a-7000-7000-8000-000000000012","createCommandId":"018f2e3a-7000-7000-8000-000000000013","idempotencyKey":"018f2e3a-7000-7000-8000-000000000013"}"#,
        )
        .expect("reference");
        let value = br#"{"schemaVersion":1,"kind":"conversation","aggregateId":"018f2e3a700070008000000000000011","workspaceId":"018f2e3a700070008000000000000012","state":"active","messages":[{"messageId":"018f2e3a700070008000000000000014","role":"user","taskRunId":"018f2e3a700070008000000000000015","attemptId":"018f2e3a700070008000000000000016","text":"ship it","committedAtMicros":1723500000123456}],"activeGeneration":{"userMessageId":"018f2e3a700070008000000000000014","taskRunId":"018f2e3a700070008000000000000015","attemptId":"018f2e3a700070008000000000000016"},"projectionDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;

        let snapshot = conversation_snapshot(value, 9, 7, &reference).expect("canonical view");

        assert_eq!(
            snapshot.conversation_id,
            "018f2e3a-7000-7000-8000-000000000011"
        );
        assert_eq!(snapshot.projection_revision, 9);
        assert_eq!(snapshot.stream_version, 7);
        assert_eq!(snapshot.messages[0].text, "ship it");
        assert_eq!(snapshot.messages[0].committed_at, 1_723_500_000_123_456);
    }
}
