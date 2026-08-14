use serde_json::{Value, json};

use super::{ConversationPromotionViewV1, ReplayPromotionProjectionViewV1};
mod taskrun;

/// Encodes a complete, deterministic local promotion document from the closed
/// semantic DTO. It never accepts local fields or exposes the source snapshot.
pub fn canonical_local_promotion_json(
    value: &ReplayPromotionProjectionViewV1,
) -> Result<Value, crate::ReplayContractError> {
    match value {
        ReplayPromotionProjectionViewV1::Conversation(view) => Ok(conversation(view)),
        ReplayPromotionProjectionViewV1::TaskRun(view) => Ok(taskrun::encode(view)),
    }
}

fn conversation(view: &ConversationPromotionViewV1) -> Value {
    let messages = view
        .messages()
        .iter()
        .map(|message| {
            json!({
                "messageId": hex(&message.message_id()),
                "role": message.role().as_str(),
                "taskRunId": hex(&message.taskrun_id()),
                "attemptId": hex(&message.attempt_id()),
                "text": message.text(),
                "committedAtMicros": message.committed_at_micros(),
            })
        })
        .collect::<Vec<_>>();
    let active = view.active_generation().map(|value| {
        json!({
            "userMessageId": hex(value.user_message_id.as_bytes()),
            "taskRunId": hex(value.taskrun_id.as_bytes()),
            "attemptId": hex(value.attempt_id.as_bytes()),
        })
    });
    json!({
        "schemaVersion": 1,
        "kind": "conversation",
        "aggregateId": hex(&view.aggregate_id()),
        "workspaceId": hex(&view.workspace_id()),
        "state": match view.state() { gocode_domain::conversation::ConversationState::Active => "active", gocode_domain::conversation::ConversationState::Closed => "closed" },
        "messages": messages,
        "activeGeneration": active,
        "projectionDigest": hex(view.projection_digest()),
    })
}

pub(super) fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
