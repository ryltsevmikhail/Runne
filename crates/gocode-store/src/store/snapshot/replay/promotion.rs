use gocode_api::{
    ReplayPromotionProjectionV1, ReplayPromotionProjectionViewV1,
    UnauthenticatedReplayPromotionProjectionV1,
};
use gocode_domain::{
    conversation::{ConversationEvent, ConversationSnapshotV1},
    event::EventEnvelope,
    timestamp::Timestamp,
};

use super::invalid;

pub(super) fn conversation_projection(
    snapshot: &ConversationSnapshotV1,
    events: &[EventEnvelope<ConversationEvent>],
) -> rusqlite::Result<(Vec<u8>, [u8; 32])> {
    let committed_at = matching_message_times(snapshot, events)?;
    let bytes = ReplayPromotionProjectionV1::encode_conversation(snapshot, &committed_at)
        .map_err(|_| invalid())?;
    let decoded =
        UnauthenticatedReplayPromotionProjectionV1::decode(&bytes).map_err(|_| invalid())?;
    let ReplayPromotionProjectionViewV1::Conversation(view) = decoded.view() else {
        return Err(invalid());
    };
    if view.aggregate_id() != *snapshot.id().as_bytes() {
        return Err(invalid());
    }
    Ok((bytes, *view.projection_digest()))
}

pub(super) fn taskrun_projection(
    snapshot: &gocode_domain::task_run::TaskRunSnapshotV1,
) -> rusqlite::Result<(Vec<u8>, [u8; 32])> {
    let bytes = ReplayPromotionProjectionV1::encode_task_run(snapshot).map_err(|_| invalid())?;
    let decoded =
        UnauthenticatedReplayPromotionProjectionV1::decode(&bytes).map_err(|_| invalid())?;
    let ReplayPromotionProjectionViewV1::TaskRun(view) = decoded.view() else {
        return Err(invalid());
    };
    if view.aggregate_id() != *snapshot.id().as_bytes() {
        return Err(invalid());
    }
    Ok((bytes, *view.promotion_digest()))
}

fn matching_message_times(
    snapshot: &ConversationSnapshotV1,
    events: &[EventEnvelope<ConversationEvent>],
) -> rusqlite::Result<Vec<Timestamp>> {
    let appended = events
        .iter()
        .filter_map(|event| match event.payload() {
            ConversationEvent::UserMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => Some((
                message_id,
                gocode_domain::message::MessageRole::User,
                taskrun_id,
                attempt_id,
                text,
                event.timestamp(),
            )),
            ConversationEvent::AssistantMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => Some((
                message_id,
                gocode_domain::message::MessageRole::Assistant,
                taskrun_id,
                attempt_id,
                text,
                event.timestamp(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    if appended.len() != snapshot.messages().len() {
        return Err(invalid());
    }
    snapshot
        .messages()
        .iter()
        .zip(appended)
        .map(|(message, event)| {
            let (message_id, role, taskrun_id, attempt_id, text, timestamp) = event;
            if message.message_id != *message_id
                || message.role != role
                || message.taskrun_id != *taskrun_id
                || message.attempt_id != *attempt_id
                || message.text != *text
                || timestamp.as_unix_micros() <= 0
            {
                return Err(invalid());
            }
            Ok(*timestamp)
        })
        .collect()
}
