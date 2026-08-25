use super::super::TaskRunTimelineKind;
use super::{
    CanonicalId, CanonicalReplayPayload, ConversationReplayPayload, HashSet, MAXIMUM_REASON_BYTES,
    MAXIMUM_TEXT_BYTES, ReplayAggregateKind, ReplayClientError, ReplayClientErrorKind,
    TaskRunReplayPayload, parse_uuid_v7, validate_exact_keys,
};

pub(super) fn validate_payload(
    aggregate_kind: ReplayAggregateKind,
    event_type: &str,
    value: &serde_json::Value,
) -> Result<CanonicalReplayPayload, ReplayClientError> {
    match aggregate_kind {
        ReplayAggregateKind::Conversation => validate_conversation_payload(event_type, value)
            .map(CanonicalReplayPayload::Conversation),
        ReplayAggregateKind::TaskRun => {
            validate_task_run_payload(event_type, value).map(CanonicalReplayPayload::TaskRun)
        }
    }
}
include!("payload/conversation.rs");
include!("payload/task_run.rs");
include!("payload/fields.rs");
