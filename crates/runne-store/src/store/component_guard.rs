use super::append_helpers::*;
use super::parse_helpers::*;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn guard_event_components<E>(
    prohibited_content: &dyn ProhibitedContentPort,
    event: &UncommittedEvent<E>,
    aggregate_type: i64,
    aggregate_id: &[u8; 16],
    sequence: u64,
    global_position: i64,
    timestamp: i64,
    payload: &[u8],
    digest: IntegrityDigest,
    integrity_profile: i64,
) -> Result<(), CommitError> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"GOCODE_STORED_EVENT_V1\0");
    append_guard_component(&mut encoded, event.event_id().as_bytes());
    append_guard_component(&mut encoded, &aggregate_type.to_be_bytes());
    append_guard_component(&mut encoded, aggregate_id);
    append_guard_component(&mut encoded, &sequence.to_be_bytes());
    append_guard_component(&mut encoded, &global_position.to_be_bytes());
    append_guard_component(&mut encoded, &timestamp.to_be_bytes());
    append_guard_component(
        &mut encoded,
        &sensitivity_value(*event.sensitivity()).to_be_bytes(),
    );
    append_guard_component(&mut encoded, &event.schema_version().to_be_bytes());
    match event.causation_id() {
        Some(id) => append_guard_component(&mut encoded, id.as_bytes()),
        None => append_guard_component(&mut encoded, &[]),
    }
    append_guard_component(&mut encoded, event.command_id().as_bytes());
    append_guard_component(&mut encoded, event.idempotency_key().as_str().as_bytes());
    append_guard_component(&mut encoded, event.actor().as_str().as_bytes());
    append_guard_component(&mut encoded, payload);
    append_guard_component(&mut encoded, digest.as_bytes());
    let (correlation_id, correlation_type) = match event.correlation_id() {
        AggregateId::TaskRun(id) => (id.as_bytes(), CORRELATION_TYPE_TASK_RUN),
        AggregateId::Conversation(id) => (id.as_bytes(), CORRELATION_TYPE_CONVERSATION),
        AggregateId::Workspace(_) => {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    };
    append_guard_component(&mut encoded, correlation_id);
    append_guard_component(&mut encoded, &correlation_type.to_be_bytes());
    append_guard_component(&mut encoded, &integrity_profile.to_be_bytes());

    match prohibited_content.inspect(CanonicalContentBoundary::CanonicalMutation, &encoded) {
        Ok(ContentDisposition::Allowed { .. }) => Ok(()),
        Ok(ContentDisposition::Prohibited { .. }) | Err(_) => {
            Err(storage_failure(StorageFailureKind::PolicyDenied))
        }
    }
}
