use super::*;

pub(super) fn valid_event_context<E>(
    event: &UncommittedEvent<E>,
    command_id: CommandId,
    idempotency_key: &gocode_domain::id::IdempotencyKey,
    aggregate_id: AggregateId,
    sensitivity: Sensitivity,
) -> bool {
    event.command_id() == &command_id
        && event.idempotency_key() == idempotency_key
        && event.aggregate_id() == &aggregate_id
        && event.correlation_id() == &aggregate_id
        && event.schema_version() == 1
        && event.sensitivity() == &sensitivity
}
