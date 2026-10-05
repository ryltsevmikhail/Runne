use super::*;

pub(super) fn is_active_cycle(
    connection: &rusqlite::Connection,
    receipt: &TextGenerationReceipt,
    original: &BeginConversationTextInput,
    scope: &runne_application::ports::IdempotencyScope,
    authority: &RuntimeAuthorityId,
) -> Result<bool, OrphanSettlementError> {
    use runne_domain::agent_loop::LoopCycleState;
    use runne_domain::task_run::{TaskRun, TaskRunState};
    if scope.runtime_authority_id != *authority
        || scope.operation != runne_application::ports::OperationTag::GenerateConversationText
        || scope.aggregate_scope
            != (runne_application::ports::AggregateScope::ExistingConversation {
                conversation_id: receipt.conversation_id,
            })
    {
        return Err(OrphanSettlementError::InvariantViolation);
    }
    let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
        connection,
        receipt.taskrun_id,
        None,
    )
    .map_err(|_| OrphanSettlementError::InvariantViolation)?;
    if stream.active_attempt != Some(receipt.attempt_id)
        || !matches!(
            stream.state,
            TaskRunState::Running | TaskRunState::Cancelling
        )
    {
        return Ok(false);
    }
    let task =
        TaskRun::replay(&stream.events).map_err(|_| OrphanSettlementError::InvariantViolation)?;
    let snapshot = task.snapshot_v1();
    let selected_d2 = snapshot
        .input()
        .and_then(|input| input.selected_profile())
        .is_some_and(|profile| profile.profile_id() == "runne-linux-agent-tools-v1");
    let Some(cycle) = snapshot.active_cycle() else {
        return Ok(false);
    };
    if !selected_d2
        || cycle.attempt_id != receipt.attempt_id
        || !matches!(
            cycle.state,
            LoopCycleState::Observing
                | LoopCycleState::Proposing
                | LoopCycleState::Acting
                | LoopCycleState::Evaluating
        )
    {
        return Err(OrphanSettlementError::InvariantViolation);
    }
    let origin = crate::store::taskrun_submit_origin::verify_submitted_v2_origin(
        connection,
        receipt.taskrun_id,
        authority,
    )
    .map_err(|_| OrphanSettlementError::InvariantViolation)?
    .ok_or(OrphanSettlementError::InvariantViolation)?;
    if origin.conversation_id != receipt.conversation_id
        || origin.workspace_id != receipt.workspace_id
        || origin.principal_id != scope.principal_id
        || origin.input.prompt() != original.text.as_str()
        || origin
            .input
            .selected_profile()
            .is_none_or(|profile| profile.profile_id() != "runne-linux-agent-tools-v1")
    {
        return Err(OrphanSettlementError::InvariantViolation);
    }
    let start_version = i64::try_from(receipt.taskrun_version)
        .map_err(|_| OrphanSettlementError::InvariantViolation)?;
    let started_payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
            rusqlite::params![receipt.taskrun_id.as_bytes(), start_version],
            |row| row.get(0),
        )
        .map_err(|_| OrphanSettlementError::InvariantViolation)?;
    if crate::codec::TaskRunEventCodec
        .decode(&started_payload)
        .map_err(|_| OrphanSettlementError::InvariantViolation)?
        != (runne_domain::task_run::TaskRunEvent::AttemptStarted {
            attempt_id: receipt.attempt_id,
        })
    {
        return Err(OrphanSettlementError::InvariantViolation);
    }
    Ok(true)
}
