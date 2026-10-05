use super::*;
use rusqlite::{OptionalExtension, params};

pub(super) fn verify_recovery_candidate(
    tx: &rusqlite::Transaction<'_>,
    candidate: &ToolInvocationAreaRecoveryCandidate,
    current_node: &ExecutionNodeId,
    current_epoch: u64,
    runtime_authority: &runne_application::ports::RuntimeAuthorityId,
) -> Result<(), ToolInvocationStoreError> {
    let node =
        uuid::Uuid::parse_str(&current_node.0).map_err(|_| ToolInvocationStoreError::Conflict)?;
    if current_node != &candidate.assignment.node_id
        || current_epoch <= candidate.assignment.node_epoch
        || uuid::Uuid::parse_str(&runtime_authority.0)
            .map_err(|_| ToolInvocationStoreError::Conflict)?
            != node
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let now = validate::fresh_now_millis();
    let registered: Option<(i64, i64)> = tx
        .query_row(
            "SELECT launch_generation,expires_at_ms FROM execution_nodes WHERE node_id=?1",
            [node.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if registered.is_none_or(|(epoch, expiry)| epoch != current_epoch as i64 || expiry <= now) {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let stream = super::super::super::taskrun_claim::stream_validate::verify_stream(
        tx,
        candidate.key.taskrun_id,
        None,
    )
    .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if !matches!(
        stream.state,
        runne_domain::task_run::TaskRunState::Running
            | runne_domain::task_run::TaskRunState::Cancelling
            | runne_domain::task_run::TaskRunState::Succeeded
            | runne_domain::task_run::TaskRunState::Failed
            | runne_domain::task_run::TaskRunState::Cancelled
            | runne_domain::task_run::TaskRunState::Unrecoverable
    ) {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let historical: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_assignments a JOIN taskrun_claim_receipts c USING(taskrun_id,fence,attempt_id,node_id,node_epoch) WHERE a.taskrun_id=?1 AND a.fence=?2 AND a.attempt_id=?3 AND a.node_id=?4 AND a.node_epoch=?5 AND c.command_id=a.command_id AND c.admitted_event_id=a.admitted_event_id AND c.started_event_id=a.started_event_id AND c.new_version>0)",
            params![candidate.key.taskrun_id.as_bytes(),candidate.assignment.fence.0 as i64,candidate.key.attempt_id.as_bytes(),node.as_bytes(),candidate.assignment.node_epoch as i64],
            |row| row.get(0),
        )
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let record =
        read::load_record(tx, candidate.key)?.ok_or(ToolInvocationStoreError::InvalidState)?;
    if !historical
        || record.receipt.semantic_digest != candidate.semantic_digest
        || record.binding.key != candidate.key
        || record.claim_assignment.as_ref() != Some(&candidate.assignment)
        || record.managed_area_identity != Some(candidate.area_identity)
        || record.local_stop_state != LocalToolStopState::Launched
        || record
            .binding
            .key
            .managed_area_nonce(candidate.semantic_digest)
            != candidate.area_identity[84..100]
        || record.receipt.state != candidate.state
        || record.release_started != candidate.release_started
        || !matches!(
            record.receipt.state,
            ToolInvocationState::Claimed
                | ToolInvocationState::Uncertain
                | ToolInvocationState::Cancelled
                | ToolInvocationState::AuditOnly
        )
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    Ok(())
}
