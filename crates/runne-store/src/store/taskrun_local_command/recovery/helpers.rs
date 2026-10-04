use super::super::LocalCommandAttemptState;
use super::super::LocalCommandRecoveryCandidate;
use runne_application::ports::EventStoreError;
#[cfg(target_os = "linux")]
use runne_application::ports::ExecutionNodeId;
#[cfg(target_os = "linux")]
use runne_platform::process_managed_area::ManagedAreaIdentity;
use rusqlite::{OptionalExtension, params};

#[cfg(target_os = "linux")]
pub(in crate::store::taskrun_local_command) fn verify_recovery_owner(
    tx: &rusqlite::Transaction<'_>,
    candidate: &LocalCommandRecoveryCandidate,
    current_node: &ExecutionNodeId,
    current_epoch: u64,
    runtime_authority: &runne_application::ports::RuntimeAuthorityId,
) -> Result<(), EventStoreError> {
    if current_node != &candidate.identity.node_id || current_epoch <= candidate.identity.node_epoch
    {
        return Err(EventStoreError::CorruptData);
    }
    let node = uuid::Uuid::parse_str(&current_node.0).map_err(|_| EventStoreError::CorruptData)?;
    if uuid::Uuid::parse_str(&runtime_authority.0).map_err(|_| EventStoreError::CorruptData)?
        != node
    {
        return Err(EventStoreError::CorruptData);
    }
    let registered: Option<(i64, i64)> = tx
        .query_row(
            "SELECT launch_generation,expires_at_ms FROM execution_nodes WHERE node_id=?1",
            [node.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((epoch, expires_at)) = registered else {
        return Err(EventStoreError::CorruptData);
    };
    let expected_epoch = i64::try_from(current_epoch).map_err(|_| EventStoreError::CorruptData)?;
    if epoch != expected_epoch || expires_at <= now_millis() {
        return Err(EventStoreError::CorruptData);
    }
    verify_historical_assignment(tx, candidate)?;
    let state = read_exact_state(tx, candidate)?;
    let (digest, conversation, workspace): (Vec<u8>, Vec<u8>, Vec<u8>) = tx
        .query_row(
            "SELECT command_digest,conversation_id,workspace_id FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [candidate.identity.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let origin = crate::store::taskrun_submit_origin::verify_submitted_v2_origin(
        tx,
        candidate.identity.taskrun_id,
        runtime_authority,
    )
    .map_err(|_| EventStoreError::CorruptData)?
    .ok_or(EventStoreError::CorruptData)?;
    let local_command = origin
        .input
        .local_command()
        .ok_or(EventStoreError::CorruptData)?;
    if digest.as_slice() != local_command.intent_digest()
        || conversation.as_slice() != origin.conversation_id.as_bytes()
        || workspace.as_slice() != origin.workspace_id.as_bytes()
    {
        return Err(EventStoreError::CorruptData);
    }
    let area = ManagedAreaIdentity::from_bytes(&candidate.area_identity)
        .map_err(|_| EventStoreError::CorruptData)?;
    let bytes = area.to_bytes();
    if &bytes[52..68] != candidate.identity.taskrun_id.as_bytes()
        || &bytes[68..84] != candidate.identity.attempt_id.as_bytes()
    {
        return Err(EventStoreError::CorruptData);
    }
    if !matches!(
        state,
        LocalCommandAttemptState::LaunchIntent
            | LocalCommandAttemptState::ReleaseReserved
            | LocalCommandAttemptState::Running
            | LocalCommandAttemptState::CancelRequested
            | LocalCommandAttemptState::Completed
            | LocalCommandAttemptState::Cancelled
            | LocalCommandAttemptState::StopUnconfirmed
            | LocalCommandAttemptState::OutcomeUnknown
    ) {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_historical_assignment(
    tx: &rusqlite::Transaction<'_>,
    candidate: &LocalCommandRecoveryCandidate,
) -> Result<(), EventStoreError> {
    let node = uuid::Uuid::parse_str(&candidate.identity.node_id.0)
        .map_err(|_| EventStoreError::CorruptData)?;
    let valid: bool = tx
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM taskrun_assignments a
               JOIN taskrun_claim_receipts c USING(taskrun_id,fence)
               JOIN taskrun_assignment_occupations o USING(taskrun_id,fence)
               WHERE a.taskrun_id=?1 AND a.attempt_id=?2 AND a.node_id=?3 AND a.node_epoch=?4 AND a.fence=?5
                 AND c.taskrun_id=a.taskrun_id AND c.attempt_id=a.attempt_id AND c.node_id=a.node_id
                 AND c.node_epoch=a.node_epoch AND c.command_id=a.command_id
                 AND c.admitted_event_id=a.admitted_event_id AND c.started_event_id=a.started_event_id
                 AND o.attempt_id=a.attempt_id AND o.node_id=a.node_id AND o.node_epoch=a.node_epoch
                 AND o.dispatch_intent='absent'
                 AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents d
                   WHERE d.taskrun_id=a.taskrun_id AND d.fence=a.fence)
                 AND NOT EXISTS(SELECT 1 FROM taskrun_provider_bindings b
                   WHERE b.taskrun_id=a.taskrun_id AND b.fence=a.fence)
                 AND ((o.state='active' AND o.release_event_id IS NULL)
                   OR (o.state='released' AND o.release_event_id IS NOT NULL AND (
                     EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts t
                       WHERE t.taskrun_id=o.taskrun_id AND t.fence=o.fence
                         AND t.attempt_id=a.attempt_id AND t.node_id=a.node_id
                         AND t.node_epoch=a.node_epoch AND t.terminal_event_id=o.release_event_id)
                     OR EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts n
                       WHERE n.taskrun_id=o.taskrun_id AND n.fence=o.fence
                         AND n.attempt_id=a.attempt_id AND n.failure_event_id=o.release_event_id
                         AND n.new_version=(SELECT sequence FROM events WHERE event_id=o.release_event_id))
                   )))
             )",
            params![
                candidate.identity.taskrun_id.as_bytes(),
                candidate.identity.attempt_id.as_bytes(),
                node.as_bytes(),
                candidate.identity.node_epoch as i64,
                candidate.identity.fence.0 as i64,
            ],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if valid {
        Ok(())
    } else {
        Err(EventStoreError::CorruptData)
    }
}

pub(in crate::store::taskrun_local_command::recovery) fn read_exact_state(
    tx: &rusqlite::Transaction<'_>,
    candidate: &LocalCommandRecoveryCandidate,
) -> Result<LocalCommandAttemptState, EventStoreError> {
    let state: Option<String> = tx.query_row(
        "SELECT state FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2 AND node_id=?3 AND node_epoch=?4 AND fence=?5 AND managed_area_identity=?6",
        params![candidate.identity.taskrun_id.as_bytes(),candidate.identity.attempt_id.as_bytes(),uuid::Uuid::parse_str(&candidate.identity.node_id.0).map_err(|_| EventStoreError::CorruptData)?.as_bytes(),candidate.identity.node_epoch as i64,candidate.identity.fence.0 as i64,candidate.area_identity],
        |row| row.get(0),
    ).optional().map_err(|_| EventStoreError::CorruptData)?;
    state
        .as_deref()
        .ok_or(EventStoreError::CorruptData)
        .and_then(LocalCommandAttemptState::from_sql)
}

pub(super) fn fixed_id<const N: usize>(bytes: &[u8]) -> Result<[u8; N], EventStoreError> {
    bytes.try_into().map_err(|_| EventStoreError::CorruptData)
}

pub(super) fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
