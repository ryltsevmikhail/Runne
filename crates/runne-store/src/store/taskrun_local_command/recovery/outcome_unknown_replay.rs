use super::super::LocalCommandRecoveryCandidate;
use crate::codec::{StoreCodec, TaskRunEventCodec};
use runne_application::ports::EventStoreError;
use runne_domain::task_run::TaskRunState;
use runne_platform::process_managed_area::VerifiedEmptyManagedArea;
use rusqlite::{OptionalExtension, params};

pub(super) fn replay_existing_receipt(
    tx: &rusqlite::Transaction<'_>,
    candidate: &LocalCommandRecoveryCandidate,
    current_epoch: u64,
    empty: &VerifiedEmptyManagedArea<'_>,
) -> Result<bool, EventStoreError> {
    type Receipt = (
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        String,
        Vec<u8>,
        i64,
    );
    let row: Option<Receipt> = tx
        .query_row(
            "SELECT attempt_id,historic_node_epoch,historic_node_id,proof_node_id,
                    proof_node_epoch,managed_area_identity,command_digest,stop_kind,
                    terminal_event_id,terminal_version
             FROM taskrun_local_command_stop_receipts WHERE taskrun_id=?1 AND fence=?2",
            params![
                candidate.identity.taskrun_id.as_bytes(),
                candidate.identity.fence.0 as i64
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((
        attempt,
        historic_epoch,
        historic_node,
        proof_node,
        proof_epoch,
        area_identity,
        digest,
        stop_kind,
        terminal,
        version,
    )) = row
    else {
        return Ok(false);
    };
    let node = uuid::Uuid::parse_str(&candidate.identity.node_id.0)
        .map_err(|_| EventStoreError::CorruptData)?;
    let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
        tx,
        candidate.identity.taskrun_id,
        None,
    )
    .map_err(|_| EventStoreError::CorruptData)?;
    let released: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_assignment_occupations o
             JOIN taskrun_terminal_settlement_receipts t USING(taskrun_id,fence)
             WHERE o.taskrun_id=?1 AND o.fence=?2 AND o.attempt_id=?3 AND o.node_id=?4
               AND o.node_epoch=?5 AND o.dispatch_intent='absent'
               AND o.state='released' AND o.release_event_id=?6
               AND t.attempt_id=?3 AND t.node_id=?4 AND t.node_epoch=?5
               AND t.terminal_event_id=?6 AND t.terminal_version=?7)",
            params![
                candidate.identity.taskrun_id.as_bytes(),
                candidate.identity.fence.0 as i64,
                attempt,
                node.as_bytes(),
                candidate.identity.node_epoch as i64,
                terminal,
                version
            ],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let last_event: Vec<u8> = tx
        .query_row(
            "SELECT last_event_id FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
            [candidate.identity.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let (local_state, exit_code, local_area, local_digest): (
        String,
        Option<i32>,
        Vec<u8>,
        Vec<u8>,
    ) = tx
        .query_row(
            "SELECT state,exit_code,managed_area_identity,command_digest
             FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2
               AND node_id=?3 AND node_epoch=?4 AND fence=?5",
            params![
                candidate.identity.taskrun_id.as_bytes(),
                candidate.identity.attempt_id.as_bytes(),
                node.as_bytes(),
                candidate.identity.node_epoch as i64,
                candidate.identity.fence.0 as i64
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let (terminal_payload, reconcile_payload): (Vec<u8>, Vec<u8>) = tx
        .query_row(
            "SELECT terminal.payload,reconcile.payload FROM events terminal
             JOIN events reconcile ON reconcile.aggregate_type=terminal.aggregate_type
               AND reconcile.aggregate_id=terminal.aggregate_id
               AND reconcile.sequence=terminal.sequence-1
             WHERE terminal.event_id=?1 AND terminal.aggregate_type=1
               AND terminal.aggregate_id=?2 AND terminal.sequence=?3",
            params![terminal, candidate.identity.taskrun_id.as_bytes(), version],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if attempt != candidate.identity.attempt_id.as_bytes()
        || historic_epoch != candidate.identity.node_epoch as i64
        || historic_node != node.as_bytes()
        || proof_node != node.as_bytes()
        || proof_epoch <= historic_epoch
        || proof_epoch > current_epoch as i64
        || area_identity != candidate.area_identity
        || stop_kind != "outcome_unknown"
        || digest.as_slice() != local_digest
        || local_area != candidate.area_identity
        || local_state != "outcome_unknown"
        || exit_code.is_some()
        || version <= 0
        || stream.state != TaskRunState::Unrecoverable
        || stream.version != version as u64
        || last_event != terminal
        || !released
        || !valid_event_chain(tx, candidate, &terminal, version, proof_epoch)?
        || TaskRunEventCodec.decode(&terminal_payload).ok()
            != Some(runne_domain::task_run::TaskRunEvent::Unrecoverable)
        || TaskRunEventCodec.decode(&reconcile_payload).ok()
            != Some(runne_domain::task_run::TaskRunEvent::ReconciliationStarted)
    {
        return Err(EventStoreError::CorruptData);
    }
    empty
        .revalidate()
        .map_err(|_| EventStoreError::CorruptData)?;
    Ok(true)
}

fn valid_event_chain(
    tx: &rusqlite::Transaction<'_>,
    candidate: &LocalCommandRecoveryCandidate,
    terminal_id: &[u8],
    terminal_version: i64,
    proof_epoch: i64,
) -> Result<bool, EventStoreError> {
    type EventChain = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );
    let chain: EventChain = tx
        .query_row(
            "SELECT prior.event_id,reconcile.event_id,reconcile.causation_id,
                    reconcile.command_id,reconcile.idempotency_key,reconcile.actor,
                    terminal.causation_id,terminal.command_id,terminal.idempotency_key,
                    terminal.actor
             FROM events terminal
             JOIN events reconcile ON reconcile.aggregate_type=terminal.aggregate_type
               AND reconcile.aggregate_id=terminal.aggregate_id
               AND reconcile.sequence=terminal.sequence-1
             JOIN events prior ON prior.aggregate_type=reconcile.aggregate_type
               AND prior.aggregate_id=reconcile.aggregate_id
               AND prior.sequence=reconcile.sequence-1
             WHERE terminal.event_id=?1 AND terminal.aggregate_type=1
               AND terminal.aggregate_id=?2 AND terminal.sequence=?3",
            params![
                terminal_id,
                candidate.identity.taskrun_id.as_bytes(),
                terminal_version
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    let (
        prior,
        reconcile,
        reconcile_causation,
        command,
        key,
        actor,
        terminal_causation,
        terminal_command,
        terminal_key,
        terminal_actor,
    ) = chain;
    let expected_key = format!(
        "local-command-recovery-unknown-v1:{}:{}:{proof_epoch}",
        candidate.identity.taskrun_id, candidate.identity.fence.0
    );
    Ok(reconcile_causation == prior
        && terminal_causation == reconcile
        && command.len() == 16
        && command != [0; 16]
        && terminal_command == command
        && key == expected_key.as_bytes()
        && terminal_key == key
        && actor == b"system:local_command_recovery"
        && terminal_actor == actor)
}
