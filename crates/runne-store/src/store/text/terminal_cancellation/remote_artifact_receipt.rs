use super::*;
use sha2::{Digest, Sha256};

pub(super) fn retire_remote_artifact_cancel_occupation(
    tx: &rusqlite::Transaction<'_>,
    stored: &TextGenerationReceipt,
    payload: &RejectTextGenerationAfterRemoteArtifactCancellationCommit,
) -> Result<(), CommitError> {
    use runne_domain::task_run::TaskRunEvent;

    let integrity = || super::invalid();
    let event = payload.taskrun_events.first().ok_or_else(integrity)?;
    if event.payload() != &TaskRunEvent::CancellationCompleted {
        return Err(integrity());
    }
    let claim_version =
        i64::try_from(payload.expected_started_taskrun_version).map_err(|_| integrity())?;
    let claim: Option<(Vec<u8>, i64, i64)> = tx
        .query_row(
            "SELECT node_id,node_epoch,fence FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND new_version=?3",
            rusqlite::params![
                stored.taskrun_id.as_bytes(),
                stored.attempt_id.as_bytes(),
                claim_version,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| integrity())?;
    let Some((node, epoch, fence)) = claim else {
        return Err(integrity());
    };
    if node.len() != 16 || epoch <= 0 || fence <= 0 {
        return Err(integrity());
    }
    let intent: Option<String> = tx
        .query_row(
            "SELECT dispatch_intent FROM taskrun_assignment_occupations
             WHERE taskrun_id=?1 AND attempt_id=?2 AND node_id=?3 AND node_epoch=?4
               AND fence=?5 AND state='active' AND release_event_id IS NULL",
            rusqlite::params![
                stored.taskrun_id.as_bytes(),
                stored.attempt_id.as_bytes(),
                node,
                epoch,
                fence
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| integrity())?;
    if intent.as_deref() != Some("present") {
        return Err(integrity());
    }
    tx.execute(
        "INSERT INTO taskrun_terminal_settlement_receipts(
            taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version)
         VALUES(?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![
            stored.taskrun_id.as_bytes(),
            fence,
            stored.attempt_id.as_bytes(),
            node,
            epoch,
            event.event_id().as_bytes(),
            i64::try_from(payload.receipt.taskrun_version).map_err(|_| integrity())?,
        ],
    )
    .map_err(|_| integrity())?;
    let changed = tx
        .execute(
            "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1
             WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5
               AND node_epoch=?6 AND state='active' AND dispatch_intent='present'
               AND release_event_id IS NULL",
            rusqlite::params![
                event.event_id().as_bytes(),
                stored.taskrun_id.as_bytes(),
                fence,
                stored.attempt_id.as_bytes(),
                node,
                epoch,
            ],
        )
        .map_err(|_| integrity())?;
    if changed != 1 {
        return Err(integrity());
    }
    Ok(())
}

pub(super) fn duplicate_if_exact(
    tx: &rusqlite::Transaction<'_>,
    stored: &TextGenerationReceipt,
    payload: &RejectTextGenerationAfterRemoteArtifactCancellationCommit,
) -> Result<TextGenerationCommitResult, CommitError> {
    if stored != &payload.receipt {
        return Err(invalid());
    }
    let closure: Option<(Vec<u8>, i64, Vec<u8>, i64)> = tx
        .query_row(
            "SELECT taskrun_terminal_event_id,taskrun_terminal_version,
                conversation_terminal_event_id,conversation_terminal_version
             FROM provider_remote_artifact_cancel_closures
             WHERE dispatch_attempt_id=?1 AND taskrun_id=?2 AND taskrun_attempt_id=?3
               AND conversation_id=?4 AND artifact_digest=?5 AND terminal_status=?6
               AND cancellation_command_id=?7 AND cancellation_event_id=?8
               AND cancellation_taskrun_version=?9",
            rusqlite::params![
                payload.evidence.dispatch_attempt_id().as_slice(),
                stored.taskrun_id.as_bytes(),
                stored.attempt_id.as_bytes(),
                stored.conversation_id.as_bytes(),
                payload.evidence.artifact_digest().as_slice(),
                payload.evidence.terminal_disposition().code(),
                payload.evidence.cancellation_command_id().as_slice(),
                payload.evidence.cancellation_event_id().as_slice(),
                i64::try_from(payload.evidence.cancellation_taskrun_version())
                    .map_err(|_| invalid())?,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| invalid())?;
    let Some((taskrun_event, taskrun_version, conversation_event, conversation_version)) = closure
    else {
        return Err(invalid());
    };
    if !crate::schema::verify_v60_remote_artifact_cancel_closures(tx).map_err(|_| invalid())? {
        return Err(invalid());
    }
    if taskrun_version != i64::try_from(stored.taskrun_version).map_err(|_| invalid())?
        || conversation_version
            != i64::try_from(stored.conversation_version).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let taskrun_payload: Vec<u8> = tx
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1
             AND event_id=?2 AND sequence=?3",
            rusqlite::params![
                stored.taskrun_id.as_bytes(),
                &taskrun_event,
                taskrun_version
            ],
            |row| row.get(0),
        )
        .map_err(|_| invalid())?;
    let conversation_payload: Vec<u8> = tx
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1
             AND event_id=?2 AND sequence=?3",
            rusqlite::params![
                stored.conversation_id.as_bytes(),
                &conversation_event,
                conversation_version
            ],
            |row| row.get(0),
        )
        .map_err(|_| invalid())?;
    if crate::codec::TaskRunEventCodec
        .decode(&taskrun_payload)
        .map_err(|_| invalid())?
        != runne_domain::task_run::TaskRunEvent::CancellationCompleted
        || !matches!(
            crate::codec::ConversationEventCodec
                .decode(&conversation_payload)
                .map_err(|_| invalid())?,
            runne_domain::conversation::ConversationEvent::GenerationFailed {
                taskrun_id,
                attempt_id,
                reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
            } if taskrun_id == stored.taskrun_id && attempt_id == stored.attempt_id
        )
    {
        return Err(invalid());
    }
    Ok(TextGenerationCommitResult::Duplicate {
        stored_result: stored.clone(),
    })
}

pub(super) fn insert_closure_receipt(
    tx: &rusqlite::Transaction<'_>,
    stored: &TextGenerationReceipt,
    payload: &RejectTextGenerationAfterRemoteArtifactCancellationCommit,
    observed_conversation_head: Option<runne_domain::id::EventId>,
    now: i64,
) -> Result<(), CommitError> {
    let observed = observed_conversation_head.ok_or_else(invalid)?;
    let terminal_conversation = payload.conversation_events[0].event_id();
    let terminal_taskrun = payload.taskrun_events[0].event_id();
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/provider/remote-artifact-cancel-closure/v1\0");
    hasher.update(payload.evidence.dispatch_attempt_id());
    hasher.update(stored.taskrun_id.as_bytes());
    hasher.update(stored.attempt_id.as_bytes());
    hasher.update(stored.conversation_id.as_bytes());
    hasher.update(payload.evidence.artifact_digest());
    hasher.update(payload.evidence.terminal_disposition().code().to_be_bytes());
    hasher.update(payload.evidence.cancellation_command_id());
    hasher.update(payload.evidence.cancellation_event_id());
    hasher.update(
        payload
            .evidence
            .cancellation_taskrun_version()
            .to_be_bytes(),
    );
    hasher.update(terminal_taskrun.as_bytes());
    hasher.update(payload.receipt.taskrun_version.to_be_bytes());
    hasher.update(observed.as_bytes());
    hasher.update(payload.expected_conversation_version.to_be_bytes());
    hasher.update(terminal_conversation.as_bytes());
    hasher.update(payload.receipt.conversation_version.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    tx.execute(
        "INSERT INTO provider_remote_artifact_cancel_closures
         (dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,artifact_digest,
          terminal_status,cancellation_command_id,cancellation_event_id,
          cancellation_taskrun_version,taskrun_terminal_event_id,taskrun_terminal_version,
          observed_conversation_head_event_id,observed_conversation_head_version,
          conversation_terminal_event_id,conversation_terminal_version,closure_digest,created_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        rusqlite::params![
            payload.evidence.dispatch_attempt_id().as_slice(),
            stored.taskrun_id.as_bytes(),
            stored.attempt_id.as_bytes(),
            stored.conversation_id.as_bytes(),
            payload.evidence.artifact_digest().as_slice(),
            payload.evidence.terminal_disposition().code(),
            payload.evidence.cancellation_command_id().as_slice(),
            payload.evidence.cancellation_event_id().as_slice(),
            i64::try_from(payload.evidence.cancellation_taskrun_version()).map_err(|_| invalid())?,
            terminal_taskrun.as_bytes(),
            i64::try_from(payload.receipt.taskrun_version).map_err(|_| invalid())?,
            observed.as_bytes(),
            i64::try_from(payload.expected_conversation_version).map_err(|_| invalid())?,
            terminal_conversation.as_bytes(),
            i64::try_from(payload.receipt.conversation_version).map_err(|_| invalid())?,
            digest.as_slice(),
            now,
        ],
    )
    .map_err(|_| invalid())?;
    Ok(())
}

pub(super) fn persist_rejected_receipt(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationAfterRemoteArtifactCancellationCommit,
    scope: &[u8],
    now: i64,
) -> Result<(), CommitError> {
    let bytes = TextGenerationReceiptCodec
        .encode(&payload.receipt)
        .map_err(|_| invalid())?;
    let changed = tx
        .execute(
            "UPDATE command_receipts SET command_outcome=?1,committed_at=?2
             WHERE command_id=?3 AND idempotency_scope_bytes=?4 AND idempotency_key=?5
               AND fingerprint=?6",
            rusqlite::params![
                bytes,
                now,
                payload.command_id.as_bytes(),
                scope,
                payload.idempotency_key.as_str().as_bytes(),
                payload.command_fingerprint.as_bytes(),
            ],
        )
        .map_err(|_| invalid())?;
    if changed != 1 {
        return Err(invalid());
    }
    Ok(())
}
