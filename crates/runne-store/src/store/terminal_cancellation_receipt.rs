use super::parse_helpers::storage_failure;
use super::*;

mod no_admission;
mod unknown_terminal;

pub(crate) fn validate_no_admission_receipt(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> rusqlite::Result<bool> {
    no_admission::validate(connection, receipt).map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(crate) fn requires_no_admission_proof(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> rusqlite::Result<bool> {
    no_admission::requires_no_admission_proof(connection, receipt)
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

pub(crate) fn validate_terminal_cancellation_receipt(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<(), CommitError> {
    if validate_remote_artifact_cancellation_receipt(connection, receipt)? {
        return Ok(());
    }
    if no_admission::validate(connection, receipt)? {
        return Ok(());
    }
    let unknown_terminal_exact = unknown_terminal::validate_receipt(connection, receipt)?;
    let verified = super::taskrun_claim::stream_validate::verify_stream(
        connection,
        receipt.taskrun_id,
        Some(receipt.taskrun_version),
    )
    .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if verified.state != runne_domain::task_run::TaskRunState::Cancelled {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let cancelled: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1 AND sequence=?2",
            params![
                receipt.conversation_id.as_bytes(),
                receipt.conversation_version as i64
            ],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !matches!(ConversationEventCodec.decode(&cancelled)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        ConversationEvent::GenerationFailed { taskrun_id, attempt_id, reason }
            if taskrun_id == receipt.taskrun_id && attempt_id == receipt.attempt_id
                && reason == runne_domain::conversation::GenerationFailureReason::Cancelled)
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let (requested, completed, submitted): (Vec<u8>, Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT (SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=5),
                (SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=6),
                (SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1)",
        [receipt.taskrun_id.as_bytes()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if TaskRunEventCodec
        .decode(&requested)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        != TaskRunEvent::CancellationRequested
        || TaskRunEventCodec
            .decode(&completed)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
            != TaskRunEvent::CancellationCompleted
        || !matches!(
            TaskRunEventCodec
                .decode(&submitted)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            TaskRunEvent::TaskRunSubmitted { .. }
        )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let terminal_exact: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r
         JOIN taskrun_assignment_occupations o ON o.taskrun_id=r.taskrun_id AND o.fence=r.fence
             AND o.attempt_id=r.attempt_id AND o.node_id=r.node_id AND o.node_epoch=r.node_epoch
             AND o.state='released' AND o.release_event_id=r.terminal_event_id
         JOIN events e ON e.aggregate_type=1 AND e.aggregate_id=r.taskrun_id
             AND e.sequence=r.terminal_version AND e.event_id=r.terminal_event_id
         JOIN provider_execution_admissions a ON a.taskrun_id=r.taskrun_id AND a.execution_attempt_id=r.attempt_id
         JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
         JOIN provider_accounting_settlements s ON s.dispatch_attempt_id=d.attempt_id AND s.settlement_digest=d.settlement_digest
         JOIN provider_terminal_dispositions m ON m.dispatch_attempt_id=d.attempt_id
         WHERE r.taskrun_id=?1 AND r.attempt_id=?2 AND r.terminal_version=6
             AND m.disposition IN (1,2,3) AND s.settlement_digest=d.settlement_digest)",
        params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes()], |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let rejected_before_effect_exact: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r
         JOIN taskrun_assignment_occupations o ON o.taskrun_id=r.taskrun_id AND o.fence=r.fence
           AND o.attempt_id=r.attempt_id AND o.node_id=r.node_id AND o.node_epoch=r.node_epoch
           AND o.state='released' AND o.release_event_id=r.terminal_event_id
         JOIN events e ON e.aggregate_type=1 AND e.aggregate_id=r.taskrun_id
           AND e.sequence=r.terminal_version AND e.event_id=r.terminal_event_id
         JOIN provider_execution_admissions a ON a.taskrun_id=r.taskrun_id AND a.execution_attempt_id=r.attempt_id
           AND a.conversation_id=?3
         JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id AND d.state=2
           AND d.pre_effect_rejection BETWEEN 1 AND 7 AND d.call_id=a.call_id
           AND d.provider_idempotency_key=a.provider_idempotency_key AND d.fencing_token=a.fencing_token
           AND d.profile_digest=a.profile_digest AND d.prepared_digest=a.prepared_digest AND d.render_digest=a.render_digest
         JOIN provider_prepared_requests p ON p.call_id=a.call_id AND p.prepared_digest=a.prepared_digest
           AND p.render_digest=a.render_digest AND p.profile_digest=a.profile_digest
         JOIN taskrun_claim_receipts c ON c.taskrun_id=r.taskrun_id AND c.attempt_id=r.attempt_id
           AND c.fence=r.fence AND c.node_id=r.node_id AND c.node_epoch=r.node_epoch AND c.new_version=4
         LEFT JOIN taskrun_provider_bindings b ON b.taskrun_id=r.taskrun_id
         WHERE r.taskrun_id=?1 AND r.attempt_id=?2 AND r.terminal_version=6
           AND o.dispatch_intent IN ('absent','present')
           AND NOT EXISTS(SELECT 1 FROM provider_effect_starts x WHERE x.dispatch_attempt_id=d.attempt_id)
           AND NOT EXISTS(SELECT 1 FROM provider_stream_journal x WHERE x.dispatch_attempt_id=d.attempt_id)
           AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox x WHERE x.dispatch_attempt_id=d.attempt_id)
           AND NOT EXISTS(SELECT 1 FROM provider_accounting_settlements x WHERE x.dispatch_attempt_id=d.attempt_id)
           AND NOT EXISTS(SELECT 1 FROM provider_terminal_dispositions x WHERE x.dispatch_attempt_id=d.attempt_id)
           AND ((o.dispatch_intent='absent' AND b.taskrun_id IS NULL
                 AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=o.taskrun_id AND i.fence=o.fence))
             OR (o.dispatch_intent='present' AND b.taskrun_id=a.taskrun_id AND b.attempt_id=a.execution_attempt_id
                 AND b.fence=o.fence AND b.node_id=o.node_id AND b.node_epoch=o.node_epoch AND b.claim_version=4
                 AND b.call_digest_version=p.call_digest_version AND b.call_id=a.call_id
                 AND b.provider_idempotency_key=a.provider_idempotency_key AND b.prepared_digest=a.prepared_digest
                 AND b.render_digest=a.render_digest AND b.profile_digest=a.profile_digest
                 AND EXISTS(SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=o.taskrun_id
                   AND i.fence=o.fence AND i.attempt_id=o.attempt_id AND i.node_id=o.node_id
                   AND i.node_epoch=o.node_epoch AND i.state='present'))))",
        params![receipt.taskrun_id.as_bytes(), receipt.attempt_id.as_bytes(), receipt.conversation_id.as_bytes()],
        |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if terminal_exact || rejected_before_effect_exact || unknown_terminal_exact {
        Ok(())
    } else {
        Err(storage_failure(StorageFailureKind::IntegrityViolation))
    }
}

pub(crate) fn validate_unknown_terminal_cancellation(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
    evidence: runne_application::ports::ProviderUnknownTerminalCancellationEvidence,
) -> Result<bool, CommitError> {
    unknown_terminal::validate_evidence(connection, receipt, evidence)
}

fn validate_remote_artifact_cancellation_receipt(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<bool, CommitError> {
    let has_table: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table'
             AND name='provider_remote_artifact_cancel_closures')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !has_table {
        return Ok(false);
    }
    let closure: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT taskrun_terminal_event_id,conversation_terminal_event_id
             FROM provider_remote_artifact_cancel_closures
             WHERE taskrun_id=?1 AND taskrun_attempt_id=?2 AND conversation_id=?3
               AND taskrun_terminal_version=?4 AND conversation_terminal_version=?5",
            params![
                receipt.taskrun_id.as_bytes(),
                receipt.attempt_id.as_bytes(),
                receipt.conversation_id.as_bytes(),
                i64::try_from(receipt.taskrun_version)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
                i64::try_from(receipt.conversation_version)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some((taskrun_event_id, conversation_event_id)) = closure else {
        return Ok(false);
    };
    if !crate::schema::verify_v60_remote_artifact_cancel_closures(connection)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?
        || taskrun_event_id.len() != 16
        || conversation_event_id.len() != 16
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let taskrun_payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1
               AND event_id=?2 AND sequence=?3",
            params![
                receipt.taskrun_id.as_bytes(),
                taskrun_event_id,
                i64::try_from(receipt.taskrun_version)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            ],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let conversation_payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=2 AND aggregate_id=?1
               AND event_id=?2 AND sequence=?3",
            params![
                receipt.conversation_id.as_bytes(),
                conversation_event_id,
                i64::try_from(receipt.conversation_version)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            ],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let taskrun_event = TaskRunEventCodec
        .decode(&taskrun_payload)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let conversation_event = ConversationEventCodec
        .decode(&conversation_payload)
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if taskrun_event != TaskRunEvent::CancellationCompleted
        || !matches!(
            conversation_event,
            ConversationEvent::GenerationFailed {
                taskrun_id,
                attempt_id,
                reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
            } if taskrun_id == receipt.taskrun_id && attempt_id == receipt.attempt_id
        )
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(true)
}
