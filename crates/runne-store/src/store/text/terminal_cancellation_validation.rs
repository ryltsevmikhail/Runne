use super::super::parse_helpers::storage_failure;
use super::super::*;
use runne_application::commands::BeginConversationTextInput;
use runne_application::ports::{
    ProviderCancellationProof, RejectTextGenerationAfterCancellationCommit,
};

mod no_admission;
mod pre_effect;

pub(super) fn verify_cancellation_evidence(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationAfterCancellationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    if let ProviderCancellationProof::D2ToolLoop(evidence) = payload.proof {
        return d2_tool_loop::verify(tx, payload, evidence, authority);
    }
    let exact = match payload.proof {
        ProviderCancellationProof::D2ToolLoop(evidence) => {
            return d2_tool_loop::verify(tx, payload, evidence, authority);
        }
        ProviderCancellationProof::Terminal(evidence) => {
            let code = match evidence.disposition {
                runne_provider::ProviderTerminalDisposition::Completed => 1,
                runne_provider::ProviderTerminalDisposition::RemoteFailed => 2,
                runne_provider::ProviderTerminalDisposition::RemoteIncomplete => 3,
                runne_provider::ProviderTerminalDisposition::CancelledUncertain => {
                    return Err(storage_failure(StorageFailureKind::IntegrityViolation));
                }
            };
            tx.query_row(
         "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions a
         JOIN taskrun_provider_bindings b ON b.taskrun_id=a.taskrun_id AND b.attempt_id=a.execution_attempt_id
              AND b.call_id=a.call_id
              AND b.provider_idempotency_key=a.provider_idempotency_key
              AND b.prepared_digest=a.prepared_digest AND b.render_digest=a.render_digest AND b.profile_digest=a.profile_digest
         JOIN provider_prepared_requests p ON p.call_id=b.call_id
              AND p.prepared_digest=b.prepared_digest AND p.render_digest=b.render_digest AND p.profile_digest=b.profile_digest
         JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id AND d.call_id=a.call_id
              AND d.provider_idempotency_key=a.provider_idempotency_key AND d.fencing_token=a.fencing_token
              AND d.profile_digest=a.profile_digest AND d.prepared_digest=a.prepared_digest AND d.render_digest=a.render_digest
         JOIN provider_accounting_settlements s ON s.dispatch_attempt_id=d.attempt_id AND s.settlement_digest=d.settlement_digest
         JOIN provider_terminal_dispositions m ON m.dispatch_attempt_id=d.attempt_id
         JOIN taskrun_assignment_occupations o ON o.taskrun_id=b.taskrun_id AND o.fence=b.fence
              AND o.attempt_id=b.attempt_id AND o.node_id=b.node_id AND o.node_epoch=b.node_epoch
         JOIN taskrun_claim_receipts c ON c.taskrun_id=b.taskrun_id AND c.fence=b.fence
              AND c.attempt_id=b.attempt_id AND c.node_id=b.node_id AND c.node_epoch=b.node_epoch
              AND c.new_version=b.claim_version
         WHERE d.attempt_id=?1 AND d.settlement_digest=?2 AND s.settlement_digest=?2 AND m.disposition=?3
           AND a.taskrun_id=?4 AND a.conversation_id=?5 AND a.execution_attempt_id=?6
           AND a.principal_id=?7
           AND d.state=CASE WHEN ?3=1 THEN 4 ELSE 5 END
           AND o.state='active' AND o.dispatch_intent='present' AND o.release_event_id IS NULL
           AND ( (?3=1 AND EXISTS(SELECT 1 FROM provider_terminal_outbox x WHERE x.dispatch_attempt_id=d.attempt_id AND x.settlement_digest=?2))
              OR (?3 IN (2,3) AND NOT EXISTS(SELECT 1 FROM provider_terminal_outbox x WHERE x.dispatch_attempt_id=d.attempt_id)) )
           AND EXISTS(SELECT 1 FROM provider_runtime_authority_state r
                      WHERE r.id=1 AND r.active=1 AND r.runtime_authority_id=?8
                        AND r.lease_generation>0 AND r.lease_fencing_token>0)
           AND NOT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts r WHERE r.taskrun_id=a.taskrun_id))",
        params![evidence.dispatch_attempt_id.as_slice(), evidence.settlement_digest.as_slice(), code,
            payload.receipt.taskrun_id.as_bytes(), payload.receipt.conversation_id.as_bytes(), payload.receipt.attempt_id.as_bytes(),
            payload.idempotency_scope.principal_id.0,
            uuid::Uuid::parse_str(&authority.0).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?.as_bytes()],
        |row| row.get(0),
            ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
        }
        ProviderCancellationProof::UnknownTerminal(evidence) => {
            super::super::terminal_cancellation_receipt::validate_unknown_terminal_cancellation(
                tx,
                &payload.receipt,
                evidence,
            )?
        }
        ProviderCancellationProof::PreEffect(evidence) => {
            pre_effect::verify(tx, payload, evidence.dispatch_attempt_id)?
        }
        ProviderCancellationProof::NoAdmission(evidence) => {
            if evidence.cancellation_taskrun_version
                != payload.expected_started_taskrun_version.saturating_add(1)
            {
                false
            } else {
                no_admission::verify_absence(tx, payload, authority)?
            }
        }
    };
    if !exact {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    if !matches!(payload.proof, ProviderCancellationProof::NoAdmission(_)) {
        let submit_payload: Vec<u8> = tx
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
            [payload.receipt.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if !matches!(
            TaskRunEventCodec
                .decode(&submit_payload)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
            TaskRunEvent::TaskRunSubmitted { .. }
        ) {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
    }
    let conversation = super::super::conversation::load_conversation_from_connection(
        tx,
        payload.receipt.conversation_id,
    )
    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let text = match conversation
        .events
        .get(
            usize::try_from(
                payload
                    .expected_conversation_version
                    .checked_sub(1)
                    .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?,
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
        )
        .map(|event| event.payload())
    {
        Some(ConversationEvent::UserMessageAppended {
            taskrun_id,
            attempt_id,
            text,
            ..
        }) if *taskrun_id == payload.receipt.taskrun_id
            && *attempt_id == payload.receipt.attempt_id =>
        {
            text.clone()
        }
        _ => return Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    };
    let started_input = BeginConversationTextInput {
        conversation_id: payload.receipt.conversation_id,
        expected_version: payload
            .expected_conversation_version
            .checked_sub(1)
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?,
        text,
    };
    let mut started = payload.receipt.clone();
    started.phase = TextGenerationPhase::Started;
    started.conversation_version = payload.expected_conversation_version;
    started.taskrun_version = payload.expected_started_taskrun_version;
    let scope = &payload.idempotency_scope;
    match super::super::taskrun_started_generation::classify_started_generation_taskrun(
        tx, &started, &started_input, payload.command_id, &payload.idempotency_key,
        scope, authority,
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))? {
        super::super::taskrun_started_generation::StartedGenerationTaskRunState::PendingCancellation => Ok(()),
        super::super::taskrun_started_generation::StartedGenerationTaskRunState::Running => Err(storage_failure(StorageFailureKind::IntegrityViolation)),
    }
}

pub(super) fn retire_cancellation_occupation(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationAfterCancellationCommit,
) -> Result<(), CommitError> {
    if matches!(payload.proof, ProviderCancellationProof::NoAdmission(_)) {
        return no_admission::retire_claim(tx, payload);
    }
    let (node, epoch, fence): (Vec<u8>, i64, i64) = tx.query_row(
        "SELECT node_id,node_epoch,fence FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND attempt_id=?2 AND new_version=?3",
        params![payload.receipt.taskrun_id.as_bytes(), payload.receipt.attempt_id.as_bytes(), payload.expected_started_taskrun_version as i64],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    tx.execute("INSERT INTO taskrun_terminal_settlement_receipts(taskrun_id,fence,attempt_id,node_id,node_epoch,terminal_event_id,terminal_version) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![payload.receipt.taskrun_id.as_bytes(), fence, payload.receipt.attempt_id.as_bytes(), node, epoch,
            payload.taskrun_events[0].event_id().as_bytes(), payload.receipt.taskrun_version as i64])
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let intent_guard = match payload.proof {
        ProviderCancellationProof::D2ToolLoop(_) => "dispatch_intent IN ('absent','present')",
        ProviderCancellationProof::Terminal(_) | ProviderCancellationProof::UnknownTerminal(_) => {
            "dispatch_intent='present'"
        }
        ProviderCancellationProof::PreEffect(_) => "dispatch_intent IN ('absent','present')",
        ProviderCancellationProof::NoAdmission(_) => unreachable!("handled above"),
    };
    let sql = format!(
        "UPDATE taskrun_assignment_occupations SET state='released',release_event_id=?1 WHERE taskrun_id=?2 AND fence=?3 AND attempt_id=?4 AND node_id=?5 AND node_epoch=?6 AND state='active' AND {intent_guard} AND release_event_id IS NULL"
    );
    if tx
        .execute(
            &sql,
            params![
                payload.taskrun_events[0].event_id().as_bytes(),
                payload.receipt.taskrun_id.as_bytes(),
                fence,
                payload.receipt.attempt_id.as_bytes(),
                node,
                epoch
            ],
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?
        != 1
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}

#[path = "terminal_cancellation_validation/d2_tool_loop.rs"]
mod d2_tool_loop;

pub(super) fn verify_d2_cancelled_provider_rounds(
    connection: &rusqlite::Connection,
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
    evidence: runne_application::ports::D2ToolLoopCancellationEvidence,
    original_claim_version: u64,
    cancel_version: u64,
) -> Result<(), CommitError> {
    d2_tool_loop::rounds::verify_cancelled_provider_rounds(
        connection,
        taskrun_id,
        attempt_id,
        evidence,
        original_claim_version,
        cancel_version,
    )
}
