use super::*;

type CancellationClaimOccupationRow = (Vec<u8>, i64, i64, String, Option<Vec<u8>>);

mod assignment_retirement;
mod cancel_receipt;
mod effect_diagnostics;

pub(super) fn verify_absence(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationAfterCancellationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<bool, CommitError> {
    use crate::store::test_support_diagnostics as diagnostics;

    let taskrun_id = payload.receipt.taskrun_id.as_bytes();
    let attempt_id = payload.receipt.attempt_id.as_bytes();
    let rows_absent: bool = tx
        .query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM provider_execution_admissions
                    WHERE taskrun_id=?1 AND execution_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM taskrun_provider_bindings
                    WHERE taskrun_id=?1 AND attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents
                    WHERE taskrun_id=?1 AND attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_request_intents
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_response_bindings
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_settlements
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_artifact_cancel_closures
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_operation_proofs
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_applications
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM provider_remote_terminal_audit_receipts
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM taskrun_provider_cancel_fences
                    WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM taskrun_local_command_attempts
                    WHERE taskrun_id=?1 AND (attempt_id IS NULL OR attempt_id=?2))
                AND NOT EXISTS(SELECT 1 FROM taskrun_local_command_stop_receipts
                    WHERE taskrun_id=?1 AND attempt_id=?2)
                AND NOT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts
                    WHERE taskrun_id=?1)",
            rusqlite::params![taskrun_id, attempt_id],
            |row| row.get(0),
        )
        .map_err(|_| {
            diagnostics::record("cancel.no_admission.effect_rows_query");
            storage_failure(StorageFailureKind::CorruptData)
        })?;
    if !rows_absent {
        effect_diagnostics::record_present(tx, taskrun_id, attempt_id);
        diagnostics::record("cancel.no_admission.effect_rows_present");
        return Ok(false);
    }
    if !diagnostics::on_error(
        "cancel.no_admission.assignment_check",
        verify_assignment(tx, payload),
    )? {
        diagnostics::record("cancel.no_admission.assignment_mismatch");
        return Ok(false);
    }
    let verified = super::super::taskrun_claim::stream_validate::verify_stream(
        tx,
        payload.receipt.taskrun_id,
        Some(
            payload
                .expected_started_taskrun_version
                .checked_add(1)
                .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?,
        ),
    )
    .map_err(|_| {
        diagnostics::record("cancel.no_admission.taskrun_stream");
        storage_failure(StorageFailureKind::IntegrityViolation)
    })?;
    if verified.state != runne_domain::task_run::TaskRunState::Cancelling
        || verified.active_attempt != Some(payload.receipt.attempt_id)
        || verified.events.last().map(|event| event.payload())
            != Some(&TaskRunEvent::CancellationRequested)
    {
        diagnostics::record("cancel.no_admission.taskrun_state");
        return Ok(false);
    }
    diagnostics::on_error(
        "cancel.no_admission.cancel_receipt",
        cancel_receipt::verify(tx, payload, authority),
    )?;
    let conversation = diagnostics::on_error(
        "cancel.no_admission.conversation_stream",
        super::super::conversation::load_conversation_from_connection(
            tx,
            payload.receipt.conversation_id,
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData)),
    )?;
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
        _ => {
            diagnostics::record("cancel.no_admission.user_message");
            return Ok(false);
        }
    };
    let mut started = payload.receipt.clone();
    started.phase = TextGenerationPhase::Started;
    started.conversation_version = payload.expected_conversation_version;
    started.taskrun_version = payload.expected_started_taskrun_version;
    let input = BeginConversationTextInput {
        conversation_id: payload.receipt.conversation_id,
        expected_version: payload
            .expected_conversation_version
            .checked_sub(1)
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?,
        text,
    };
    match super::super::taskrun_started_generation::classify_started_generation_taskrun(
        tx,
        &started,
        &input,
        payload.command_id,
        &payload.idempotency_key,
        &payload.idempotency_scope,
        &payload.idempotency_scope.runtime_authority_id,
    )
    .map_err(|_| {
        diagnostics::record("cancel.no_admission.started_generation");
        storage_failure(StorageFailureKind::IntegrityViolation)
    })?
    {
        super::super::taskrun_started_generation::StartedGenerationTaskRunState::PendingCancellation => Ok(true),
        super::super::taskrun_started_generation::StartedGenerationTaskRunState::Running => {
            diagnostics::record("cancel.no_admission.cancellation_not_pending");
            Ok(false)
        }
    }
}

fn verify_assignment(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationAfterCancellationCommit,
) -> Result<bool, CommitError> {
    // Dispatch/effect identifiers are distinct from TaskRun execution-attempt
    // identifiers. Their exact TaskRun owners are the admission, dispatch
    // intent, and remote-request rows checked by this proof.
    let id = payload.receipt.taskrun_id.as_bytes();
    let counts: (i64, i64, i64) = tx
        .query_row(
            "SELECT (SELECT COUNT(*) FROM taskrun_assignments WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM taskrun_claim_receipts WHERE taskrun_id=?1),
                (SELECT COUNT(*) FROM taskrun_assignment_occupations WHERE taskrun_id=?1)",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if counts == (0, 0, 0) {
        return Ok(true);
    }
    if counts != (1, 1, 1) {
        return Ok(false);
    }
    let expected_claim_version = payload.expected_started_taskrun_version;
    let row: Option<CancellationClaimOccupationRow> = tx
        .query_row(
            "SELECT c.node_id,c.node_epoch,c.fence,o.dispatch_intent,o.release_event_id
         FROM taskrun_claim_receipts c
         JOIN taskrun_assignments a ON a.taskrun_id=c.taskrun_id AND a.fence=c.fence
           AND a.attempt_id=c.attempt_id AND a.node_id=c.node_id AND a.node_epoch=c.node_epoch
           AND a.command_id=c.command_id AND a.admitted_event_id=c.admitted_event_id
           AND a.started_event_id=c.started_event_id
         JOIN taskrun_assignment_occupations o ON o.taskrun_id=c.taskrun_id AND o.fence=c.fence
           AND o.attempt_id=c.attempt_id AND o.node_id=c.node_id AND o.node_epoch=c.node_epoch
         WHERE c.taskrun_id=?1 AND c.attempt_id=?2 AND c.new_version=?3
           AND o.state='active' AND o.dispatch_intent='absent' AND o.release_event_id IS NULL",
            params![
                id,
                payload.receipt.attempt_id.as_bytes(),
                i64::try_from(expected_claim_version)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let Some((node, epoch, fence, intent, release)) = row else {
        return Ok(false);
    };
    if intent != "absent" || release.is_some() {
        return Ok(false);
    }
    let identity = TaskRunAssignmentIdentity {
        taskrun_id: payload.receipt.taskrun_id,
        attempt_id: payload.receipt.attempt_id,
        node_id: runne_application::ports::ExecutionNodeId(
            uuid::Uuid::from_bytes(
                node.as_slice()
                    .try_into()
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            )
            .to_string(),
        ),
        node_epoch: u64::try_from(epoch)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        fence: runne_application::ports::TaskRunFence(
            u64::try_from(fence).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
        ),
    };
    super::super::taskrun_claim::verify_assignment_history(tx, &identity)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    Ok(true)
}

pub(super) fn retire_claim(
    tx: &rusqlite::Transaction<'_>,
    payload: &RejectTextGenerationAfterCancellationCommit,
) -> Result<(), CommitError> {
    assignment_retirement::retire_claim(tx, payload)
}
