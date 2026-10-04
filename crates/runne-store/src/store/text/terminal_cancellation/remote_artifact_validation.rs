use super::*;

type RemoteArtifactCancellationSourceRow =
    (Vec<u8>, Vec<u8>, i64, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>);

pub(super) fn validate_payload(
    payload: &RejectTextGenerationAfterRemoteArtifactCancellationCommit,
) -> Result<(), CommitError> {
    if payload.conversation_events.len() != payload.taskrun_events.len()
        || payload.conversation_events.len() > 1
        || payload.receipt.phase != TextGenerationPhase::Rejected
        || payload.receipt.conversation_version
            != payload
                .expected_conversation_version
                .checked_add(1)
                .ok_or_else(invalid)?
        || payload.receipt.taskrun_version
            != payload
                .evidence
                .cancellation_taskrun_version()
                .checked_add(1)
                .ok_or_else(invalid)?
        || (!payload.conversation_events.is_empty()
            && (!matches!(
                payload.conversation_events[0].payload(),
                runne_domain::conversation::ConversationEvent::GenerationFailed {
                    taskrun_id,
                    attempt_id,
                    reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
                } if *taskrun_id == payload.receipt.taskrun_id
                    && *attempt_id == payload.receipt.attempt_id
            ) || payload.taskrun_events[0].payload()
                != &runne_domain::task_run::TaskRunEvent::CancellationCompleted
                || !valid_event_context(
                    &payload.conversation_events[0],
                    payload.command_id,
                    &payload.idempotency_key,
                    AggregateId::Conversation(payload.receipt.conversation_id),
                    Sensitivity::Public,
                )
                || !valid_event_context(
                    &payload.taskrun_events[0],
                    payload.command_id,
                    &payload.idempotency_key,
                    AggregateId::TaskRun(payload.receipt.taskrun_id),
                    Sensitivity::Public,
                )))
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn invalid() -> CommitError {
    storage_failure(StorageFailureKind::IntegrityViolation)
}

pub(super) fn validate_started(
    stored: &TextGenerationReceipt,
    payload: &RejectTextGenerationAfterRemoteArtifactCancellationCommit,
) -> Result<(), CommitError> {
    if stored.phase != TextGenerationPhase::Started
        || payload.conversation_events.len() != 1
        || payload.taskrun_events.len() != 1
        || stored.conversation_id != payload.receipt.conversation_id
        || stored.workspace_id != payload.receipt.workspace_id
        || stored.taskrun_id != payload.receipt.taskrun_id
        || stored.attempt_id != payload.receipt.attempt_id
        || stored.user_message_id != payload.receipt.user_message_id
        || stored.assistant_message_id != payload.receipt.assistant_message_id
        || stored.conversation_version != payload.expected_conversation_version
        || stored.taskrun_version != payload.expected_started_taskrun_version
        || payload.evidence.cancellation_taskrun_version()
            <= payload.expected_started_taskrun_version
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn validate_remote_cancel_source(
    tx: &rusqlite::Transaction<'_>,
    stored: &TextGenerationReceipt,
    payload: &RejectTextGenerationAfterRemoteArtifactCancellationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    let source: RemoteArtifactCancellationSourceRow = tx
        .query_row(
            "SELECT s.dispatch_attempt_id,s.artifact_digest,s.source_kind,
                s.terminal_status,s.settlement_state,s.taskrun_id,s.taskrun_attempt_id,
                s.conversation_id
             FROM provider_remote_terminal_settlements s
             JOIN provider_remote_terminal_artifacts a USING(dispatch_attempt_id)
             JOIN provider_remote_request_intents q USING(dispatch_attempt_id)
             WHERE s.dispatch_attempt_id=?1 AND s.taskrun_id=?2
               AND s.taskrun_attempt_id=?3 AND s.conversation_id=?4
               AND a.taskrun_id=s.taskrun_id AND a.taskrun_attempt_id=s.taskrun_attempt_id
               AND a.disposition=s.terminal_status AND a.request_digest=s.request_digest
               AND a.plaintext_digest=s.artifact_digest
               AND a.response_id_digest=s.response_id_digest
               AND a.profile_digest=s.profile_digest
               AND a.pricing_revision_digest=s.pricing_revision_digest
               AND a.runtime_authority_id=s.runtime_authority_id
               AND a.database_generation=s.database_generation
               AND a.runtime_generation=s.runtime_generation AND a.fencing_token=s.fencing_token
               AND q.taskrun_id=s.taskrun_id AND q.taskrun_attempt_id=s.taskrun_attempt_id
               AND q.request_digest=s.request_digest",
            rusqlite::params![
                payload.evidence.dispatch_attempt_id().as_slice(),
                stored.taskrun_id.as_bytes(),
                stored.attempt_id.as_bytes(),
                stored.conversation_id.as_bytes(),
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
                ))
            },
        )
        .map_err(|_| invalid())?;
    let disposition_code = payload.evidence.terminal_disposition().code();
    if source.0.as_slice() != payload.evidence.dispatch_attempt_id().as_slice()
        || source.1.as_slice() != payload.evidence.artifact_digest().as_slice()
        || source.2 != 2
        || source.3 != disposition_code
        || !(1..=5).contains(&source.4)
        || source.5.as_slice() != stored.taskrun_id.as_bytes()
        || source.6.as_slice() != stored.attempt_id.as_bytes()
        || source.7.as_slice() != stored.conversation_id.as_bytes()
    {
        return Err(invalid());
    }
    let dispatch = *payload.evidence.dispatch_attempt_id();
    let verified = crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
        tx, &dispatch, authority,
    )
    .map_err(|_| invalid())?;
    let cancellation = RemoteTerminalTaskRunApplicability::AcceptedCancellation {
        taskrun_version: payload.evidence.cancellation_taskrun_version(),
        cancellation_event_id: *payload.evidence.cancellation_event_id(),
        cancellation_command_id: runne_domain::id::CommandId::from_bytes(
            *payload.evidence.cancellation_command_id(),
        ),
    };
    if verified.applicability != cancellation
        || verified.current_taskrun_state != runne_domain::task_run::TaskRunState::Cancelling
        || !verified.current_generation_active
        || verified.taskrun_id != stored.taskrun_id
        || verified.taskrun_attempt_id != stored.attempt_id
        || verified.conversation_id != stored.conversation_id
        || (verified.expected_taskrun_version != stored.taskrun_version
            && verified.expected_taskrun_version != payload.evidence.cancellation_taskrun_version())
    {
        return Err(invalid());
    }
    Ok(())
}
