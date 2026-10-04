use super::*;

mod assignment_receipt;
mod cancel_receipt;

pub(super) fn requires_no_admission_proof(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<bool, CommitError> {
    assignment_receipt::no_provider_rows(connection, receipt)
}

pub(super) fn validate(
    connection: &Connection,
    receipt: &TextGenerationReceipt,
) -> Result<bool, CommitError> {
    let fail = || storage_failure(StorageFailureKind::IntegrityViolation);
    let verified = super::super::taskrun_claim::stream_validate::verify_stream(
        connection,
        receipt.taskrun_id,
        Some(receipt.taskrun_version),
    )
    .map_err(|_| fail())?;
    let events = &verified.events;
    if receipt.taskrun_version < 3
        || u64::try_from(events.len()).map_err(|_| fail())? != receipt.taskrun_version
    {
        return Ok(false);
    }
    let terminal_index = events.len() - 1;
    if events[terminal_index].payload() != &TaskRunEvent::CancellationCompleted
        || events[terminal_index - 1].payload() != &TaskRunEvent::CancellationRequested
    {
        return Ok(false);
    }
    let started_index = terminal_index.checked_sub(2).ok_or_else(fail)?;
    let TaskRunEvent::AttemptStarted { attempt_id } = events[started_index].payload() else {
        return Ok(false);
    };
    if *attempt_id != receipt.attempt_id
        || verified.state != runne_domain::task_run::TaskRunState::Cancelled
        || verified.active_attempt.is_some()
        || super::super::taskrun_claim::active_attempt_at_verified_version(
            connection,
            receipt.taskrun_id,
            u64::try_from(started_index + 1).map_err(|_| fail())?,
        )
        .map_err(|_| fail())?
            != Some(receipt.attempt_id)
    {
        return Err(fail());
    }
    if !assignment_receipt::no_provider_rows(connection, receipt)? {
        return Ok(false);
    }

    let conversation = super::super::conversation::load_conversation_from_connection(
        connection,
        receipt.conversation_id,
    )
    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    let started_conversation_version = receipt
        .conversation_version
        .checked_sub(1)
        .ok_or_else(fail)?;
    let start_index = usize::try_from(
        started_conversation_version
            .checked_sub(1)
            .ok_or_else(fail)?,
    )
    .map_err(|_| fail())?;
    let Some(start_event) = conversation.events.get(start_index) else {
        return Err(fail());
    };
    let ConversationEvent::UserMessageAppended {
        message_id,
        taskrun_id,
        attempt_id,
        text,
        ..
    } = start_event.payload()
    else {
        return Err(fail());
    };
    if *taskrun_id != receipt.taskrun_id || *attempt_id != receipt.attempt_id {
        return Err(fail());
    }
    if *message_id != receipt.user_message_id {
        return Err(fail());
    }
    let terminal_event = conversation
        .events
        .get(
            usize::try_from(
                receipt
                    .conversation_version
                    .checked_sub(1)
                    .ok_or_else(fail)?,
            )
            .map_err(|_| fail())?,
        )
        .ok_or_else(fail)?;
    if !matches!(terminal_event.payload(), ConversationEvent::GenerationFailed {
        taskrun_id, attempt_id,
        reason: runne_domain::conversation::GenerationFailureReason::Cancelled,
    } if *taskrun_id == receipt.taskrun_id && *attempt_id == receipt.attempt_id)
    {
        return Err(fail());
    }
    if receipt.phase != TextGenerationPhase::Rejected
        || receipt.conversation_version
            != started_conversation_version
                .checked_add(1)
                .ok_or_else(fail)?
        || receipt.taskrun_version != u64::try_from(terminal_index + 1).map_err(|_| fail())?
        || conversation.events.iter().any(|event| {
            matches!(event.payload(),
            ConversationEvent::AssistantMessageAppended { taskrun_id, attempt_id, .. }
                if *taskrun_id == receipt.taskrun_id && *attempt_id == receipt.attempt_id)
        })
    {
        return Err(fail());
    }
    let command_id = *start_event.command_id();
    let key = start_event.idempotency_key().clone();
    let (scope_bytes, stored_key, fingerprint): (Vec<u8>, Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint
             FROM command_receipts WHERE command_id=?1",
            [command_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| fail())?;
    let scope = IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| fail())?;
    cancel_receipt::verify(
        connection,
        &events[terminal_index - 1],
        receipt.taskrun_id,
        &scope.runtime_authority_id,
    )?;
    let expected_fingerprint = CommandFingerprint::for_generate_conversation_text(
        &receipt.conversation_id,
        started_conversation_version
            .checked_sub(1)
            .ok_or_else(fail)?,
        text,
    );
    let conversation_id = receipt.conversation_id;
    if stored_key != key.as_str().as_bytes()
        || fingerprint != expected_fingerprint.as_bytes()
        || scope.operation != OperationTag::GenerateConversationText
        || scope.aggregate_scope != (AggregateScope::ExistingConversation { conversation_id })
    {
        return Err(fail());
    }
    let origin = events.first().ok_or_else(fail)?.payload();
    let workspace_id = match origin {
        TaskRunEvent::TaskRunSubmitted { .. } => {
            let verified_origin = super::super::taskrun_submit_origin::verify_submitted_v2_origin(
                connection,
                receipt.taskrun_id,
                &scope.runtime_authority_id,
            )
            .map_err(|_| fail())?
            .ok_or_else(fail)?;
            if verified_origin.conversation_id != conversation_id
                || verified_origin.input.prompt() != text.as_str()
                || verified_origin.principal_id != scope.principal_id
            {
                return Err(fail());
            }
            verified_origin.workspace_id
        }
        TaskRunEvent::TaskRunCreated => {
            let conversation_workspace = conversation
                .events
                .first()
                .and_then(|event| match event.payload() {
                    ConversationEvent::ConversationCreated { workspace_id } => Some(*workspace_id),
                    _ => None,
                })
                .ok_or_else(fail)?;
            if conversation_workspace != receipt.workspace_id {
                return Err(fail());
            }
            crate::project_workspace::lineage::validate_text_taskrun_lineage(
                connection,
                receipt.taskrun_id,
                receipt.workspace_id,
                command_id,
                &scope,
            )
            .map_err(|_| fail())?;
            receipt.workspace_id
        }
        _ => return Err(fail()),
    };
    if workspace_id != receipt.workspace_id {
        return Err(fail());
    }
    assignment_receipt::validate(
        connection,
        receipt,
        events,
        events[started_index].sequence(),
    )?;
    Ok(true)
}
