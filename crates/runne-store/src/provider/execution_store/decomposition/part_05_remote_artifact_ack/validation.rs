type RemoteArtifactAckSourceRow = (i64, i64, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

fn validate_remote_artifact_ack_inner(
    tx: &Connection,
    outbox_id: [u8; 16],
    attempt_id: [u8; 16],
    settlement_digest: [u8; 32],
    receipt_digest: [u8; 32],
    expected_source_state: i64,
    validate_global_closures: bool,
) -> Result<Option<RemoteArtifactAckKind>, ProviderExecutionError> {
    use crate::codec::StoreCodec;
    use crate::store::taskrun_submit_origin::RemoteTerminalTaskRunApplicability;
    use runne_application::ports::RuntimeAuthorityId;
    use sha2::{Digest, Sha256};

    let source: RemoteArtifactAckSourceRow = tx
        .query_row(
            "SELECT source_kind,settlement_state,terminal_status,publication_disposition,
                artifact_digest,runtime_authority_id,COALESCE(application_receipt_digest,X''),
                published_output_digest
         FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1
           AND settlement_digest=?2",
            params![attempt_id.as_slice(), settlement_digest.as_slice()],
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
        .map_err(|_| ProviderExecutionError::OutboxConflict)?;
    if source.0 != 2 || source.1 != expected_source_state || source.2 != 1 || source.3 != 0 {
        return Ok(None);
    }
    if expected_source_state == 4 && source.6.as_slice() != receipt_digest.as_slice() {
        return Ok(None);
    }
    let outbox: (Vec<u8>, i64, Vec<u8>, Vec<u8>) = tx
        .query_row(
            "SELECT dispatch_attempt_id,terminal_sequence,plaintext_digest,settlement_digest
         FROM provider_terminal_outbox WHERE outbox_id=?1",
            [outbox_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| ProviderExecutionError::OutboxConflict)?;
    if outbox.0.as_slice() != attempt_id.as_slice()
        || outbox.1 != 0
        || outbox.2.as_slice() != source.4.as_slice()
        || outbox.3.as_slice() != settlement_digest.as_slice()
    {
        return Ok(None);
    }
    let authority = source.5.iter().map(|byte| format!("{byte:02x}")).collect();
    let verified = crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
        tx,
        &attempt_id,
        &RuntimeAuthorityId(authority),
    )
    .map_err(|_| ProviderExecutionError::OutboxConflict)?;
    if expected_source_state == 2 {
        let first_ack_is_audit_only = match &verified.applicability {
            RemoteTerminalTaskRunApplicability::ActiveRunning { .. } => {
                !verified.publication_allowed || !verified.current_generation_active
            }
            RemoteTerminalTaskRunApplicability::ExactUserSupersession { .. }
            | RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion { .. } => true,
            RemoteTerminalTaskRunApplicability::AcceptedCancellation { .. } => false,
        };
        if !first_ack_is_audit_only {
            return Ok(None);
        }
    }
    let outcome_bytes: Option<Vec<u8>> = tx
        .query_row(
            "SELECT command_outcome FROM command_receipts WHERE command_id=?1",
            [verified.begin_command_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ProviderExecutionError::OutboxConflict)?;
    let Some(outcome_bytes) = outcome_bytes else {
        return Ok(None);
    };
    let receipt = crate::codec::TextGenerationReceiptCodec
        .decode(&outcome_bytes)
        .map_err(|_| ProviderExecutionError::OutboxConflict)?;
    if receipt.conversation_id != verified.conversation_id
        || receipt.taskrun_id != verified.taskrun_id
        || receipt.attempt_id != verified.taskrun_attempt_id
    {
        return Ok(None);
    }
    let mut hash = Sha256::new();
    let published_completion = receipt.phase
        == runne_application::ports::TextGenerationPhase::Completed
        || (receipt.phase == runne_application::ports::TextGenerationPhase::Rejected
            && source.7.is_some()
            && matches!(
                &verified.applicability,
                RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
                    terminal_payload,
                    ..
                } if matches!(terminal_payload.as_ref(), runne_domain::task_run::TaskRunEvent::TaskRunCompleted {
                    result: runne_domain::command::TerminalResult::Success,
                })
            ));
    if published_completion {
        let RemoteTerminalTaskRunApplicability::AlreadyAppliedCompletion {
            terminal_event_id,
            terminal_version,
            terminal_payload,
            ..
        } = &verified.applicability
        else {
            return Ok(None);
        };
        if terminal_payload.as_ref()
            != &(runne_domain::task_run::TaskRunEvent::TaskRunCompleted {
                result: runne_domain::command::TerminalResult::Success,
            })
            || receipt.taskrun_version != *terminal_version
            || *terminal_event_id == [0; 16]
        {
            return Ok(None);
        }
        let Some(expected_output) = source.7.as_deref() else {
            return Ok(None);
        };
        let assistant: Option<(Option<Vec<u8>>, Vec<u8>)> = tx
            .query_row(
                "SELECT command_id,payload FROM events
             WHERE aggregate_type=2 AND aggregate_id=?1 AND sequence=?2",
                params![
                    verified.conversation_id.as_bytes(),
                    receipt.conversation_version
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProviderExecutionError::OutboxConflict)?;
        let Some((Some(command_bytes), payload)) = assistant else {
            return Ok(None);
        };
        let event =
            crate::codec::StoreCodec::decode(&crate::codec::ConversationEventCodec, &payload)
                .map_err(|_| ProviderExecutionError::OutboxConflict)?;
        let runne_domain::conversation::ConversationEvent::AssistantMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text,
            ..
        } = event
        else {
            return Ok(None);
        };
        let command_id = runne_domain::id::CommandId::from_bytes(
            command_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ProviderExecutionError::OutboxConflict)?,
        );
        let actual_output: [u8; 32] = Sha256::digest(text.as_str().as_bytes()).into();
        if message_id != receipt.assistant_message_id
            || taskrun_id != verified.taskrun_id
            || attempt_id != verified.taskrun_attempt_id
            || expected_output != actual_output.as_slice()
            || command_id != verified.begin_command_id
        {
            return Ok(None);
        }
        hash.update(b"GOCODE_PROVIDER_CONVERSATION_RECEIPT_V1\0");
        hash.update(outbox_id);
        hash.update(settlement_digest);
        hash.update(receipt.conversation_id.as_bytes());
        hash.update(receipt.taskrun_id.as_bytes());
        hash.update(receipt.attempt_id.as_bytes());
        hash.update(receipt.user_message_id.as_bytes());
        hash.update(receipt.assistant_message_id.as_bytes());
        hash.update(receipt.conversation_version.to_be_bytes());
        hash.update(receipt.taskrun_version.to_be_bytes());
        return Ok((hash.finalize().as_slice() == receipt_digest)
            .then_some(RemoteArtifactAckKind::PublishedOutput));
    } else if receipt.phase == runne_application::ports::TextGenerationPhase::Rejected
        && matches!(expected_source_state, 2 | 4)
        && remote_artifact_cancel_closure_matches(
            tx,
            attempt_id,
            &source.4,
            source.2,
            &verified,
            &receipt,
            validate_global_closures,
        )?
    {
        hash.update(b"GOCODE_PROVIDER_REMOTE_ARTIFACT_AUDIT_ACK_V1\0");
        hash.update(outbox_id);
        hash.update(settlement_digest);
        hash.update(verified.taskrun_id.as_bytes());
        hash.update(verified.taskrun_attempt_id.as_bytes());
        hash.update(source.4);
    } else if expected_source_state == 4
        && source.7.is_none()
        && receipt.phase == runne_application::ports::TextGenerationPhase::Started
    {
        // An already-acknowledged audit-only artifact is immutable. A replay
        // checks its original receipt digest and the current verified source
        // history, but must not require the original Running phase to remain
        // current after an accepted cancellation or its terminal closure.
        hash.update(b"GOCODE_PROVIDER_REMOTE_ARTIFACT_AUDIT_ACK_V1\0");
        hash.update(outbox_id);
        hash.update(settlement_digest);
        hash.update(verified.taskrun_id.as_bytes());
        hash.update(verified.taskrun_attempt_id.as_bytes());
        hash.update(source.4);
    } else if receipt.phase == runne_application::ports::TextGenerationPhase::Started {
        hash.update(b"GOCODE_PROVIDER_REMOTE_ARTIFACT_AUDIT_ACK_V1\0");
        hash.update(outbox_id);
        hash.update(settlement_digest);
        hash.update(verified.taskrun_id.as_bytes());
        hash.update(verified.taskrun_attempt_id.as_bytes());
        hash.update(source.4);
    } else {
        return Ok(None);
    }
    Ok((hash.finalize().as_slice() == receipt_digest).then_some(RemoteArtifactAckKind::AuditOnly))
}

include!("cancel_closure.rs");
