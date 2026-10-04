use super::*;
use runne_application::provider::ProviderTerminalCommitOutcome;

pub(super) fn recover_unknown_one<K, S, P>(
    execution: &RuntimeProviderExecution<'_, K, S, P>,
    redaction: &dyn ProviderEventRedaction,
    store: &StoreTransaction,
    service: &dyn ConversationTextCommandService,
    candidate: &runne_store::store::provider_failure_recovery::ProviderUnknownFailureRecoveryRecord,
) -> Result<(), ()>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: runne_runtime::provider_execution::ProviderTerminalPricing,
{
    let dispatch = DispatchAttemptId::from_bytes(candidate.dispatch_attempt_id);
    let events = execution
        .recover_events(dispatch)
        .map_err(|_| recovery_failure(RecoveryFailureStage::JournalRecovery))?;
    let (sequence, disposition) = unknown_terminal_shape(&events)
        .map_err(|_| recovery_failure(RecoveryFailureStage::TerminalAssembly))?;
    if sequence != candidate.terminal_sequence || disposition != candidate.disposition {
        return {
            recovery_failure(RecoveryFailureStage::TerminalStatus);
            Err(())
        };
    }
    if redaction
        .terminal_disposition(dispatch)
        .map_err(|_| recovery_failure(RecoveryFailureStage::ScannerRead))?
        != Some(ScannerTerminalDisposition::Completed)
    {
        return {
            recovery_failure(RecoveryFailureStage::ScannerDisposition);
            Err(())
        };
    }
    let context = ProviderEventJournalContext {
        attempt_id: dispatch,
        fencing_token: candidate.fencing_token,
        call_digest_version: candidate.call_digest_version,
        profile_digest: candidate.profile_digest,
        runtime_generation: candidate.runtime_generation,
    };
    let replay = execution
        .finalize_terminal_output(&context)
        .map_err(|_| recovery_failure(RecoveryFailureStage::UnknownReplay))?;
    if replay != ProviderTerminalCommitOutcome::Replayed {
        return {
            recovery_failure(RecoveryFailureStage::UnknownReplay);
            Err(())
        };
    }
    finish_unknown_failure(store, service, candidate)
}

fn unknown_terminal_shape(
    events: &[ProviderStreamEvent],
) -> Result<(u64, ProviderTerminalDisposition), ()> {
    let mut validator = ProviderStreamValidator::default();
    let mut terminal = None;
    for event in events {
        validator.accept(event).map_err(|_| ())?;
        match event.kind() {
            ProviderStreamEventKind::Finished {
                disposition,
                reason,
            }
            | ProviderStreamEventKind::ScannerCompleted {
                disposition,
                reason,
                ..
            } => {
                terminal = Some((event.sequence(), *disposition, reason.clone()));
            }
            ProviderStreamEventKind::ToolCallRequested { .. } => return Err(()),
            _ => {}
        }
    }
    let (sequence, disposition, reason) = terminal.ok_or(())?;
    if events.last().map(ProviderStreamEvent::sequence) != Some(sequence)
        || !matches!(
            (disposition, reason),
            (
                ProviderTerminalDisposition::RemoteFailed,
                ProviderFinishReason::Error
            ) | (
                ProviderTerminalDisposition::RemoteIncomplete,
                ProviderFinishReason::Length
                    | ProviderFinishReason::ContentFilter
                    | ProviderFinishReason::Error
            )
        )
    {
        return Err(());
    }
    Ok((sequence, disposition))
}

fn finish_unknown_failure(
    store: &StoreTransaction,
    service: &dyn ConversationTextCommandService,
    candidate: &runne_store::store::provider_failure_recovery::ProviderUnknownFailureRecoveryRecord,
) -> Result<(), ()> {
    let stream = store
        .load_conversation(candidate.conversation_id)
        .map_err(|_| recovery_failure(RecoveryFailureStage::ConversationLoad))?;
    let mut matches = stream.events.iter().filter(|event| {
        matches!(event.payload(), ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
            if *taskrun_id == candidate.taskrun_id && *attempt_id == candidate.execution_attempt_id)
    });
    let event = matches
        .next()
        .ok_or_else(|| recovery_failure(RecoveryFailureStage::SubmittedMessageProof))?;
    if matches.next().is_some() {
        return {
            recovery_failure(RecoveryFailureStage::SubmittedMessageProof);
            Err(())
        };
    }
    let ConversationEvent::UserMessageAppended {
        message_id, text, ..
    } = event.payload()
    else {
        return {
            recovery_failure(RecoveryFailureStage::SubmittedMessageProof);
            Err(())
        };
    };
    let Some(submit_actor) = candidate.submit_actor.as_ref() else {
        return {
            recovery_failure(RecoveryFailureStage::SubmittedMessageProof);
            Err(())
        };
    };
    if text.as_str() != candidate.submitted_prompt || event.actor() != submit_actor {
        return {
            recovery_failure(RecoveryFailureStage::SubmittedMessageProof);
            Err(())
        };
    }
    let sequence = event.sequence();
    let command_id = *event.command_id();
    let key = event.idempotency_key().clone();
    let started = store
        .load_text_generation_receipt_by_command(command_id, &key)
        .map_err(|_| recovery_failure(RecoveryFailureStage::StartedReceiptLoad))?;
    if started.phase != TextGenerationPhase::Started
        || started.conversation_id != candidate.conversation_id
        || started.taskrun_id != candidate.taskrun_id
        || started.attempt_id != candidate.execution_attempt_id
        || started.conversation_version != sequence
        || started.taskrun_version != candidate.claim_version
        || started.user_message_id != *message_id
        || Some(started.workspace_id) != candidate.workspace_id
    {
        return {
            recovery_failure(RecoveryFailureStage::StartedReceiptBinding);
            Err(())
        };
    }
    let original = BeginConversationTextInput {
        conversation_id: candidate.conversation_id,
        expected_version: sequence.checked_sub(1).ok_or(())?,
        text: text.clone(),
    };
    let context = ApplicationCommandContext {
        command_id,
        idempotency_key: key,
        principal_id: PrincipalId(candidate.principal_id.clone()),
        actor: submit_actor.clone(),
    };
    let completion =
        if let Some(cancellation_taskrun_version) = candidate.cancellation_taskrun_version {
            ConversationTextCompletion::UnknownJournalSettledCancellation {
                evidence: runne_application::ports::ProviderUnknownTerminalCancellationEvidence {
                    dispatch_attempt_id: candidate.dispatch_attempt_id,
                    disposition: candidate.disposition,
                    unknown_commitment: candidate.unknown_commitment,
                    cancellation_taskrun_version,
                },
            }
        } else {
            ConversationTextCompletion::Rejected {
                reason: GenerationFailureReason::ProviderExecutionFailed,
            }
        };
    service
        .finish_text(
            &context,
            FinishConversationTextInput {
                original,
                started,
                completion,
            },
        )
        .map_err(|_| recovery_failure(RecoveryFailureStage::FailureApply))?;
    Ok(())
}
