use super::*;

pub(super) fn apply_terminal_cancellation(
    store: &StoreTransaction,
    service: &dyn ConversationTextCommandService,
    candidate: &runne_store::store::provider_failure_recovery::ProviderFailureRecoveryRecord,
    disposition: ProviderTerminalDisposition,
    cancellation_taskrun_version: u64,
) -> Result<(), ()> {
    let stream = store
        .load_conversation(candidate.conversation_id)
        .map_err(|_| ())?;
    let mut matches = stream.events.iter().filter(|event| {
        matches!(event.payload(),
        ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
            if *taskrun_id == candidate.taskrun_id && *attempt_id == candidate.execution_attempt_id)
    });
    let event = matches.next().ok_or(())?;
    if matches.next().is_some() {
        return Err(());
    }
    let ConversationEvent::UserMessageAppended {
        message_id, text, ..
    } = event.payload()
    else {
        return Err(());
    };
    if text.as_str() != candidate.submitted_prompt
        || event.actor() != candidate.submit_actor.as_ref().ok_or(())?
    {
        return Err(());
    }
    let sequence = event.sequence();
    let command_id = *event.command_id();
    let key = event.idempotency_key().clone();
    let started = store
        .load_text_generation_receipt_by_command(command_id, &key)
        .map_err(|_| ())?;
    if started.phase != TextGenerationPhase::Started
        || started.conversation_id != candidate.conversation_id
        || started.taskrun_id != candidate.taskrun_id
        || started.attempt_id != candidate.execution_attempt_id
        || started.conversation_version != sequence
        || started.taskrun_version != candidate.claim_version
        || started.user_message_id != *message_id
        || Some(started.workspace_id) != candidate.workspace_id
    {
        return Err(());
    }
    let context = ApplicationCommandContext {
        command_id,
        idempotency_key: key,
        principal_id: PrincipalId(candidate.principal_id.clone()),
        actor: candidate.submit_actor.clone().ok_or(())?,
    };
    service
        .finish_text(
            &context,
            FinishConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id: candidate.conversation_id,
                    expected_version: sequence.checked_sub(1).ok_or(())?,
                    text: text.clone(),
                },
                started,
                completion: ConversationTextCompletion::TerminalSettledCancellation {
                    evidence: runne_application::ports::ProviderTerminalCancellationEvidence {
                        dispatch_attempt_id: candidate.dispatch_attempt_id,
                        disposition,
                        settlement_digest: candidate.settlement_digest,
                        cancellation_taskrun_version,
                    },
                },
            },
        )
        .map_err(|_| ())?;
    Ok(())
}
