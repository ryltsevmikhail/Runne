use super::*;
use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, PrincipalId, TextGenerationPhase,
};
use runne_domain::conversation::GenerationFailureReason;
use runne_provider::{
    DispatchAttemptId, ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
    ProviderStreamValidator, ProviderTerminalDisposition, ProviderUsage,
    ScannerTerminalDisposition,
};
use runne_runtime::provider_redaction::ProviderEventRedaction;
use sha2::{Digest, Sha256};
mod diagnostics;
use diagnostics::{RecoveryFailureStage, recovery_failure};

mod cancelled;
pub(super) use cancelled::recover_exact_cancelled_taskrun;

mod cancellation;
mod terminal;
mod unknown_terminal;
use cancellation::apply_terminal_cancellation;
use terminal::{assemble_failure, verify_settlement};
use unknown_terminal::recover_unknown_one;

const MAX_RECOVERY_OUTPUT_BYTES: usize = 4_194_288;
const SETTLEMENT_DOMAIN: &[u8] = b"GOCODE_PROVIDER_SETTLEMENT_V2\0";

pub(super) fn recover_settled_failures<K, S, P>(
    execution: &RuntimeProviderExecution<'_, K, S, P>,
    redaction: &dyn ProviderEventRedaction,
    store: &StoreTransaction,
    service: &dyn ConversationTextCommandService,
) -> Result<usize, ()>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: runne_runtime::provider_execution::ProviderTerminalPricing,
{
    let mut applied = 0usize;
    let mut cursor = None;
    loop {
        let page = store
            .provider_failure_recovery_candidates(cursor, 128)
            .map_err(|_| ())?;
        for candidate in page.candidates {
            if recover_one(execution, redaction, store, service, &candidate).is_ok() {
                applied = applied.checked_add(1).ok_or(())?;
            }
        }
        if page.reached_end {
            break;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Err(());
        }
    }
    let mut unknown_cursor = None;
    loop {
        let page = store
            .provider_unknown_failure_recovery_candidates(unknown_cursor, 128)
            .map_err(|_| ())?;
        for candidate in page.candidates {
            if recover_unknown_one(execution, redaction, store, service, &candidate).is_ok() {
                applied = applied.checked_add(1).ok_or(())?;
            }
        }
        if page.reached_end {
            break;
        }
        unknown_cursor = page.next_cursor;
        if unknown_cursor.is_none() {
            return Err(());
        }
    }
    let mut rejection_cursor = None;
    loop {
        let page = store
            .provider_rejection_recovery_candidates(rejection_cursor, 128)
            .map_err(|_| ())?;
        for candidate in page.candidates {
            if candidate.cancellation_taskrun_version.is_some() {
                continue;
            }
            if apply_failure(
                store,
                service,
                &candidate,
                GenerationFailureReason::ProviderExecutionRejected,
            )
            .is_ok()
            {
                applied = applied.checked_add(1).ok_or(())?;
            }
        }
        if page.reached_end {
            break;
        }
        rejection_cursor = page.next_cursor;
        if rejection_cursor.is_none() {
            return Err(());
        }
    }
    Ok(applied)
}

fn recover_one<K, S, P>(
    execution: &RuntimeProviderExecution<'_, K, S, P>,
    redaction: &dyn ProviderEventRedaction,
    store: &StoreTransaction,
    service: &dyn ConversationTextCommandService,
    candidate: &runne_store::store::provider_failure_recovery::ProviderFailureRecoveryRecord,
) -> Result<(), ()>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: runne_runtime::provider_execution::ProviderTerminalPricing,
{
    if candidate.kind == runne_store::store::provider_failure_recovery::ProviderFailureRecoveryKind::RejectedBeforeEffect {
        if candidate.pre_effect_rejection.is_none() {
            return {
                recovery_failure(RecoveryFailureStage::MissingPreEffectProof);
                Err(())
            };
        }
        return apply_failure(store, service, candidate, GenerationFailureReason::ProviderExecutionRejected);
    }
    let dispatch = DispatchAttemptId::from_bytes(candidate.dispatch_attempt_id);
    let events = execution
        .recover_events(dispatch)
        .map_err(|_| recovery_failure(RecoveryFailureStage::JournalRecovery))?;
    let (sequence, disposition, usage, unavailable, output_digest) = assemble_failure(&events)
        .map_err(|_| recovery_failure(RecoveryFailureStage::TerminalAssembly))?;
    if !matches!(
        disposition,
        ProviderTerminalDisposition::RemoteFailed | ProviderTerminalDisposition::RemoteIncomplete
    ) {
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
    verify_settlement(
        candidate,
        sequence,
        disposition,
        usage,
        unavailable,
        output_digest,
    )
    .map_err(|_| recovery_failure(RecoveryFailureStage::SettlementProof))?;
    if let Some(cancellation_taskrun_version) = candidate.cancellation_taskrun_version {
        if candidate.terminal_disposition != Some(disposition) {
            return {
                recovery_failure(RecoveryFailureStage::CancellationStatus);
                Err(())
            };
        }
        return apply_terminal_cancellation(
            store,
            service,
            candidate,
            disposition,
            cancellation_taskrun_version,
        )
        .map_err(|_| recovery_failure(RecoveryFailureStage::CancellationApply));
    }
    apply_failure(
        store,
        service,
        candidate,
        GenerationFailureReason::ProviderExecutionFailed,
    )
    .map_err(|_| recovery_failure(RecoveryFailureStage::FailureApply))
}

fn apply_failure(
    store: &StoreTransaction,
    service: &dyn ConversationTextCommandService,
    candidate: &runne_store::store::provider_failure_recovery::ProviderFailureRecoveryRecord,
    failure_reason: GenerationFailureReason,
) -> Result<(), ()> {
    let stream = store
        .load_conversation(candidate.conversation_id)
        .map_err(|_| recovery_failure(RecoveryFailureStage::ConversationLoad))?;
    let mut matches = stream.events.iter().filter(|event| {
        matches!(event.payload(),
        ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
            if *taskrun_id == candidate.taskrun_id && *attempt_id == candidate.execution_attempt_id)
    });
    let event = matches
        .next()
        .ok_or_else(|| recovery_failure(RecoveryFailureStage::SubmittedMessageProof))?;
    if matches.next().is_some() {
        recovery_failure(RecoveryFailureStage::SubmittedMessageProof);
        return Err(());
    }
    let ConversationEvent::UserMessageAppended {
        message_id, text, ..
    } = event.payload()
    else {
        recovery_failure(RecoveryFailureStage::SubmittedMessageProof);
        return Err(());
    };
    let Some(submit_actor) = candidate.submit_actor.as_ref() else {
        return {
            recovery_failure(RecoveryFailureStage::SubmittedMessageProof);
            Err(())
        };
    };
    if text.as_str() != candidate.submitted_prompt || event.actor() != submit_actor {
        recovery_failure(RecoveryFailureStage::SubmittedMessageProof);
        return Err(());
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
        recovery_failure(RecoveryFailureStage::StartedReceiptBinding);
        return Err(());
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
        actor: candidate.submit_actor.clone().ok_or(())?,
    };
    service
        .finish_text(
            &context,
            FinishConversationTextInput {
                original,
                started,
                completion: ConversationTextCompletion::Rejected {
                    reason: failure_reason,
                },
            },
        )
        .map_err(|_| recovery_failure(RecoveryFailureStage::FinishApplication))?;
    Ok(())
}
