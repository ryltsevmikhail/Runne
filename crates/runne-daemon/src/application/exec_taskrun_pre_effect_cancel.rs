use super::{ConversationTextCommandService, StoreTransaction};
use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, PrincipalId, TextGenerationPhase,
};
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::Actor;
use runne_domain::message::MessageText;
use runne_store::store::provider_failure_recovery::{
    ProviderFailureRecoveryKind, ProviderFailureRecoveryRecord,
};

mod no_admission;
pub(super) use no_admission::{
    recover_all_no_admission_cancellations, settle_no_admission_cancellation,
};

pub(super) fn settle_pre_effect_cancellation(
    store: &StoreTransaction,
    text: &dyn ConversationTextCommandService,
    taskrun_id: runne_domain::id::TaskRunId,
    cancellation_version: u64,
) -> Result<bool, ()> {
    let mut cursor = None;
    let mut matched = None;
    loop {
        let page = store
            .provider_rejection_recovery_candidates(cursor, 128)
            .map_err(|_| ())?;
        for candidate in page.candidates {
            if candidate.taskrun_id == taskrun_id
                && candidate.cancellation_taskrun_version == Some(cancellation_version)
                && matched.replace(candidate).is_some()
            {
                return Err(());
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
    let Some(candidate) = matched else {
        return Ok(false);
    };
    settle_one(store, text, candidate)?;
    Ok(true)
}

pub(super) fn recover_all_pre_effect_cancellations(
    store: &StoreTransaction,
    text: &dyn ConversationTextCommandService,
) -> Result<usize, ()> {
    let mut cursor = None;
    let mut settled = 0usize;
    loop {
        let page = store
            .provider_rejection_recovery_candidates(cursor, 128)
            .map_err(|_| ())?;
        for candidate in page
            .candidates
            .iter()
            .filter(|candidate| candidate.cancellation_taskrun_version.is_some())
        {
            settle_one(store, text, candidate.clone())?;
            settled = settled.checked_add(1).ok_or(())?;
        }
        if page.reached_end {
            return Ok(settled);
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Err(());
        }
    }
}

fn settle_one(
    store: &StoreTransaction,
    text_service: &dyn ConversationTextCommandService,
    candidate: ProviderFailureRecoveryRecord,
) -> Result<(), ()> {
    if candidate.kind != ProviderFailureRecoveryKind::RejectedBeforeEffect
        || candidate.pre_effect_rejection.is_none()
    {
        return Err(());
    }
    let stream = store
        .load_conversation(candidate.conversation_id)
        .map_err(|_| ())?;
    let mut found = stream.events.iter().filter(|event| {
        matches!(event.payload(),
        ConversationEvent::UserMessageAppended { taskrun_id, attempt_id, .. }
            if *taskrun_id == candidate.taskrun_id && *attempt_id == candidate.execution_attempt_id)
    });
    let event = found.next().ok_or(())?;
    if found.next().is_some() {
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
    let command_id = *event.command_id();
    let key = event.idempotency_key().clone();
    let started = store
        .load_text_generation_receipt_by_command(command_id, &key)
        .map_err(|_| ())?;
    if started.phase != TextGenerationPhase::Started
        || started.conversation_id != candidate.conversation_id
        || started.taskrun_id != candidate.taskrun_id
        || started.attempt_id != candidate.execution_attempt_id
        || started.conversation_version != event.sequence()
        || started.taskrun_version != candidate.claim_version
        || started.user_message_id != *message_id
        || Some(started.workspace_id) != candidate.workspace_id
    {
        return Err(());
    }
    let actor: Actor = event.actor().clone();
    let context = ApplicationCommandContext {
        command_id,
        idempotency_key: key,
        principal_id: PrincipalId(candidate.principal_id.clone()),
        actor,
    };
    let version = candidate.cancellation_taskrun_version.ok_or(())?;
    text_service
        .finish_text(
            &context,
            FinishConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id: candidate.conversation_id,
                    expected_version: event.sequence().checked_sub(1).ok_or(())?,
                    text: MessageText::new(text.as_str().to_owned()).map_err(|_| ())?,
                },
                started,
                completion: ConversationTextCompletion::PreEffectRejectedCancellation {
                    evidence: runne_application::ports::ProviderPreEffectCancellationEvidence {
                        dispatch_attempt_id: candidate.dispatch_attempt_id,
                        cancellation_taskrun_version: version,
                    },
                },
            },
        )
        .map_err(|_| ())?;
    Ok(())
}
