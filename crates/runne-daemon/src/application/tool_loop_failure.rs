//! Truthful Conversation projection after a canonical D2 loop failure.
use runne_application::{
    commands::BeginConversationTextInput,
    fingerprint::CommandFingerprint,
    ports::{
        AggregateScope, ApplicationCommandContext, ConversationRepository,
        ConversationTextRepository, D2ToolLoopFailurePort, D2ToolLoopFailureResult,
        D2ToolLoopFailureV1, EventStore, IdempotencyScope, OperationTag, TaskRunAssignmentIdentity,
        TextGenerationPhase, TextGenerationReceipt, TextGenerationReceiptLookup,
    },
};
use runne_domain::{
    conversation::{Conversation, ConversationCommand, GenerationFailureReason},
    event::{CommandContext, materialize_batch},
    id::{CycleId, EventId},
    task_run::{TaskRun, TaskRunState},
};
use runne_store::store::StoreTransaction;
use sha2::{Digest, Sha256};

// The writer atomically binds original command, TaskRun cycle and recovery epoch.
#[allow(clippy::too_many_arguments)]
pub(super) fn fail_d2_tool_loop(
    store: &StoreTransaction,
    command: &ApplicationCommandContext,
    original: &BeginConversationTextInput,
    started: &TextGenerationReceipt,
    assignment: &TaskRunAssignmentIdentity,
    cycle_id: CycleId,
    reason: GenerationFailureReason,
    recovery_epoch: Option<u64>,
) -> Result<TextGenerationReceipt, ()> {
    if started.phase != TextGenerationPhase::Started
        || started.taskrun_id != assignment.taskrun_id
        || started.attempt_id != assignment.attempt_id
    {
        return Err(());
    }
    let fingerprint = CommandFingerprint::for_generate_conversation_text(
        &original.conversation_id,
        original.expected_version,
        &original.text,
    );
    let scope = IdempotencyScope {
        runtime_authority_id: store.runtime_authority_id().clone(),
        principal_id: command.principal_id.clone(),
        operation: OperationTag::GenerateConversationText,
        aggregate_scope: AggregateScope::ExistingConversation {
            conversation_id: original.conversation_id,
        },
    };
    let prior = match store
        .lookup_text_generation_receipt(
            command.command_id,
            &command.idempotency_key,
            &scope,
            &fingerprint,
        )
        .map_err(|_| ())?
    {
        TextGenerationReceiptLookup::Miss => None,
        TextGenerationReceiptLookup::Duplicate { stored_result } if stored_result == *started => {
            None
        }
        TextGenerationReceiptLookup::Duplicate { stored_result }
            if stored_result.phase == TextGenerationPhase::Rejected =>
        {
            Some(stored_result)
        }
        _ => return Err(()),
    };
    let conversation = store
        .load_conversation(started.conversation_id)
        .map_err(|_| ())?;
    if prior.is_none() && conversation.current_version != started.conversation_version {
        return Err(());
    }
    let taskrun = store.load_task_run(started.taskrun_id).map_err(|_| ())?;
    let taskrun_aggregate = TaskRun::replay(&taskrun.events).map_err(|_| ())?;
    if taskrun_aggregate.state() != TaskRunState::Failed
        || !taskrun.events.iter().any(|event| {
            matches!(event.payload(),
            runne_domain::task_run::TaskRunEvent::LoopCycleCompleted {
                cycle_id: saved_cycle,
                attempt_id: saved_attempt,
                disposition: runne_domain::agent_loop::LoopDisposition::Fail { .. }
            } if *saved_cycle == cycle_id && *saved_attempt == assignment.attempt_id)
        })
    {
        return Err(());
    }
    let expected_event_id = failure_event_id(command.command_id, started.attempt_id, reason);
    let expected_payload = runne_domain::conversation::ConversationEvent::GenerationFailed {
        taskrun_id: started.taskrun_id,
        attempt_id: started.attempt_id,
        reason,
    };
    let (event, failed) = if let Some(receipt) = prior {
        if receipt.taskrun_version != taskrun.current_version
            || receipt.conversation_version
                != started.conversation_version.checked_add(1).ok_or(())?
            || receipt.workspace_id != started.workspace_id
            || receipt.user_message_id != started.user_message_id
            || receipt.assistant_message_id != started.assistant_message_id
        {
            return Err(());
        }
        let sequence = receipt.conversation_version;
        let saved = usize::try_from(sequence)
            .ok()
            .and_then(|value| value.checked_sub(1))
            .and_then(|index| conversation.events.get(index))
            .ok_or(())?;
        if *saved.event_id() != expected_event_id
            || saved.payload() != &expected_payload
            || saved.command_id() != &command.command_id
            || saved.idempotency_key() != &command.idempotency_key
            || saved.actor() != &command.actor
        {
            return Err(());
        }
        (
            runne_domain::event::UncommittedEvent::from_parts(
                *saved.event_id(),
                saved.aggregate_id().clone(),
                saved.correlation_id().clone(),
                saved.causation_id().copied(),
                *saved.command_id(),
                saved.idempotency_key().clone(),
                saved.schema_version(),
                saved.actor().clone(),
                *saved.sensitivity(),
                saved.payload().clone(),
            ),
            receipt,
        )
    } else {
        let aggregate = Conversation::replay(&conversation.events).map_err(|_| ())?;
        let drafts = aggregate
            .decide(ConversationCommand::FailGeneration {
                taskrun_id: started.taskrun_id,
                attempt_id: started.attempt_id,
                reason,
            })
            .map_err(|_| ())?;
        let event_id = failure_event_id(command.command_id, started.attempt_id, reason);
        let event = materialize_batch(
            drafts,
            &[event_id],
            conversation.events.last().map(|event| *event.event_id()),
            &CommandContext {
                command_id: command.command_id,
                idempotency_key: command.idempotency_key.clone(),
                actor: command.actor.clone(),
            },
        )
        .map_err(|_| ())?
        .into_iter()
        .next()
        .ok_or(())?;
        let failed = TextGenerationReceipt {
            phase: TextGenerationPhase::Rejected,
            conversation_version: started.conversation_version.checked_add(1).ok_or(())?,
            taskrun_version: taskrun.current_version,
            ..started.clone()
        };
        (event, failed)
    };
    match store
        .fail_d2_tool_loop(D2ToolLoopFailureV1 {
            command_id: command.command_id,
            idempotency_key: command.idempotency_key.clone(),
            idempotency_scope: scope,
            command_fingerprint: fingerprint,
            expected_conversation_version: started.conversation_version,
            expected_taskrun_head: taskrun.current_version,
            assignment: assignment.clone(),
            taskrun_id: started.taskrun_id,
            attempt_id: started.attempt_id,
            cycle_id,
            recovery_epoch,
            reason,
            actor: command.actor.clone(),
            conversation_id: started.conversation_id,
            conversation_event: event,
            started_receipt: started.clone(),
            failed_receipt: failed.clone(),
        })
        .map_err(|_| ())?
    {
        D2ToolLoopFailureResult::Committed { receipt }
        | D2ToolLoopFailureResult::Duplicate { receipt } => Ok(receipt),
    }
}

fn failure_event_id(
    command: runne_domain::id::CommandId,
    attempt: runne_domain::id::AttemptId,
    reason: GenerationFailureReason,
) -> EventId {
    let mut hash = Sha256::new();
    hash.update(b"RUNNE_D2_FAILURE_EVENT_V1\0");
    hash.update(command.as_bytes());
    hash.update(attempt.as_bytes());
    hash.update(reason.as_code().as_bytes());
    let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().expect("fixed digest");
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EventId::from_bytes(bytes)
}
