//! Atomic D2 FinalStop projection into the original Conversation receipt.

use crate::canonical_provider::D2ToolTerminalRef;
use runne_application::{
    commands::BeginConversationTextInput,
    fingerprint::CommandFingerprint,
    ports::{
        AggregateScope, ApplicationCommandContext, ConversationRepository,
        ConversationTextRepository, D2ToolLoopCompletionPort, D2ToolLoopCompletionResult,
        D2ToolLoopCompletionV1, D2ToolTerminalSourceV1, EventStore, IdGenerator, IdempotencyScope,
        OperationTag, TaskRunAssignmentIdentity, TextGenerationPhase, TextGenerationReceipt,
        TextGenerationReceiptLookup,
    },
};
use runne_domain::{
    conversation::{Conversation, ConversationCommand},
    event::{CommandContext, materialize_batch},
    id::{CycleId, IntegrityDigest},
    message::MessageText,
    task_run::TaskRun,
    verification::PlanEvaluationRef,
};
use runne_store::store::{
    D2ToolLoopCompletionReplayBinding, StoreTransaction, taskrun_tool_invocation::ToolSourceRef,
};
use sha2::{Digest, Sha256};

#[allow(clippy::too_many_arguments)]
pub(super) fn complete_d2_tool_loop(
    store: &StoreTransaction,
    command: &ApplicationCommandContext,
    original: &BeginConversationTextInput,
    started: &TextGenerationReceipt,
    assignment: &TaskRunAssignmentIdentity,
    cycle_id: CycleId,
    evaluation_ref: PlanEvaluationRef,
    terminal: &D2ToolTerminalRef,
    sources: &[ToolSourceRef],
    assistant_text: String,
) -> Result<TextGenerationReceipt, D2ToolLoopCompletionError> {
    let text = MessageText::new(assistant_text).map_err(|_| D2ToolLoopCompletionError::Invalid)?;
    if started.phase != TextGenerationPhase::Started
        || started.taskrun_id != assignment.taskrun_id
        || started.attempt_id != assignment.attempt_id
        || evaluation_ref.taskrun_id != started.taskrun_id
        || terminal.attempt_id.as_bytes() == &[0; 16]
        || sources.is_empty()
    {
        return Err(D2ToolLoopCompletionError::Invalid);
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
    let terminal_sources = terminal_sources(sources);
    if let TextGenerationReceiptLookup::Duplicate { stored_result } = store
        .lookup_text_generation_receipt(
            command.command_id,
            &command.idempotency_key,
            &scope,
            &fingerprint,
        )?
    {
        if stored_result.phase == TextGenerationPhase::Completed
            && stored_result.conversation_id == started.conversation_id
            && stored_result.workspace_id == started.workspace_id
            && stored_result.taskrun_id == started.taskrun_id
            && stored_result.attempt_id == started.attempt_id
            && stored_result.user_message_id == started.user_message_id
            && stored_result.assistant_message_id == started.assistant_message_id
            && started
                .conversation_version
                .checked_add(1)
                .is_some_and(|version| stored_result.conversation_version == version)
        {
            let binding = D2ToolLoopCompletionReplayBinding {
                command_id: command.command_id,
                taskrun_id: started.taskrun_id,
                attempt_id: started.attempt_id,
                cycle_id,
                taskrun_head: stored_result.taskrun_version,
                evaluation_ref: evaluation_ref.clone(),
                terminal_attempt_id: *terminal.attempt_id.as_bytes(),
                terminal_outbox_id: terminal.outbox_id,
                terminal_sequence: terminal.terminal_sequence,
                settlement_digest: IntegrityDigest::from_bytes(terminal.settlement_digest),
                terminal_sources: terminal_sources.clone(),
                assistant_message_id: started.assistant_message_id,
                assistant_text_digest: IntegrityDigest::from_bytes(
                    Sha256::digest(text.as_str().as_bytes()).into(),
                ),
                assistant_text_length: text.as_str().len() as u64,
                completed_receipt: stored_result.clone(),
            };
            if store.validate_d2_tool_loop_completion_replay(&binding)? {
                return Ok(stored_result);
            }
            return Err(D2ToolLoopCompletionError::Conflict);
        }
        if stored_result.phase != TextGenerationPhase::Started {
            return Err(D2ToolLoopCompletionError::Conflict);
        }
    }
    let conversation = store
        .load_conversation(started.conversation_id)
        .map_err(|_| D2ToolLoopCompletionError::Unavailable)?;
    if conversation.current_version != started.conversation_version
        || conversation.events.len() as u64 != conversation.current_version
    {
        return Err(D2ToolLoopCompletionError::Conflict);
    }
    let conversation_aggregate = Conversation::replay(&conversation.events)
        .map_err(|_| D2ToolLoopCompletionError::Invalid)?;
    let drafts = conversation_aggregate
        .decide(ConversationCommand::AppendAssistantMessage {
            message_id: started.assistant_message_id,
            taskrun_id: started.taskrun_id,
            attempt_id: started.attempt_id,
            text: text.clone(),
        })
        .map_err(|_| D2ToolLoopCompletionError::Invalid)?;

    let taskrun_stream = store
        .load_task_run(started.taskrun_id)
        .map_err(|_| D2ToolLoopCompletionError::Unavailable)?;
    if taskrun_stream.current_version <= evaluation_ref.evaluated_stream_head {
        return Err(D2ToolLoopCompletionError::Conflict);
    }
    let taskrun =
        TaskRun::replay(&taskrun_stream.events).map_err(|_| D2ToolLoopCompletionError::Invalid)?;
    if !taskrun.state().is_terminal()
        || !taskrun
            .state()
            .eq(&runne_domain::task_run::TaskRunState::Succeeded)
    {
        return Err(D2ToolLoopCompletionError::Invalid);
    }

    let event_ids = store
        .next_event_ids(drafts.len())
        .map_err(|_| D2ToolLoopCompletionError::Unavailable)?;
    let event = materialize_batch(
        drafts,
        &event_ids,
        conversation.events.last().map(|event| *event.event_id()),
        &CommandContext {
            command_id: command.command_id,
            idempotency_key: command.idempotency_key.clone(),
            actor: command.actor.clone(),
        },
    )
    .map_err(|_| D2ToolLoopCompletionError::Invalid)?
    .into_iter()
    .next()
    .ok_or(D2ToolLoopCompletionError::Invalid)?;
    let completed = TextGenerationReceipt {
        phase: TextGenerationPhase::Completed,
        conversation_version: started
            .conversation_version
            .checked_add(1)
            .ok_or(D2ToolLoopCompletionError::Invalid)?,
        taskrun_version: taskrun_stream.current_version,
        ..started.clone()
    };
    let terminal_attempt_id = *terminal.attempt_id.as_bytes();
    let assistant_text_digest =
        IntegrityDigest::from_bytes(Sha256::digest(text.as_str().as_bytes()).into());
    let request = D2ToolLoopCompletionV1 {
        command_id: command.command_id,
        idempotency_key: command.idempotency_key.clone(),
        idempotency_scope: scope,
        command_fingerprint: fingerprint,
        expected_conversation_version: started.conversation_version,
        expected_taskrun_head: taskrun_stream.current_version,
        assignment: assignment.clone(),
        taskrun_id: started.taskrun_id,
        attempt_id: started.attempt_id,
        cycle_id,
        evaluation_ref,
        terminal_attempt_id,
        terminal_outbox_id: terminal.outbox_id,
        terminal_sequence: terminal.terminal_sequence,
        settlement_digest: IntegrityDigest::from_bytes(terminal.settlement_digest),
        terminal_sources,
        assistant_text_digest,
        assistant_text_length: text.as_str().len() as u64,
        conversation_id: started.conversation_id,
        conversation_event: event,
        started_receipt: started.clone(),
        completed_receipt: completed.clone(),
    };
    match store.complete_d2_tool_loop(request)? {
        D2ToolLoopCompletionResult::Committed { receipt }
        | D2ToolLoopCompletionResult::Duplicate { receipt } => Ok(receipt),
    }
}

fn terminal_sources(sources: &[ToolSourceRef]) -> Vec<D2ToolTerminalSourceV1> {
    sources
        .iter()
        .map(|source| D2ToolTerminalSourceV1 {
            dispatch_attempt_id: source.dispatch_attempt_id,
            sequence: source.sequence,
            event_kind: source.event_kind,
            terminal: source.terminal,
            plaintext_digest: source.plaintext_digest,
            profile_digest: source.profile_digest,
            runtime_generation: source.runtime_generation,
        })
        .collect()
}

#[derive(Debug)]
pub(super) enum D2ToolLoopCompletionError {
    Invalid,
    Conflict,
    Unavailable,
    Commit,
}

impl From<runne_application::ports::CommitError> for D2ToolLoopCompletionError {
    fn from(value: runne_application::ports::CommitError) -> Self {
        let _ = value;
        Self::Commit
    }
}
