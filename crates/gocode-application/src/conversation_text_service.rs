//! Two-phase durable coordination of Conversation messages and TaskRun.

use std::sync::Arc;

use gocode_domain::command::{CreateTaskRun, TaskRunCommand, TerminalResult};
use gocode_domain::conversation::{Conversation, ConversationError};
use gocode_domain::event::{CommandContext, materialize_batch};
use gocode_domain::task_run::TaskRun;

use crate::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use crate::fingerprint::CommandFingerprint;
use crate::ports::{
    AggregateScope, ApplicationCommandContext, BeginTextGenerationCommit, CommitError,
    ConversationRepository, ConversationTextRepository, EventStore, EventStoreError,
    FinishTextGenerationCommit, IdGenerationError, IdGenerator, IdempotencyScope, OperationTag,
    RejectTextGenerationCommit, RuntimeAuthorityId, TextGenerationCommitResult,
    TextGenerationPhase, TextGenerationReceipt, TextGenerationReceiptLookup,
};
use crate::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};

/// Typed failures from [`ConversationTextService`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationTextServiceError {
    /// Input contained material registered as prohibited or could not be
    /// inspected safely.
    ProhibitedSecretMaterial,
    /// Target Conversation does not exist.
    ConversationNotFound,
    /// Stored event data could not be loaded or replayed safely.
    StoredDataUnavailable,
    /// Expected version or idempotency identity conflicted.
    Conflict,
    /// Domain lifecycle rejected the requested message transition.
    ConversationDomain(ConversationError),
    /// TaskRun lifecycle rejected the coordinated transition.
    TaskRunDomain,
    /// Identity allocation failed.
    IdGeneration(IdGenerationError),
    /// Event materialization violated an invariant.
    MaterializationFailed,
    /// Persistence failed.
    Commit(CommitError),
    /// Persistence returned a receipt unrelated to this command.
    ReceiptMismatch,
}

/// Application coordinator for resumable local text execution.
pub struct ConversationTextService<R, I> {
    repository: R,
    id_generator: I,
    runtime_authority_id: RuntimeAuthorityId,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

/// Object-safe application boundary consumed by the runtime dispatcher.
pub trait ConversationTextCommandService: Send + Sync {
    /// Executes the durable started phase.
    fn begin_text(
        &self,
        context: &ApplicationCommandContext,
        input: BeginConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError>;

    /// Executes the durable completed phase.
    fn finish_text(
        &self,
        context: &ApplicationCommandContext,
        input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError>;
}

impl<R, I> ConversationTextService<R, I>
where
    R: ConversationRepository + ConversationTextRepository + EventStore,
    I: IdGenerator,
{
    /// Creates a coordinator from abstract persistence and identity ports.
    pub fn new(
        repository: R,
        id_generator: I,
        runtime_authority_id: RuntimeAuthorityId,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Self {
        Self {
            repository,
            id_generator,
            runtime_authority_id,
            prohibited_content,
        }
    }

    /// Durably appends the user message and starts its exact TaskRun attempt.
    pub fn begin(
        &self,
        context: &ApplicationCommandContext,
        input: BeginConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        match self.prohibited_content.inspect(
            CanonicalContentBoundary::CanonicalMutation,
            input.text.as_str().as_bytes(),
        ) {
            Ok(ContentDisposition::Allowed { .. }) => {}
            Ok(ContentDisposition::Prohibited { .. }) | Err(_) => {
                return Err(ConversationTextServiceError::ProhibitedSecretMaterial);
            }
        }
        let fingerprint = CommandFingerprint::for_generate_conversation_text(
            &input.conversation_id,
            input.expected_version,
            &input.text,
        );
        let scope = self.scope(context, input.conversation_id);
        match self
            .repository
            .lookup_text_generation_receipt(
                context.command_id,
                &context.idempotency_key,
                &scope,
                &fingerprint,
            )
            .map_err(map_commit)?
        {
            TextGenerationReceiptLookup::Miss => {}
            TextGenerationReceiptLookup::Duplicate { stored_result } => {
                validate_receipt(&stored_result, input.conversation_id)?;
                return Ok(stored_result);
            }
        }

        let stream = self
            .repository
            .load_conversation(input.conversation_id)
            .map_err(map_conversation_load)?;
        validate_conversation_stream(&stream)?;
        if stream.current_version != input.expected_version {
            return Err(ConversationTextServiceError::Conflict);
        }
        let conversation = Conversation::replay(&stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;

        let taskrun_id = self
            .id_generator
            .next_taskrun_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let attempt_id = self
            .id_generator
            .next_attempt_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let user_message_id = self
            .id_generator
            .next_message_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let assistant_message_id = self
            .id_generator
            .next_message_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;

        let conversation_drafts = conversation
            .decide(
                gocode_domain::command::ConversationCommand::AppendUserMessage {
                    message_id: user_message_id,
                    taskrun_id,
                    attempt_id,
                    text: input.text.clone(),
                },
            )
            .map_err(ConversationTextServiceError::ConversationDomain)?;
        let taskrun_drafts = TaskRun::decide_create_running(
            CreateTaskRun {
                taskrun_id,
                conversation_id: input.conversation_id,
                workspace_id: conversation.workspace_id,
            },
            attempt_id,
        )
        .map_err(|_| ConversationTextServiceError::TaskRunDomain)?;
        let event_ids = self
            .id_generator
            .next_event_ids(conversation_drafts.len() + taskrun_drafts.len())
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let domain_context = domain_context(context);
        let split = conversation_drafts.len();
        let conversation_events = materialize_batch(
            conversation_drafts,
            &event_ids[..split],
            stream.last_event_id,
            &domain_context,
        )
        .map_err(|_| ConversationTextServiceError::MaterializationFailed)?;
        let taskrun_events =
            materialize_batch(taskrun_drafts, &event_ids[split..], None, &domain_context)
                .map_err(|_| ConversationTextServiceError::MaterializationFailed)?;
        let receipt = TextGenerationReceipt {
            phase: TextGenerationPhase::Started,
            conversation_id: input.conversation_id,
            workspace_id: conversation.workspace_id,
            taskrun_id,
            attempt_id,
            user_message_id,
            assistant_message_id,
            conversation_version: stream
                .current_version
                .checked_add(1)
                .ok_or(ConversationTextServiceError::StoredDataUnavailable)?,
            taskrun_version: 4,
        };

        let result = self
            .repository
            .begin_text_generation(BeginTextGenerationCommit {
                command_id: context.command_id,
                idempotency_key: context.idempotency_key.clone(),
                idempotency_scope: scope,
                command_fingerprint: fingerprint,
                expected_conversation_version: input.expected_version,
                conversation_events,
                taskrun_events,
                receipt,
            })
            .map_err(map_commit)?;
        commit_result(result, input.conversation_id)
    }

    /// Commits deterministic assistant output and completes the TaskRun.
    pub fn finish(
        &self,
        context: &ApplicationCommandContext,
        input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        let fingerprint = CommandFingerprint::for_generate_conversation_text(
            &input.original.conversation_id,
            input.original.expected_version,
            &input.original.text,
        );
        let scope = self.scope(context, input.original.conversation_id);
        let durable = match self
            .repository
            .lookup_text_generation_receipt(
                context.command_id,
                &context.idempotency_key,
                &scope,
                &fingerprint,
            )
            .map_err(map_commit)?
        {
            TextGenerationReceiptLookup::Miss => {
                return Err(ConversationTextServiceError::ReceiptMismatch);
            }
            TextGenerationReceiptLookup::Duplicate { stored_result } => stored_result,
        };
        validate_receipt(&durable, input.original.conversation_id)?;
        if matches!(
            durable.phase,
            TextGenerationPhase::Completed
                | TextGenerationPhase::Rejected
                | TextGenerationPhase::ProhibitedInputRejected
        ) {
            return Ok(durable);
        }
        if durable != input.started || durable.phase != TextGenerationPhase::Started {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }

        let conversation_stream = self
            .repository
            .load_conversation(durable.conversation_id)
            .map_err(map_conversation_load)?;
        validate_conversation_stream(&conversation_stream)?;
        if conversation_stream.current_version != durable.conversation_version {
            return Err(ConversationTextServiceError::Conflict);
        }
        let conversation = Conversation::replay(&conversation_stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;
        let taskrun_stream = self
            .repository
            .load_task_run(durable.taskrun_id)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;
        if taskrun_stream.current_version != durable.taskrun_version
            || taskrun_stream.last_event_id.is_none()
        {
            return Err(ConversationTextServiceError::StoredDataUnavailable);
        }
        let taskrun = TaskRun::replay(&taskrun_stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;

        let terminal_phase = match &input.completion {
            ConversationTextCompletion::AssistantText(_) => TextGenerationPhase::Completed,
            ConversationTextCompletion::ProhibitedInputRejected { .. } => {
                TextGenerationPhase::ProhibitedInputRejected
            }
            ConversationTextCompletion::Rejected { .. } => TextGenerationPhase::Rejected,
        };
        let (conversation_drafts, taskrun_drafts) = match input.completion {
            ConversationTextCompletion::AssistantText(assistant_text) => {
                let conversation_drafts = conversation
                    .decide(
                        gocode_domain::command::ConversationCommand::AppendAssistantMessage {
                            message_id: durable.assistant_message_id,
                            taskrun_id: durable.taskrun_id,
                            attempt_id: durable.attempt_id,
                            text: assistant_text,
                        },
                    )
                    .map_err(ConversationTextServiceError::ConversationDomain)?;
                let taskrun_drafts = taskrun
                    .decide(TaskRunCommand::Complete {
                        result: TerminalResult::Success,
                    })
                    .map_err(|_| ConversationTextServiceError::TaskRunDomain)?;
                (conversation_drafts, taskrun_drafts)
            }
            ConversationTextCompletion::ProhibitedInputRejected { reason }
            | ConversationTextCompletion::Rejected { reason } => {
                let conversation_drafts = conversation
                    .decide(
                        gocode_domain::command::ConversationCommand::FailGeneration {
                            taskrun_id: durable.taskrun_id,
                            attempt_id: durable.attempt_id,
                            reason,
                        },
                    )
                    .map_err(ConversationTextServiceError::ConversationDomain)?;
                let taskrun_drafts = taskrun
                    .decide(TaskRunCommand::FailGeneration { reason })
                    .map_err(|_| ConversationTextServiceError::TaskRunDomain)?;
                (conversation_drafts, taskrun_drafts)
            }
        };
        let event_ids = self
            .id_generator
            .next_event_ids(conversation_drafts.len() + taskrun_drafts.len())
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let domain_context = domain_context(context);
        let split = conversation_drafts.len();
        let conversation_events = materialize_batch(
            conversation_drafts,
            &event_ids[..split],
            conversation_stream.last_event_id,
            &domain_context,
        )
        .map_err(|_| ConversationTextServiceError::MaterializationFailed)?;
        let taskrun_events = materialize_batch(
            taskrun_drafts,
            &event_ids[split..],
            taskrun_stream.last_event_id,
            &domain_context,
        )
        .map_err(|_| ConversationTextServiceError::MaterializationFailed)?;
        let terminal = TextGenerationReceipt {
            phase: terminal_phase,
            conversation_version: durable
                .conversation_version
                .checked_add(1)
                .ok_or(ConversationTextServiceError::StoredDataUnavailable)?,
            taskrun_version: durable
                .taskrun_version
                .checked_add(1)
                .ok_or(ConversationTextServiceError::StoredDataUnavailable)?,
            ..durable
        };
        let result = match terminal_phase {
            TextGenerationPhase::Completed => {
                self.repository
                    .finish_text_generation(FinishTextGenerationCommit {
                        command_id: context.command_id,
                        idempotency_key: context.idempotency_key.clone(),
                        idempotency_scope: scope,
                        command_fingerprint: fingerprint,
                        expected_conversation_version: input.started.conversation_version,
                        expected_taskrun_version: input.started.taskrun_version,
                        conversation_events,
                        taskrun_events,
                        receipt: terminal,
                    })
            }
            TextGenerationPhase::Rejected | TextGenerationPhase::ProhibitedInputRejected => self
                .repository
                .reject_text_generation(RejectTextGenerationCommit {
                    command_id: context.command_id,
                    idempotency_key: context.idempotency_key.clone(),
                    idempotency_scope: scope,
                    command_fingerprint: fingerprint,
                    expected_conversation_version: input.started.conversation_version,
                    expected_taskrun_version: input.started.taskrun_version,
                    conversation_events,
                    taskrun_events,
                    receipt: terminal,
                }),
            TextGenerationPhase::Started => unreachable!("started is not a terminal phase"),
        }
        .map_err(map_commit)?;
        commit_result(result, input.original.conversation_id)
    }

    fn scope(
        &self,
        context: &ApplicationCommandContext,
        conversation_id: gocode_domain::id::ConversationId,
    ) -> IdempotencyScope {
        IdempotencyScope {
            runtime_authority_id: self.runtime_authority_id.clone(),
            principal_id: context.principal_id.clone(),
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
        }
    }
}

impl<R, I> ConversationTextCommandService for ConversationTextService<R, I>
where
    R: ConversationRepository + ConversationTextRepository + EventStore + Send + Sync,
    I: IdGenerator + Send + Sync,
{
    fn begin_text(
        &self,
        context: &ApplicationCommandContext,
        input: BeginConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        self.begin(context, input)
    }

    fn finish_text(
        &self,
        context: &ApplicationCommandContext,
        input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        self.finish(context, input)
    }
}

fn domain_context(context: &ApplicationCommandContext) -> CommandContext {
    CommandContext {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key.clone(),
        actor: context.actor.clone(),
    }
}

fn validate_conversation_stream(
    stream: &crate::ports::ConversationLoadedStream,
) -> Result<(), ConversationTextServiceError> {
    let Some(last) = stream.events.last() else {
        return Err(ConversationTextServiceError::StoredDataUnavailable);
    };
    if stream.current_version != last.sequence()
        || stream.last_event_id != Some(*last.event_id())
        || stream.events.len() as u64 != stream.current_version
    {
        return Err(ConversationTextServiceError::StoredDataUnavailable);
    }
    Ok(())
}

fn validate_receipt(
    receipt: &TextGenerationReceipt,
    conversation_id: gocode_domain::id::ConversationId,
) -> Result<(), ConversationTextServiceError> {
    let versions_valid = match receipt.phase {
        TextGenerationPhase::Started => receipt.taskrun_version == 4,
        TextGenerationPhase::Completed
        | TextGenerationPhase::Rejected
        | TextGenerationPhase::ProhibitedInputRejected => receipt.taskrun_version == 5,
    };
    if receipt.conversation_id != conversation_id || !versions_valid {
        return Err(ConversationTextServiceError::ReceiptMismatch);
    }
    Ok(())
}

fn commit_result(
    result: TextGenerationCommitResult,
    conversation_id: gocode_domain::id::ConversationId,
) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
    let result = match result {
        TextGenerationCommitResult::Committed { result } => result,
        TextGenerationCommitResult::Duplicate { stored_result } => stored_result,
    };
    validate_receipt(&result, conversation_id)?;
    Ok(result)
}

fn map_conversation_load(error: EventStoreError) -> ConversationTextServiceError {
    match error {
        EventStoreError::NotFound => ConversationTextServiceError::ConversationNotFound,
        EventStoreError::CorruptData | EventStoreError::Unavailable => {
            ConversationTextServiceError::StoredDataUnavailable
        }
    }
}

fn map_commit(error: CommitError) -> ConversationTextServiceError {
    match error {
        CommitError::VersionConflict { .. } | CommitError::IdempotencyConflict { .. } => {
            ConversationTextServiceError::Conflict
        }
        error => ConversationTextServiceError::Commit(error),
    }
}
