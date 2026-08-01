//! Canonical Conversation host backed by the runtime and durable event store.

use std::sync::Arc;

use gocode_api::{
    CanonicalConversationMessage, CanonicalMessageRole, ConversationCommandContext,
    ConversationCommandHostPort, ConversationCreatedAck, ConversationHostError,
    ConversationMessagesSnapshot, ConversationQueryHostPort, ConversationTextResult,
    CreateCanonicalConversationCommand, CreateConversationInput, GenerateConversationTextCommand,
    NonNegativeUnixMillis,
};
use gocode_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use gocode_application::conversation_service::{ConversationService, ConversationServiceError};
use gocode_application::conversation_text_service::ConversationTextServiceError;
use gocode_application::ports::{
    ApplicationCommandContext, CommitError, ConversationRepository, EventStoreError, IdGenerator,
    PrincipalId, TextGenerationPhase, TextGenerationReceipt,
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use gocode_domain::conversation::{Conversation, ConversationEvent};
use gocode_domain::event::Actor;
use gocode_domain::message::{MAX_MESSAGE_TEXT_BYTES, MessageText};
use sha2::{Digest, Sha256};

use crate::canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
};
use crate::error::RuntimeError;
use crate::handle::RuntimeHandle;

const LOCAL_RESPONSE_PREFIX: &str = "GOCODE local response: ";

/// Closed failures from a local text provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTextProviderError {
    /// The provider produced text outside the canonical message contract.
    InvalidOutput,
}

/// Side-effect-free text provider boundary used by the first canonical slice.
pub trait LocalTextProvider: Send + Sync {
    /// Produces one bounded assistant message from validated user text.
    fn generate(&self, input: &MessageText) -> Result<MessageText, LocalTextProviderError>;
}

/// Deterministic in-process provider with no network, filesystem, process, or
/// credential access.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeterministicTextProvider;

impl LocalTextProvider for DeterministicTextProvider {
    fn generate(&self, input: &MessageText) -> Result<MessageText, LocalTextProviderError> {
        let response =
            if LOCAL_RESPONSE_PREFIX.len() + input.as_str().len() <= MAX_MESSAGE_TEXT_BYTES {
                format!("{LOCAL_RESPONSE_PREFIX}{}", input.as_str())
            } else {
                let digest = Sha256::digest(input.as_str().as_bytes());
                format!("{LOCAL_RESPONSE_PREFIX}sha256:{}", hex::encode(digest))
            };
        MessageText::new(response).map_err(|_| LocalTextProviderError::InvalidOutput)
    }
}

/// Cloneable canonical host.
///
/// Conversation creation uses the existing application service, generation
/// phases always pass through [`RuntimeHandle`], and queries replay the
/// authoritative committed Conversation stream.
pub struct RuntimeCanonicalConversationHost<R, I, E, P> {
    handle: RuntimeHandle,
    create_service: Arc<ConversationService<R, I>>,
    event_store: E,
    provider: Arc<P>,
    provider_execution: bool,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
}

impl<R, I, E, P> Clone for RuntimeCanonicalConversationHost<R, I, E, P>
where
    E: Clone,
{
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            create_service: Arc::clone(&self.create_service),
            event_store: self.event_store.clone(),
            provider: Arc::clone(&self.provider),
            provider_execution: self.provider_execution,
            prohibited_content: Arc::clone(&self.prohibited_content),
        }
    }
}

impl<R, I, E, P> RuntimeCanonicalConversationHost<R, I, E, P> {
    /// Creates a host from the runtime command path and durable adapters.
    pub fn new(
        handle: RuntimeHandle,
        create_service: Arc<ConversationService<R, I>>,
        event_store: E,
        provider: P,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Self {
        Self {
            handle,
            create_service,
            event_store,
            provider: Arc::new(provider),
            provider_execution: false,
            prohibited_content,
        }
    }

    /// Creates a host whose Started jobs must use the runtime-supervised provider service.
    pub fn new_provider(
        handle: RuntimeHandle,
        create_service: Arc<ConversationService<R, I>>,
        event_store: E,
        prohibited_content: Arc<dyn ProhibitedContentPort>,
    ) -> Self
    where
        P: Default,
    {
        Self {
            handle,
            create_service,
            event_store,
            provider: Arc::new(P::default()),
            provider_execution: true,
            prohibited_content,
        }
    }
}

impl<R, I, E, P> ConversationCommandHostPort for RuntimeCanonicalConversationHost<R, I, E, P>
where
    R: ConversationRepository + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
    E: ConversationRepository + Clone + Send + Sync + 'static,
    P: LocalTextProvider + 'static,
{
    async fn create_conversation(
        &self,
        context: ConversationCommandContext,
        command: CreateCanonicalConversationCommand,
    ) -> Result<ConversationCreatedAck, ConversationHostError> {
        let application_context = into_application_context(context)?;
        let input = CreateConversationInput {
            conversation_id: command.conversation_id,
            workspace_id: command.workspace_id,
            command_id: application_context.command_id,
            idempotency_key: application_context.idempotency_key.clone(),
        };
        let service = Arc::clone(&self.create_service);
        let output = tokio::task::spawn_blocking(move || {
            service.create_from_application(&application_context, input)
        })
        .await
        .map_err(|_| ConversationHostError::Unavailable)?
        .map_err(map_create_error)?;

        Ok(ConversationCreatedAck {
            conversation_id: output.conversation_id,
            workspace_id: output.workspace_id,
            stream_version: output.stream_version,
            committed_at: output.committed_at,
        })
    }

    async fn generate_text(
        &self,
        context: ConversationCommandContext,
        command: GenerateConversationTextCommand,
    ) -> Result<ConversationTextResult, ConversationHostError> {
        let application_context = into_application_context(context)?;
        let original = BeginConversationTextInput {
            conversation_id: command.conversation_id,
            expected_version: command.expected_version,
            text: command.text.into_domain(),
        };
        let started = self
            .handle
            .begin_conversation_text(application_context.clone(), original.clone())
            .await
            .map_err(map_runtime_error)?;
        let completed = match started.phase {
            TextGenerationPhase::Completed => started,
            TextGenerationPhase::Rejected => {
                return Err(ConversationHostError::ProviderOutputRejected);
            }
            TextGenerationPhase::ProhibitedInputRejected => {
                return Err(ConversationHostError::ProhibitedSecretMaterial);
            }
            TextGenerationPhase::Started => {
                if !matches!(
                    self.prohibited_content.inspect(
                        CanonicalContentBoundary::OutboundDelivery,
                        original.text.as_str().as_bytes(),
                    ),
                    Ok(ContentDisposition::Allowed { .. })
                ) {
                    let rejected = self
                        .handle
                        .finish_conversation_text(
                            application_context,
                            FinishConversationTextInput {
                                original,
                                started,
                                completion:
                                    ConversationTextCompletion::ProhibitedInputRejected {
                                    reason: gocode_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
                                },
                            },
                        )
                        .await
                        .map_err(map_runtime_error)?;
                    if rejected.phase != TextGenerationPhase::ProhibitedInputRejected {
                        return Err(ConversationHostError::InvariantViolation);
                    }
                    return Err(ConversationHostError::ProhibitedSecretMaterial);
                }
                if self.provider_execution {
                    match self
                        .handle
                        .execute_canonical_provider(CanonicalProviderExecutionJob {
                            context: application_context.clone(),
                            original: original.clone(),
                            started: started.clone(),
                        })
                        .await
                    {
                        Ok(receipt) => receipt,
                        Err(CanonicalProviderExecutionError::Uncertain) => {
                            return Err(ConversationHostError::ProviderOutputRejected);
                        }
                        Err(error) => {
                            let rejected = self
                                .handle
                                .finish_conversation_text(
                                    application_context,
                                    FinishConversationTextInput {
                                        original,
                                        started,
                                        completion: ConversationTextCompletion::Rejected {
                                            reason: gocode_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
                                        },
                                    },
                                )
                                .await
                                .map_err(map_runtime_error)?;
                            if rejected.phase != TextGenerationPhase::Rejected {
                                return Err(ConversationHostError::InvariantViolation);
                            }
                            return Err(map_provider_execution_error(error));
                        }
                    }
                } else {
                    let assistant_text = self
                        .provider
                        .generate(&original.text)
                        .map_err(|_| ConversationHostError::InvariantViolation)?;
                    if !matches!(
                        self.prohibited_content.inspect(
                            CanonicalContentBoundary::CanonicalMutation,
                            assistant_text.as_str().as_bytes(),
                        ),
                        Ok(ContentDisposition::Allowed { .. })
                    ) {
                        let rejected = self
                        .handle
                        .finish_conversation_text(
                            application_context,
                            FinishConversationTextInput {
                                original,
                                started,
                                completion: ConversationTextCompletion::Rejected {
                                    reason: gocode_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
                                },
                            },
                        )
                        .await
                        .map_err(map_runtime_error)?;
                        if rejected.phase != TextGenerationPhase::Rejected {
                            return Err(ConversationHostError::InvariantViolation);
                        }
                        return Err(ConversationHostError::ProviderOutputRejected);
                    }
                    self.handle
                        .finish_conversation_text(
                            application_context,
                            FinishConversationTextInput {
                                original,
                                started,
                                completion: ConversationTextCompletion::AssistantText(
                                    assistant_text,
                                ),
                            },
                        )
                        .await
                        .map_err(map_runtime_error)?
                }
            }
        };
        if completed.phase != TextGenerationPhase::Completed {
            return Err(ConversationHostError::InvariantViolation);
        }

        let snapshot = self.list_messages(completed.conversation_id).await?;
        result_from_snapshot(completed, snapshot)
    }
}

const fn map_provider_execution_error(
    error: CanonicalProviderExecutionError,
) -> ConversationHostError {
    match error {
        CanonicalProviderExecutionError::Unavailable => ConversationHostError::Unavailable,
        CanonicalProviderExecutionError::Conflict => ConversationHostError::Conflict,
        CanonicalProviderExecutionError::RejectedBeforeEffect
        | CanonicalProviderExecutionError::RemoteFailed
        | CanonicalProviderExecutionError::RemoteIncomplete
        | CanonicalProviderExecutionError::Uncertain
        | CanonicalProviderExecutionError::PolicyDenied => {
            ConversationHostError::ProviderOutputRejected
        }
    }
}

impl<R, I, E, P> ConversationQueryHostPort for RuntimeCanonicalConversationHost<R, I, E, P>
where
    E: ConversationRepository + Clone + Send + Sync + 'static,
    R: Send + Sync,
    I: Send + Sync,
    P: Send + Sync,
{
    async fn list_messages(
        &self,
        conversation_id: gocode_domain::id::ConversationId,
    ) -> Result<ConversationMessagesSnapshot, ConversationHostError> {
        let event_store = self.event_store.clone();
        tokio::task::spawn_blocking(move || {
            let stream = event_store
                .load_conversation(conversation_id)
                .map_err(map_event_store_error)?;
            validate_loaded_stream(&stream)?;
            Conversation::replay(&stream.events).map_err(|_| ConversationHostError::Unavailable)?;

            let messages = stream
                .events
                .iter()
                .filter_map(event_to_message)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ConversationMessagesSnapshot {
                conversation_id,
                stream_version: stream.current_version,
                messages,
            })
        })
        .await
        .map_err(|_| ConversationHostError::Unavailable)?
    }
}

fn into_application_context(
    context: ConversationCommandContext,
) -> Result<ApplicationCommandContext, ConversationHostError> {
    let actor = Actor::new(context.actor.as_str().to_owned())
        .map_err(|_| ConversationHostError::InvariantViolation)?;
    Ok(ApplicationCommandContext {
        command_id: context.command_id,
        idempotency_key: context.idempotency_key,
        principal_id: PrincipalId(context.principal.as_str().to_owned()),
        actor,
    })
}

fn event_to_message(
    event: &gocode_domain::event::EventEnvelope<ConversationEvent>,
) -> Option<Result<CanonicalConversationMessage, ConversationHostError>> {
    let (message_id, role, taskrun_id, attempt_id, text) = match event.payload() {
        ConversationEvent::UserMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text,
        } => (
            *message_id,
            CanonicalMessageRole::User,
            *taskrun_id,
            *attempt_id,
            text.as_str(),
        ),
        ConversationEvent::AssistantMessageAppended {
            message_id,
            taskrun_id,
            attempt_id,
            text,
        } => (
            *message_id,
            CanonicalMessageRole::Assistant,
            *taskrun_id,
            *attempt_id,
            text.as_str(),
        ),
        ConversationEvent::ConversationCreated { .. } | ConversationEvent::ConversationClosed => {
            return None;
        }
        ConversationEvent::GenerationFailed { .. } => return None,
    };
    let committed_at =
        NonNegativeUnixMillis::new(event.timestamp().as_unix_micros().div_euclid(1_000))
            .ok_or(ConversationHostError::Unavailable);
    Some(
        committed_at.map(|committed_at| CanonicalConversationMessage {
            message_id,
            role,
            taskrun_id,
            attempt_id,
            text: text.to_owned(),
            committed_at,
        }),
    )
}

fn result_from_snapshot(
    receipt: TextGenerationReceipt,
    snapshot: ConversationMessagesSnapshot,
) -> Result<ConversationTextResult, ConversationHostError> {
    if snapshot.stream_version != receipt.conversation_version {
        return Err(ConversationHostError::InvariantViolation);
    }
    let user_message = snapshot
        .messages
        .iter()
        .find(|message| message.message_id == receipt.user_message_id)
        .cloned()
        .ok_or(ConversationHostError::InvariantViolation)?;
    let assistant_message = snapshot
        .messages
        .iter()
        .find(|message| message.message_id == receipt.assistant_message_id)
        .cloned()
        .ok_or(ConversationHostError::InvariantViolation)?;
    if user_message.role != CanonicalMessageRole::User
        || assistant_message.role != CanonicalMessageRole::Assistant
        || user_message.taskrun_id != receipt.taskrun_id
        || assistant_message.taskrun_id != receipt.taskrun_id
        || user_message.attempt_id != receipt.attempt_id
        || assistant_message.attempt_id != receipt.attempt_id
    {
        return Err(ConversationHostError::InvariantViolation);
    }

    Ok(ConversationTextResult {
        conversation_id: receipt.conversation_id,
        taskrun_id: receipt.taskrun_id,
        attempt_id: receipt.attempt_id,
        conversation_stream_version: receipt.conversation_version,
        taskrun_stream_version: receipt.taskrun_version,
        user_message,
        assistant_message,
    })
}

fn validate_loaded_stream(
    stream: &gocode_application::ports::ConversationLoadedStream,
) -> Result<(), ConversationHostError> {
    let Some(last) = stream.events.last() else {
        return Err(ConversationHostError::Unavailable);
    };
    if stream.current_version != last.sequence()
        || stream.last_event_id != Some(*last.event_id())
        || stream.events.len() as u64 != stream.current_version
    {
        return Err(ConversationHostError::Unavailable);
    }
    Ok(())
}

fn map_create_error(error: ConversationServiceError) -> ConversationHostError {
    match error {
        ConversationServiceError::Commit(CommitError::VersionConflict { .. })
        | ConversationServiceError::Commit(CommitError::IdempotencyConflict { .. }) => {
            ConversationHostError::Conflict
        }
        ConversationServiceError::Commit(_)
        | ConversationServiceError::IdGeneration(_)
        | ConversationServiceError::InvalidCommitTimestamp => ConversationHostError::Unavailable,
        ConversationServiceError::InvalidActor
        | ConversationServiceError::ContextMismatch
        | ConversationServiceError::MaterializationFailed
        | ConversationServiceError::ReceiptMismatch => ConversationHostError::InvariantViolation,
    }
}

fn map_runtime_error(error: RuntimeError) -> ConversationHostError {
    match error {
        RuntimeError::Backpressure { .. } => ConversationHostError::Backpressure,
        RuntimeError::RuntimeClosed | RuntimeError::WorkerExecutionFailed { .. } => {
            ConversationHostError::Unavailable
        }
        RuntimeError::Application(_) => ConversationHostError::InvariantViolation,
        RuntimeError::ConversationApplication(error) => match error {
            ConversationTextServiceError::ProhibitedSecretMaterial => {
                ConversationHostError::ProhibitedSecretMaterial
            }
            ConversationTextServiceError::ConversationNotFound => ConversationHostError::NotFound,
            ConversationTextServiceError::Conflict
            | ConversationTextServiceError::ConversationDomain(_) => {
                ConversationHostError::Conflict
            }
            ConversationTextServiceError::StoredDataUnavailable
            | ConversationTextServiceError::IdGeneration(_)
            | ConversationTextServiceError::Commit(_) => ConversationHostError::Unavailable,
            ConversationTextServiceError::TaskRunDomain
            | ConversationTextServiceError::MaterializationFailed
            | ConversationTextServiceError::ReceiptMismatch => {
                ConversationHostError::InvariantViolation
            }
        },
    }
}

fn map_event_store_error(error: EventStoreError) -> ConversationHostError {
    match error {
        EventStoreError::NotFound => ConversationHostError::NotFound,
        EventStoreError::CorruptData | EventStoreError::Unavailable => {
            ConversationHostError::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_provider_is_stable_and_keeps_large_output_bounded() {
        let provider = DeterministicTextProvider;
        assert_eq!(
            provider
                .generate(&MessageText::new("hello").unwrap())
                .unwrap(),
            MessageText::new("GOCODE local response: hello").unwrap()
        );

        let maximum = MessageText::new("x".repeat(MAX_MESSAGE_TEXT_BYTES)).unwrap();
        let first = provider.generate(&maximum).unwrap();
        let second = provider.generate(&maximum).unwrap();
        assert_eq!(first, second);
        assert!(first.as_str().len() <= MAX_MESSAGE_TEXT_BYTES);
        assert!(first.as_str().starts_with(LOCAL_RESPONSE_PREFIX));
    }
}
