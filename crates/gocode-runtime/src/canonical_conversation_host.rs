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
                            completion: ConversationTextCompletion::AssistantText(assistant_text),
                        },
                    )
                    .await
                    .map_err(map_runtime_error)?
            }
        };
        if completed.phase != TextGenerationPhase::Completed {
            return Err(ConversationHostError::InvariantViolation);
        }

        let snapshot = self.list_messages(completed.conversation_id).await?;
        result_from_snapshot(completed, snapshot)
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

include!("canonical_conversation_host/helpers.rs");

#[cfg(test)]
mod tests {
    include!("canonical_conversation_host/tests.rs");
}
