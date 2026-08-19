// Canonical Conversation host backed by the runtime and durable event store.

use std::sync::Arc;

use runne_api::{
    CanonicalConversationMessage, CanonicalMessageRole, ConversationCommandContext,
    ConversationCommandHostPort, ConversationCreatedAck, ConversationHostError,
    ConversationMessagesSnapshot, ConversationQueryHostPort, ConversationTextResult,
    CreateCanonicalConversationCommand, CreateConversationInput, GenerateConversationTextCommand,
    NonNegativeUnixMillis,
};
use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::conversation_service::{ConversationService, ConversationServiceError};
use runne_application::conversation_text_service::ConversationTextServiceError;
use runne_application::ports::{
    ApplicationCommandContext, CommitError, ConversationRepository, EventStoreError, IdGenerator,
    PrincipalId, TextGenerationPhase, TextGenerationReceipt,
};
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use runne_domain::conversation::{Conversation, ConversationEvent};
use runne_domain::event::Actor;
use runne_domain::message::{MAX_MESSAGE_TEXT_BYTES, MessageText};
use sha2::{Digest, Sha256};

use crate::canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
};
use crate::error::RuntimeError;
use crate::handle::RuntimeHandle;

const LOCAL_RESPONSE_PREFIX: &str = "Runne local response: ";

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
