//! Tokio-safe adapter for the synchronous conversation application service.

use std::sync::Arc;

use runne_api::{
    ApiCommandContext, CreateConversationInput, CreateConversationOutput, HostError,
    SessionHostPort,
};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{ConversationRepository, IdGenerator};

/// Async API host that isolates synchronous repository work on Tokio's
/// blocking executor.
pub struct RuntimeConversationHost<R, I> {
    service: Arc<ConversationService<R, I>>,
}

impl<R, I> RuntimeConversationHost<R, I> {
    /// Wraps a synchronous application service for use from async API flows.
    pub fn new(service: ConversationService<R, I>) -> Self {
        Self {
            service: Arc::new(service),
        }
    }
}

impl<R, I> SessionHostPort for RuntimeConversationHost<R, I>
where
    R: ConversationRepository + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    async fn create_conversation(
        &self,
        context: &ApiCommandContext,
        input: CreateConversationInput,
    ) -> Result<CreateConversationOutput, HostError> {
        let service = Arc::clone(&self.service);
        let context = context.clone();
        let conversation_id = input.conversation_id;
        tokio::task::spawn_blocking(move || service.create(&context, input))
            .await
            .map_err(|_| HostError::StorageFailure)?
            .map_err(|error| error.into_host_error(conversation_id))
    }
}
