//! Runtime host port for API-level conversation creation.

use crate::{ApiCommandContext, CreateConversationInput, CreateConversationOutput, HostError};

/// Port through which the API creates conversations in the runtime host.
///
/// This contract is owned by the API crate and remains independent of
/// application, runtime, and storage implementations.
pub trait SessionHostPort: Send + Sync {
    /// Creates a conversation using the supplied command context and input.
    fn create_conversation(
        &self,
        ctx: &ApiCommandContext,
        input: CreateConversationInput,
    ) -> impl std::future::Future<Output = Result<CreateConversationOutput, HostError>> + Send;
}
