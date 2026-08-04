//! Provider-neutral async canonical execution boundary owned by the runtime.

use gocode_application::commands::BeginConversationTextInput;
use gocode_application::ports::{ApplicationCommandContext, TextGenerationReceipt};
use gocode_provider::ProviderFuture;
use thiserror::Error;

/// Immutable runtime job created only after canonical begin commits.
#[derive(Debug, Clone)]
pub struct CanonicalProviderExecutionJob {
    /// Authenticated original command context.
    pub context: ApplicationCommandContext,
    /// Original canonical input whose user message is already committed.
    pub original: BeginConversationTextInput,
    /// Exact durable Started receipt.
    pub started: TextGenerationReceipt,
}

/// Closed canonical provider execution failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CanonicalProviderExecutionError {
    /// Admission or credential failed before network effect.
    #[error("canonical provider rejected before effect")]
    RejectedBeforeEffect,
    /// Provider returned a typed remote failure.
    #[error("canonical provider failed remotely")]
    RemoteFailed,
    /// Provider returned incomplete output that cannot be applied.
    #[error("canonical provider output is incomplete")]
    RemoteIncomplete,
    /// Effect disposition is ambiguous and must not be retried automatically.
    #[error("canonical provider effect is uncertain")]
    Uncertain,
    /// Output or revalidation policy denied progression.
    #[error("canonical provider policy denied progression")]
    PolicyDenied,
    /// Runtime-owned execution or persistence is unavailable.
    #[error("canonical provider execution is unavailable")]
    Unavailable,
    /// Durable execution evidence conflicts.
    #[error("canonical provider execution conflicts")]
    Conflict,
}

/// Object-safe async service supervised with the runtime job lifecycle.
pub trait CanonicalProviderExecutionService: Send + Sync {
    /// Executes one exact admitted provider job through journal and outbox.
    fn execute(
        &self,
        job: CanonicalProviderExecutionJob,
    ) -> ProviderFuture<'_, Result<TextGenerationReceipt, CanonicalProviderExecutionError>>;
}
