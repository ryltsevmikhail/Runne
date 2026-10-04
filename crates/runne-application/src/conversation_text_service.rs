//! Two-phase durable coordination of Conversation messages and TaskRun.

use std::sync::Arc;

use runne_domain::command::{CreateTaskRun, TaskRunCommand, TerminalResult};
use runne_domain::conversation::{Conversation, ConversationError};
use runne_domain::event::{CommandContext, materialize_batch};
use runne_domain::task_run::TaskRun;

use crate::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, ConversationTextCompletion,
    FinishConversationTextInput,
};
use crate::fingerprint::CommandFingerprint;
use crate::ports::{
    AggregateScope, ApplicationCommandContext, BeginTextGenerationCommit, CommitError,
    ConversationRepository, ConversationTextRepository, EventStore, EventStoreError,
    FinishTextGenerationCommit, IdGenerationError, IdGenerator, IdempotencyScope, OperationTag,
    RejectTextGenerationAfterNoAdmissionCancellationCommit,
    RejectTextGenerationAfterPreEffectCancellationCommit,
    RejectTextGenerationAfterTerminalCancellationCommit, RejectTextGenerationCommit,
    RuntimeAuthorityId, TextGenerationCommitResult, TextGenerationPhase, TextGenerationReceipt,
    TextGenerationReceiptLookup,
};
use crate::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};

/// Typed failures from [`ConversationTextService`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationTextServiceError {
    /// Another principal holds the conversation's writer lease.
    WriterFenced,
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

    /// Appends a user message to the exact already claimed TaskRun.
    fn begin_claimed_text(
        &self,
        context: &ApplicationCommandContext,
        input: BeginClaimedConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        let _ = (context, input);
        Err(ConversationTextServiceError::StoredDataUnavailable)
    }

    /// Executes the durable completed phase.
    fn finish_text(
        &self,
        context: &ApplicationCommandContext,
        input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError>;
}

include!("conversation_text_service/factory.rs");
include!("conversation_text_service/begin.rs");
include!("conversation_text_service/begin_claimed.rs");
include!("conversation_text_service/finish.rs");
include!("conversation_text_service/finish/remote_cancel_replay.rs");
include!("conversation_text_service/finish/terminal_drafts.rs");
include!("conversation_text_service/finish/cancellation_receipt.rs");
include!("conversation_text_service/finish/cancellation_facts.rs");
include!("conversation_text_service/trait.rs");
include!("conversation_text_service/helpers.rs");
