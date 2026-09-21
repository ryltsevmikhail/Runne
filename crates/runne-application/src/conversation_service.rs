//! Application use case for idempotent conversation creation.

use runne_api::{
    ApiCommandContext, CreateConversationInput, CreateConversationOutput, HostError,
    NonNegativeUnixMillis,
};
use runne_domain::conversation::Conversation;
use runne_domain::event::{Actor, CommandContext, materialize_batch};

use crate::fingerprint::CommandFingerprint;
use crate::ports::{
    AggregateScope, ApplicationCommandContext, CommitError, ConversationCommit,
    ConversationCommitResult, ConversationReceipt, ConversationReceiptLookup,
    ConversationRepository, IdGenerationError, IdGenerator, IdempotencyScope, OperationTag,
    PrincipalId, RuntimeAuthorityId,
};

/// Typed failures produced by [`ConversationService`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationServiceError {
    /// Event identity allocation failed.
    IdGeneration(IdGenerationError),
    /// The API actor could not be represented by the domain actor contract.
    InvalidActor,
    /// The application context did not match the command identity in the input.
    ContextMismatch,
    /// Event materialization violated a domain/application invariant.
    MaterializationFailed,
    /// Atomic persistence or idempotency processing failed.
    Commit(CommitError),
    /// Persistence returned a receipt for a different aggregate or workspace.
    ReceiptMismatch,
    /// The durable timestamp cannot be represented by the public API.
    InvalidCommitTimestamp,
}

impl ConversationServiceError {
    /// Maps an application failure to the closed API host error contract.
    pub fn into_host_error(self, conversation_id: runne_domain::id::ConversationId) -> HostError {
        match self {
            Self::Commit(CommitError::VersionConflict { .. }) => {
                HostError::ConversationAlreadyExists(conversation_id)
            }
            _ => HostError::StorageFailure,
        }
    }
}

/// Synchronous application service behind the async API host port.
pub struct ConversationService<R, I> {
    repository: R,
    id_generator: I,
    runtime_authority_id: RuntimeAuthorityId,
}

impl<R, I> ConversationService<R, I>
where
    R: ConversationRepository,
    I: IdGenerator,
{
    /// Creates a conversation service from abstract persistence and identity ports.
    pub fn new(repository: R, id_generator: I, runtime_authority_id: RuntimeAuthorityId) -> Self {
        Self {
            repository,
            id_generator,
            runtime_authority_id,
        }
    }

    /// Executes an idempotent create-conversation command synchronously.
    pub fn create(
        &self,
        context: &ApiCommandContext,
        input: CreateConversationInput,
    ) -> Result<CreateConversationOutput, ConversationServiceError> {
        let actor = Actor::new(context.actor.as_str())
            .map_err(|_| ConversationServiceError::InvalidActor)?;
        let application_context = ApplicationCommandContext {
            command_id: input.command_id,
            idempotency_key: input.idempotency_key.clone(),
            principal_id: PrincipalId(context.principal.as_str().to_owned()),
            actor,
        };
        self.create_from_application(&application_context, input)
    }

    /// Executes an idempotent create-conversation command from the canonical
    /// application identity context.
    pub fn create_from_application(
        &self,
        context: &ApplicationCommandContext,
        input: CreateConversationInput,
    ) -> Result<CreateConversationOutput, ConversationServiceError> {
        if context.command_id != input.command_id
            || context.idempotency_key != input.idempotency_key
        {
            return Err(ConversationServiceError::ContextMismatch);
        }
        let fingerprint = CommandFingerprint::for_create_conversation(
            &input.conversation_id,
            &input.workspace_id,
            input.scope,
        );
        let scope = IdempotencyScope {
            runtime_authority_id: self.runtime_authority_id.clone(),
            principal_id: context.principal_id.clone(),
            operation: OperationTag::CreateConversation,
            aggregate_scope: AggregateScope::NewConversation {
                conversation_id: input.conversation_id,
                workspace_id: input.workspace_id,
            },
        };

        match self
            .repository
            .lookup_conversation_receipt(
                input.command_id,
                &input.idempotency_key,
                &scope,
                &fingerprint,
                input.scope,
            )
            .map_err(ConversationServiceError::Commit)?
        {
            ConversationReceiptLookup::Miss => {}
            ConversationReceiptLookup::Duplicate { stored_result } => {
                return receipt_to_output(&input, stored_result);
            }
        }

        let draft = Conversation::decide_create(input.conversation_id, input.workspace_id);
        let event_ids = self
            .id_generator
            .next_event_ids(1)
            .map_err(ConversationServiceError::IdGeneration)?;
        let events = materialize_batch(
            vec![draft],
            &event_ids,
            None,
            &CommandContext {
                command_id: input.command_id,
                idempotency_key: input.idempotency_key.clone(),
                actor: context.actor.clone(),
            },
        )
        .map_err(|_| ConversationServiceError::MaterializationFailed)?;

        let result = self
            .repository
            .commit_conversation(ConversationCommit {
                command_id: input.command_id,
                idempotency_key: input.idempotency_key.clone(),
                idempotency_scope: scope,
                command_fingerprint: fingerprint,
                expected_version: 0,
                events,
                workspace_id: input.workspace_id,
                context_scope: input.scope,
            })
            .map_err(ConversationServiceError::Commit)?;

        match result {
            ConversationCommitResult::Committed { result }
            | ConversationCommitResult::Duplicate {
                stored_result: result,
            } => receipt_to_output(&input, result),
        }
    }
}

fn receipt_to_output(
    input: &CreateConversationInput,
    receipt: ConversationReceipt,
) -> Result<CreateConversationOutput, ConversationServiceError> {
    if receipt.conversation_id != input.conversation_id
        || receipt.workspace_id != input.workspace_id
        || receipt.new_version != 1
    {
        return Err(ConversationServiceError::ReceiptMismatch);
    }
    let committed_millis = receipt.committed_at.as_unix_micros().div_euclid(1_000);
    let committed_at = NonNegativeUnixMillis::new(committed_millis)
        .ok_or(ConversationServiceError::InvalidCommitTimestamp)?;
    Ok(CreateConversationOutput {
        conversation_id: receipt.conversation_id,
        workspace_id: receipt.workspace_id,
        committed_at,
        stream_version: receipt.new_version,
    })
}
