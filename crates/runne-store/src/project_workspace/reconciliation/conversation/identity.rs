use runne_api::{
    CommandReconciliationContext, CommandReconciliationWitness, CommandReconciliationWitnessRef,
};
use runne_application::command_reconciliation::CommandReconciliationRepositoryError as Error;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{AggregateScope, IdempotencyScope, OperationTag};
use runne_domain::conversation::ConversationContextScope;
use rusqlite::{OptionalExtension, Transaction};

pub(super) fn identity(
    store: &crate::store::StoreTransaction,
    context: &CommandReconciliationContext,
    witness: &CommandReconciliationWitness,
) -> Result<(IdempotencyScope, CommandFingerprint), Error> {
    let (operation, aggregate_scope, fingerprint) = match witness.view() {
        CommandReconciliationWitnessRef::CreateConversation {
            conversation_id,
            workspace_id,
        } => (
            OperationTag::CreateConversation,
            AggregateScope::NewConversation {
                conversation_id,
                workspace_id,
            },
            CommandFingerprint::for_create_conversation(
                &conversation_id,
                &workspace_id,
                ConversationContextScope::Workspace,
            ),
        ),
        CommandReconciliationWitnessRef::CreateTextOnlyConversation {
            conversation_id,
            workspace_id,
        } => (
            OperationTag::CreateConversation,
            AggregateScope::NewConversation {
                conversation_id,
                workspace_id,
            },
            CommandFingerprint::for_create_conversation(
                &conversation_id,
                &workspace_id,
                ConversationContextScope::TextOnly,
            ),
        ),
        CommandReconciliationWitnessRef::GenerateConversationText {
            conversation_id,
            expected_version,
            text,
        } => (
            OperationTag::GenerateConversationText,
            AggregateScope::ExistingConversation { conversation_id },
            CommandFingerprint::for_generate_conversation_text(
                &conversation_id,
                expected_version,
                &text.clone().into_domain(),
            ),
        ),
        _ => return Err(Error::InvariantViolation),
    };
    Ok((
        IdempotencyScope {
            runtime_authority_id: store.runtime_authority_id().clone(),
            principal_id: runne_application::ports::PrincipalId(
                context.principal().as_str().into(),
            ),
            operation,
            aggregate_scope,
        },
        fingerprint,
    ))
}

/// Whether a stored create-conversation receipt fingerprint identifies the
/// replayed command. The durable marker must agree with the witness scope.
/// A legacy scope-less receipt is accepted only for Workspace commands with
/// no marker or an explicit Workspace marker, matching supported migration
/// states. A TextOnly or invalid marker always fails closed.
pub(super) fn stored_create_receipt_fingerprint_matches(
    transaction: &Transaction<'_>,
    conversation_id: runne_domain::id::ConversationId,
    workspace_id: runne_domain::id::WorkspaceId,
    expected_scope: ConversationContextScope,
    stored_fingerprint: &[u8],
) -> Result<bool, Error> {
    let Ok(stored_fingerprint) = <[u8; 32]>::try_from(stored_fingerprint) else {
        return Ok(false);
    };
    let marker: Option<String> = transaction
        .query_row(
            "SELECT context_scope FROM conversation_context_scope
             WHERE conversation_id = ?1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| Error::InvariantViolation)?;
    let scope = match marker.as_deref() {
        Some(marker) => match ConversationContextScope::parse(marker) {
            Some(scope) if scope == expected_scope => scope,
            _ => return Ok(false),
        },
        None if expected_scope == ConversationContextScope::Workspace
            && stored_fingerprint
                == *CommandFingerprint::for_create_conversation_legacy(
                    &conversation_id,
                    &workspace_id,
                )
                .as_bytes() =>
        {
            return Ok(true);
        }
        None => return Ok(false),
    };
    if expected_scope == ConversationContextScope::Workspace
        && stored_fingerprint
            == *CommandFingerprint::for_create_conversation_legacy(&conversation_id, &workspace_id)
                .as_bytes()
    {
        return Ok(true);
    }
    Ok(scope == expected_scope
        && stored_fingerprint
            == *CommandFingerprint::for_create_conversation(
                &conversation_id,
                &workspace_id,
                expected_scope,
            )
            .as_bytes())
}
