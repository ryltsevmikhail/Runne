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
            // The create-conversation fingerprint binds the delivery-context
            // scope, which the reconciliation wire does not carry. Lookup
            // arbitrates these receipts through
            // `stored_create_receipt_fingerprint_matches`; the legacy digest
            // here only feeds the generic non-conversation comparison path.
            CommandFingerprint::for_create_conversation_legacy(&conversation_id, &workspace_id),
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
/// replayed command. The reconciliation request carries no context scope, so
/// the durable data decides: the legacy scope-less digest matches receipts of
/// older builds, and the current format is recomputed from the durable
/// `conversation_context_scope` marker. A non-legacy fingerprint without a
/// readable marker fails closed.
pub(super) fn stored_create_receipt_fingerprint_matches(
    transaction: &Transaction<'_>,
    conversation_id: runne_domain::id::ConversationId,
    workspace_id: runne_domain::id::WorkspaceId,
    stored_fingerprint: &[u8],
) -> Result<bool, Error> {
    let Ok(stored_fingerprint) = <[u8; 32]>::try_from(stored_fingerprint) else {
        return Ok(false);
    };
    if stored_fingerprint
        == *CommandFingerprint::for_create_conversation_legacy(&conversation_id, &workspace_id)
            .as_bytes()
    {
        return Ok(true);
    }
    let marker: Option<String> = transaction
        .query_row(
            "SELECT context_scope FROM conversation_context_scope
             WHERE conversation_id = ?1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| Error::InvariantViolation)?;
    let Some(scope) = marker.as_deref().and_then(ConversationContextScope::parse) else {
        return Ok(false);
    };
    Ok(stored_fingerprint
        == *CommandFingerprint::for_create_conversation(&conversation_id, &workspace_id, scope)
            .as_bytes())
}
