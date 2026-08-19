use runne_api::{
    CommandReconciliationContext, CommandReconciliationWitness, CommandReconciliationWitnessRef,
};
use runne_application::command_reconciliation::CommandReconciliationRepositoryError as Error;
use runne_application::fingerprint::CommandFingerprint;
use runne_application::ports::{AggregateScope, IdempotencyScope, OperationTag};

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
            CommandFingerprint::for_create_conversation(&conversation_id, &workspace_id),
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
