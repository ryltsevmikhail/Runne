//! Read-only command-reconciliation adapter over the authoritative writer.

mod conversation;
mod project_workspace;
mod shared;

use runne_api::{
    CommandReconciliationContext, CommandReconciliationWitness, CommandReconciliationWitnessRef,
};
use runne_application::command_reconciliation::{
    CommandReconciliationEvidence as Evidence, CommandReconciliationRepository,
    CommandReconciliationRepositoryError as Error,
};
use rusqlite::Transaction;

use self::conversation::conversation_lookup;
use self::project_workspace::project_workspace_lookup;

impl CommandReconciliationRepository for super::ProjectWorkspaceStore {
    fn reconcile_command(
        &self,
        context: &CommandReconciliationContext,
        witness: &CommandReconciliationWitness,
    ) -> Result<Evidence, Error> {
        self.store
            .with_project_workspace_transaction(|transaction| {
                lookup(transaction, &self.store, context, witness).map_err(shared::map_error)
            })
            .map_err(shared::map_project_error)
    }
}

fn lookup(
    transaction: &Transaction<'_>,
    store: &crate::store::StoreTransaction,
    context: &CommandReconciliationContext,
    witness: &CommandReconciliationWitness,
) -> Result<Evidence, Error> {
    match witness.view() {
        CommandReconciliationWitnessRef::CreateConversation { .. }
        | CommandReconciliationWitnessRef::GenerateConversationText { .. } => {
            conversation_lookup(transaction, store, context, witness)
        }
        _ => project_workspace_lookup(transaction, store, context, witness),
    }
}
