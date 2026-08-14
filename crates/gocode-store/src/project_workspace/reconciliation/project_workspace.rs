mod identity;
mod lookup;
mod outcome;

use gocode_api::{CommandReconciliationContext, CommandReconciliationWitness};
use gocode_application::command_reconciliation::{
    CommandReconciliationEvidence as Evidence, CommandReconciliationRepositoryError as Error,
};
use rusqlite::Transaction;

pub(super) fn project_workspace_lookup(
    transaction: &Transaction<'_>,
    store: &crate::store::StoreTransaction,
    context: &CommandReconciliationContext,
    witness: &CommandReconciliationWitness,
) -> Result<Evidence, Error> {
    lookup::lookup(transaction, store, context, witness)
}
