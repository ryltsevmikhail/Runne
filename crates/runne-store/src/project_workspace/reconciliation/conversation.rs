mod identity;
mod lookup;
mod outcome;

use runne_api::{CommandReconciliationContext, CommandReconciliationWitness};
use runne_application::command_reconciliation::{
    CommandReconciliationEvidence as Evidence, CommandReconciliationRepositoryError as Error,
};
use rusqlite::Transaction;

pub(super) fn conversation_lookup(
    transaction: &Transaction<'_>,
    store: &crate::store::StoreTransaction,
    context: &CommandReconciliationContext,
    witness: &CommandReconciliationWitness,
) -> Result<Evidence, Error> {
    lookup::lookup(transaction, store, context, witness)
}
