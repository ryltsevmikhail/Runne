use runne_api::{
    CommandReconciliationContext, CommandReconciliationWitness, CommandReconciliationWitnessRef,
};
use runne_application::command_reconciliation::{
    CommandReconciliationEvidence as Evidence, CommandReconciliationRepositoryError as Error,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{identity, outcome};
use crate::codec::{ProjectWorkspaceReceiptCodec, StoreCodec};

pub(super) fn lookup(
    transaction: &Transaction<'_>,
    store: &crate::store::StoreTransaction,
    context: &CommandReconciliationContext,
    witness: &CommandReconciliationWitness,
) -> Result<Evidence, Error> {
    let request = identity::request(store, context, witness)?;
    let collision: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT fingerprint FROM command_receipts WHERE command_id = ?1",
            [context.command_id().as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| Error::Unavailable)?;
    if collision.is_some() {
        return Err(Error::Conflict);
    }
    let stored = transaction.query_row(
        "SELECT runtime_authority_id, principal_id, operation, aggregate_kind, aggregate_id, idempotency_key, semantic_fingerprint, outcome FROM project_workspace_command_receipts WHERE command_id = ?1",
        [context.command_id().as_bytes()],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, String>(5)?, row.get::<_, Vec<u8>>(6)?, row.get::<_, Vec<u8>>(7)?)),
    ).optional().map_err(|_| Error::Unavailable)?;
    let Some((authority, principal, operation, kind, id, key, fingerprint, outcome)) = stored
    else {
        return collision_for_missing(transaction, &request);
    };
    if authority != request.authority
        || principal != request.principal
        || operation != request.scope.operation as i64
        || kind != request.scope.aggregate_kind as i64
        || id != request.scope.aggregate_id
        || key != request.key.as_str()
        || fingerprint != request.fingerprint
    {
        return Err(Error::Conflict);
    }
    validate_root_admission(transaction, store, context, witness)?;
    let receipt = ProjectWorkspaceReceiptCodec
        .decode(&outcome)
        .map_err(|_| Error::InvariantViolation)?;
    outcome::outcome_for(witness, receipt).map(|value| Evidence::Terminal(Box::new(value)))
}

fn collision_for_missing(
    transaction: &Transaction<'_>,
    request: &crate::project_workspace::receipts::ReceiptRequest<'_>,
) -> Result<Evidence, Error> {
    let collision: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE runtime_authority_id = ?1 AND principal_id = ?2 AND operation = ?3 AND aggregate_kind = ?4 AND aggregate_id = ?5 AND idempotency_key = ?6)", params![request.authority, request.principal, request.scope.operation as i64, request.scope.aggregate_kind as i64, request.scope.aggregate_id, request.key.as_str()], |row| row.get(0)).map_err(|_| Error::Unavailable)?;
    if collision {
        Err(Error::Conflict)
    } else {
        Ok(Evidence::NotCommitted)
    }
}

fn validate_root_admission(
    transaction: &Transaction<'_>,
    store: &crate::store::StoreTransaction,
    context: &CommandReconciliationContext,
    witness: &CommandReconciliationWitness,
) -> Result<(), Error> {
    let CommandReconciliationWitnessRef::BindWorkspaceRoot {
        workspace_id,
        expected_version,
        admission_digest,
    } = witness.view()
    else {
        return Ok(());
    };
    let proven: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM root_admission_nonces WHERE runtime_authority_id = ?1 AND principal_id = ?2 AND workspace_id = ?3 AND expected_version = ?4 AND admission_digest = ?5)",
        params![store.runtime_authority_id().0, context.principal().as_str(), workspace_id.as_bytes(), expected_version as i64, admission_digest],
        |row| row.get(0),
    ).map_err(|_| Error::Unavailable)?;
    if proven {
        Ok(())
    } else {
        Err(Error::InvariantViolation)
    }
}
