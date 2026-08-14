use gocode_api::{
    CommandReconciliationContext, CommandReconciliationWitness, CommandReconciliationWitnessRef,
};
use gocode_application::command_reconciliation::{
    CommandReconciliationEvidence as Evidence, CommandReconciliationRepositoryError as Error,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{identity, outcome};
use crate::codec::{IdempotencyScopeCodec, StoreCodec};

pub(super) fn lookup(
    transaction: &Transaction<'_>,
    store: &crate::store::StoreTransaction,
    context: &CommandReconciliationContext,
    witness: &CommandReconciliationWitness,
) -> Result<Evidence, Error> {
    let (scope, fingerprint) = identity::identity(store, context, witness)?;
    let bytes = IdempotencyScopeCodec
        .encode(&scope)
        .map_err(|_| Error::InvariantViolation)?;
    command_id_collision(transaction, context)?;
    let row = transaction.query_row("SELECT idempotency_scope_bytes, idempotency_key, fingerprint, command_outcome FROM command_receipts WHERE command_id = ?1", [context.command_id().as_bytes()], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?))).optional().map_err(|_| Error::InvariantViolation)?;
    let Some((stored_scope, key, stored_fingerprint, outcome_bytes)) = row else {
        return scope_collision(transaction, context, &bytes);
    };
    if stored_scope != bytes
        || key != context.idempotency_key().as_str().as_bytes()
        || stored_fingerprint != fingerprint.as_bytes()
    {
        return Err(Error::Conflict);
    }
    match witness.view() {
        CommandReconciliationWitnessRef::CreateConversation {
            conversation_id,
            workspace_id,
        } => outcome::created(transaction, &outcome_bytes, conversation_id, workspace_id),
        CommandReconciliationWitnessRef::GenerateConversationText {
            conversation_id,
            expected_version,
            ..
        } => outcome::text_outcome(
            transaction,
            context,
            &scope,
            &outcome_bytes,
            conversation_id,
            expected_version,
        ),
        _ => Err(Error::InvariantViolation),
    }
}

fn command_id_collision(
    transaction: &Transaction<'_>,
    context: &CommandReconciliationContext,
) -> Result<(), Error> {
    let project: Option<i64> = transaction
        .query_row(
            "SELECT operation FROM project_workspace_command_receipts WHERE command_id = ?1",
            [context.command_id().as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| Error::Unavailable)?;
    if project.is_some() {
        Err(Error::Conflict)
    } else {
        Ok(())
    }
}

fn scope_collision(
    transaction: &Transaction<'_>,
    context: &CommandReconciliationContext,
    bytes: &[u8],
) -> Result<Evidence, Error> {
    let collision: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM command_receipts WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2)",
        params![bytes, context.idempotency_key().as_str().as_bytes()],
        |row| row.get(0),
    ).map_err(|_| Error::InvariantViolation)?;
    if collision {
        Err(Error::Conflict)
    } else {
        Ok(Evidence::NotCommitted)
    }
}
