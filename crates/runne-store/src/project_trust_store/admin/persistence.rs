use runne_application::project_trust::admin::AdminError;
use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::ProjectTrustStore;

/// Runs under the existing same-T1 connection mutex and IMMEDIATE writer transaction.
pub(super) fn transact<R>(
    store: &ProjectTrustStore,
    operation: impl FnOnce(&Transaction<'_>) -> Result<R, AdminError>,
) -> Result<R, AdminError> {
    let mut connection = store
        .connection
        .lock()
        .map_err(|_| AdminError::Unavailable)?;
    connection
        .verify_retained_identity()
        .map_err(|_| AdminError::Unavailable)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| AdminError::Unavailable)?;
    verify_sql_authority(&transaction, store.instance_epoch, store.authority_id)?;
    let result = operation(&transaction)?;
    verify_sql_authority(&transaction, store.instance_epoch, store.authority_id)?;
    transaction
        .commit()
        .map_err(|_| AdminError::UnknownAfterAction)?;
    connection
        .verify_retained_identity()
        .map_err(|_| AdminError::UnknownAfterAction)?;
    verify_sql_authority(&connection, store.instance_epoch, store.authority_id)
        .map_err(|_| AdminError::UnknownAfterAction)?;
    Ok(result)
}

pub(super) fn verify_sql_authority(
    connection: &Connection,
    expected_epoch: u64,
    expected_authority: [u8; 16],
) -> Result<(), AdminError> {
    let identity: (String, i64, i64, Vec<u8>) = connection
        .query_row(
            "SELECT schema_kind, schema_version, instance_epoch, authority_id
             FROM project_trust_schema WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| AdminError::Unavailable)?;
    if identity.0 != "runne.project-trust"
        || identity.1 != 3
        || u64::try_from(identity.2).ok() != Some(expected_epoch)
        || identity.3.as_slice() != expected_authority
    {
        return Err(AdminError::Unavailable);
    }
    Ok(())
}
