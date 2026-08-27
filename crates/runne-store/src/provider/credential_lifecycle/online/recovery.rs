use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{map_sql, snapshot};
use runne_provider::{
    CredentialBrokerCommand, CredentialBrokerTarget, CredentialLifecycleError, CredentialRecoveryWork,
};
use rusqlite::TransactionBehavior;

pub(super) fn reconcile(
    store: &SqliteProviderCredentialLifecycleStore,
    now: i64,
) -> Result<Vec<CredentialRecoveryWork>, CredentialLifecycleError> {
    if now < 0 {
        return Err(CredentialLifecycleError::InvalidInput);
    }
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let ids = transaction.prepare("SELECT operation_id FROM provider_credential_operations WHERE state IN ('CLAIMED', 'NATIVE_EFFECT_OBSERVED', 'READBACK_VERIFIED') ORDER BY operation_id").map_err(map_sql)?.query_map([], |row| row.get::<_, Vec<u8>>(0)).map_err(map_sql)?.collect::<Result<Vec<_>, _>>().map_err(map_sql)?;
    let mut work = Vec::with_capacity(ids.len());
    for id in ids {
        let operation = runne_provider::CredentialOperationId::from_bytes(
            id.try_into()
                .map_err(|_| CredentialLifecycleError::CorruptState)?,
        )
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
        let snapshot = snapshot(
                &transaction,
                operation,
                &store.enrollment_authority,
            )?;
        let attempt: Option<i64> = transaction.query_row(
            "SELECT claimed_ticket_attempt FROM provider_credential_operations WHERE operation_id=?1",
            [operation.as_bytes().as_slice()],
            |row| row.get(0),
        ).map_err(map_sql)?;
        let attempt = runne_provider::CredentialTicketAttempt::new(
            u64::try_from(attempt.ok_or(CredentialLifecycleError::CorruptState)?)
                .map_err(|_| CredentialLifecycleError::CorruptState)?,
        ).map_err(|_| CredentialLifecycleError::CorruptState)?;
        let command = recovery_command(&snapshot, attempt)?;
        let recovery = CredentialRecoveryWork::new(snapshot.clone())
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
        work.push(
            recovery
                .with_command(command)
                .map_err(|_| CredentialLifecycleError::CorruptState)?,
        );
    }
    transaction
        .execute(
            "UPDATE provider_credential_authority_heads
             SET observed_at_high_water=MAX(observed_at_high_water, ?1)
             WHERE provider_id IN (
                 SELECT operations.provider_id
                 FROM provider_credential_operations AS operations
                 JOIN provider_credential_ticket_attempts AS attempts
                   ON attempts.operation_id=operations.operation_id
                 WHERE operations.state='PREPARED' AND attempts.expires_at<=?1
             )",
            [now],
        )
        .map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_ticket_attempts AS attempts
             SET state='EXPIRED'
             WHERE state='ISSUED' AND expires_at<=?1 AND EXISTS (
                 SELECT 1 FROM provider_credential_operations AS operations
                 WHERE operations.operation_id=attempts.operation_id
                   AND operations.state='PREPARED'
             )",
            [now],
        )
        .map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_ticket_attempts
             SET state='TOMBSTONED', terminal_digest=ticket_digest
             WHERE state='EXPIRED' AND expires_at<=?1",
            [now],
        )
        .map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_authority_heads
             SET observed_at_high_water=MAX(observed_at_high_water, ?1)
             WHERE provider_id IN (
                 SELECT provider_id FROM provider_credential_operations
                 WHERE state IN ('CLAIMED', 'NATIVE_EFFECT_OBSERVED', 'READBACK_VERIFIED')
             )",
            [now],
        )
        .map_err(map_sql)?;
    transaction.commit().map_err(map_sql)?;
    Ok(work)
}

fn recovery_command(
    operation: &runne_provider::CredentialOperationSnapshot,
    attempt: runne_provider::CredentialTicketAttempt,
) -> Result<CredentialBrokerCommand, CredentialLifecycleError> {
    let (target, binding) = match operation.action() {
        runne_provider::CredentialOperationAction::Pair
        | runne_provider::CredentialOperationAction::Revoke
        | runne_provider::CredentialOperationAction::RetiredVersionCleanup => (
            CredentialBrokerTarget::Version(
                operation
                    .allocated_credential_version()
                    .or(operation.target_credential_version())
                    .ok_or(CredentialLifecycleError::CorruptState)?
                    .clone(),
            ), None),
        runne_provider::CredentialOperationAction::MigrateLegacy => (
            CredentialBrokerTarget::LegacyImport(
                operation
                    .allocated_credential_version()
                    .ok_or(CredentialLifecycleError::CorruptState)?
                    .clone(),
            ), None),
        runne_provider::CredentialOperationAction::LegacySourceCleanup => (CredentialBrokerTarget::LegacySource, None),
        runne_provider::CredentialOperationAction::WriterIdentityMigrationEffect
        | runne_provider::CredentialOperationAction::WriterIdentityMigrationVerify => {
            let metadata = operation
                .metadata()
                .migration()
                .ok_or(CredentialLifecycleError::CorruptState)?;
            (CredentialBrokerTarget::Migration { migration_id: metadata.migration_id(), phase: metadata.phase() }, Some(metadata.binding_digest()))
        }
    };
    CredentialBrokerCommand::new(operation.operation_id(), attempt, operation.provider().clone(), operation.action(), target, operation.lifecycle_revision(), operation.fence(), binding)
        .map_err(|_| CredentialLifecycleError::CorruptState)
}
