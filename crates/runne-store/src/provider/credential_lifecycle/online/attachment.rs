use runne_provider::{
    AttachCredentialProcess, CredentialLifecycleError, CredentialOperationSnapshot,
    CredentialOperationState,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::SqliteProviderCredentialLifecycleStore;
use super::claim::claim_head_matches;
use super::rows::{load_head, map_sql, snapshot};

/// Persists exactly one protected writer continuation before ticket issuance.
pub(super) fn attach(
    store: &SqliteProviderCredentialLifecycleStore,
    input: AttachCredentialProcess,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    attach_inner(store, input, None)
}

pub(super) fn attach_recovery(
    store: &SqliteProviderCredentialLifecycleStore,
    accepted: runne_provider::AcceptedCredentialCleanupRecovery,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    store.enrollment_authority.validate_cleanup_recovery(&accepted)
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    let input = AttachCredentialProcess::new(
        accepted.request().operation_id(), accepted.request().continuation_digest(),
    ).map_err(|_| CredentialLifecycleError::InvalidInput)?;
    attach_inner(store, input, Some(accepted))
}

fn attach_inner(
    store: &SqliteProviderCredentialLifecycleStore,
    input: AttachCredentialProcess,
    accepted: Option<runne_provider::AcceptedCredentialCleanupRecovery>,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    if operation.state() != CredentialOperationState::Prepared {
        return Err(CredentialLifecycleError::LifecycleClosed);
    }
    let retired_continuation: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_credential_process_attachments
         WHERE operation_id=?1 AND continuation_binding_digest=?2 AND state='TOMBSTONED')",
        params![input.operation_id().as_bytes().as_slice(), input.continuation_binding_digest().as_bytes().as_slice()],
        |row| row.get(0),
    ).map_err(map_sql)?;
    if retired_continuation {
        return Err(CredentialLifecycleError::Conflict);
    }
    let head = load_head(&transaction, operation.provider())?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    if !claim_head_matches(&operation, &head)? {
        return Err(CredentialLifecycleError::Conflict);
    }
    let now = head.observed_at.max((store.now)());
    let recovery_expiry = super::recovery_attachment::deadline(&transaction, &operation, accepted.as_ref())?;
    let expires: i64 = if let Some(expires) = recovery_expiry { expires } else { transaction
        .query_row(
            "SELECT begin_proof_expires_at_high_water FROM provider_credential_operations WHERE operation_id=?1",
            [input.operation_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(map_sql)? };
    if expires <= now {
        transaction
            .execute(
                "UPDATE provider_credential_authority_heads SET observed_at_high_water=?1
                 WHERE provider_id=?2 AND observed_at_high_water<=?1",
                params![now, operation.provider().as_str()],
            )
            .map_err(map_sql)?;
        transaction.commit().map_err(map_sql)?;
        return Err(CredentialLifecycleError::StaleLease);
    }
    let existing: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT attachment_attempt, continuation_binding_digest
             FROM provider_credential_process_attachments
             WHERE operation_id=?1 AND state='ATTACHED'",
            [input.operation_id().as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(map_sql)?;
    if let Some((attempt, existing)) = existing {
        if existing == input.continuation_binding_digest().as_bytes() {
            transaction.commit().map_err(map_sql)?;
            return Ok(operation);
        }
        transaction.execute(
            "UPDATE provider_credential_ticket_attempts SET state='EXPIRED'
             WHERE operation_id=?1 AND state='ISSUED'",
            [input.operation_id().as_bytes().as_slice()],
        ).map_err(map_sql)?;
        transaction.execute(
            "UPDATE provider_credential_ticket_attempts SET state='TOMBSTONED', terminal_digest=ticket_digest
             WHERE operation_id=?1 AND state='EXPIRED'",
            [input.operation_id().as_bytes().as_slice()],
        ).map_err(map_sql)?;
        transaction.execute(
            "UPDATE provider_credential_process_attachments
             SET state='TOMBSTONED', terminal_digest=continuation_binding_digest
             WHERE operation_id=?1 AND attachment_attempt=?2 AND state='ATTACHED'",
            params![input.operation_id().as_bytes().as_slice(), attempt],
        ).map_err(map_sql)?;
    }
    let attempt: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(attachment_attempt), 0) + 1
         FROM provider_credential_process_attachments WHERE operation_id=?1",
        [input.operation_id().as_bytes().as_slice()],
        |row| row.get(0),
    ).map_err(map_sql)?;
    transaction
        .execute(
            "INSERT INTO provider_credential_process_attachments
             (operation_id, attachment_attempt, continuation_binding_digest, attached_at, state)
             VALUES (?1, ?2, ?3, ?4, 'ATTACHED')",
            params![
                input.operation_id().as_bytes().as_slice(),
                attempt,
                input.continuation_binding_digest().as_bytes().as_slice(),
                now,
            ],
        )
        .map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_authority_heads SET observed_at_high_water=?1
             WHERE provider_id=?2 AND observed_at_high_water<=?1",
            params![now, operation.provider().as_str()],
        )
        .map_err(map_sql)?;
    transaction.commit().map_err(map_sql)?;
    Ok(operation)
}
