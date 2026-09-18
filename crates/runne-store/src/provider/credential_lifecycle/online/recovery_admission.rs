use runne_provider::{
    AcceptedCredentialCleanupRecovery, CredentialCleanupRecoveryRequest, CredentialLifecycleError,
    CredentialOperationAction, CredentialOperationState,
};
use rusqlite::{OptionalExtension as _, TransactionBehavior, params};

use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{load_head, map_sql, snapshot};

pub(super) fn expired_attempt(
    store: &SqliteProviderCredentialLifecycleStore,
    owner: runne_provider::CredentialInstallationOwnerId,
    id: runne_provider::CredentialOperationId,
) -> Result<Option<u64>, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection.transaction().map_err(map_sql)?;
    let operation = snapshot(&transaction, id, &store.enrollment_authority)?;
    if operation.installation_owner_id() != owner {
        return Err(CredentialLifecycleError::Conflict);
    }
    if operation.state() != CredentialOperationState::Prepared
        || !matches!(
            operation.action(),
            CredentialOperationAction::Revoke
                | CredentialOperationAction::RetiredVersionCleanup
                | CredentialOperationAction::LegacySourceCleanup
        )
    {
        return Ok(None);
    }
    let head = load_head(&transaction, operation.provider())?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let now = head.observed_at.max((store.now)());
    let attempt: Option<i64> = transaction.query_row(
        "SELECT attempt FROM credential_cleanup_recovery_attempts
         WHERE operation_id=?1 AND state='ACCEPTED' AND expires_at<=?2
           AND attempt=(SELECT MAX(attempt) FROM credential_cleanup_recovery_attempts WHERE operation_id=?1)
           AND NOT EXISTS(SELECT 1 FROM provider_credential_ticket_attempts WHERE operation_id=?1 AND state='CLAIMED')",
        params![id.as_bytes().as_slice(), now], |row| row.get(0),
    ).optional().map_err(map_sql)?;
    transaction.commit().map_err(map_sql)?;
    attempt
        .map(|value| {
            u64::try_from(value)
                .ok()
                .filter(|v| *v > 0)
                .ok_or(CredentialLifecycleError::CorruptState)
        })
        .transpose()
}

pub(super) fn accept(
    store: &SqliteProviderCredentialLifecycleStore,
    request: CredentialCleanupRecoveryRequest,
) -> Result<AcceptedCredentialCleanupRecovery, CredentialLifecycleError> {
    admit(store, request, None)
}

pub(super) fn supersede(
    store: &SqliteProviderCredentialLifecycleStore,
    request: CredentialCleanupRecoveryRequest,
    expected_attempt: u64,
) -> Result<AcceptedCredentialCleanupRecovery, CredentialLifecycleError> {
    let expected = i64::try_from(expected_attempt)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(CredentialLifecycleError::InvalidInput)?;
    admit(store, request, Some(expected))
}

fn admit(
    store: &SqliteProviderCredentialLifecycleStore,
    request: CredentialCleanupRecoveryRequest,
    superseded_attempt: Option<i64>,
) -> Result<AcceptedCredentialCleanupRecovery, CredentialLifecycleError> {
    store
        .enrollment_authority
        .validate_cleanup_recovery_request(&request)
        .map_err(|_| CredentialLifecycleError::InvalidInput)?;
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        request.operation_id(),
        &store.enrollment_authority,
    )?;
    if operation.state() != CredentialOperationState::Prepared
        || !matches!(
            operation.action(),
            CredentialOperationAction::Revoke
                | CredentialOperationAction::RetiredVersionCleanup
                | CredentialOperationAction::LegacySourceCleanup
        )
        || operation.installation_owner_id() != request.owner()
        || operation.metadata().qualified_release_tuple_digest() != Some(request.release_digest())
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let head = load_head(&transaction, operation.provider())?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    if !super::claim::claim_head_matches(&operation, &head)?
        || head.lifecycle != request.lifecycle_revision().get() as i64
        || head.fence != request.credential_fence().get() as i64
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let prohibited: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_credential_ticket_attempts
            WHERE operation_id=?1 AND state='CLAIMED')
         OR EXISTS(SELECT 1 FROM credential_cleanup_recovery_attempts WHERE continuation_digest=?2)
         OR EXISTS(SELECT 1 FROM provider_credential_process_attachments WHERE continuation_binding_digest=?2)
         OR EXISTS(SELECT 1 FROM provider_credential_ticket_attempts WHERE continuation_binding_digest=?2)",
        params![request.operation_id().as_bytes().as_slice(), request.continuation_digest().as_bytes().as_slice()],
        |row| row.get(0),
    ).map_err(map_sql)?;
    if prohibited {
        return Err(CredentialLifecycleError::Conflict);
    }
    let issued_at = head.observed_at.max((store.now)());
    if issued_at < 0 {
        return Err(CredentialLifecycleError::InvalidInput);
    }
    let expires_at = issued_at
        .checked_add(request.ttl_seconds() as i64)
        .ok_or(CredentialLifecycleError::InvalidInput)?;
    let previous: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(attempt), 0) FROM credential_cleanup_recovery_attempts WHERE operation_id=?1",
        [request.operation_id().as_bytes().as_slice()], |row| row.get(0),
    ).map_err(map_sql)?;
    let attempt = previous
        .checked_add(1)
        .filter(|v| *v > 0)
        .ok_or(CredentialLifecycleError::CorruptState)?;

    if let Some(expected) = superseded_attempt {
        if previous != expected {
            return Err(CredentialLifecycleError::Conflict);
        }
        let changed = transaction
            .execute(
                "UPDATE credential_cleanup_recovery_attempts
             SET state='SUPERSEDED', terminal_digest=continuation_digest
             WHERE operation_id=?1 AND attempt=?2 AND state='ACCEPTED' AND expires_at<=?3",
                params![
                    request.operation_id().as_bytes().as_slice(),
                    expected,
                    issued_at
                ],
            )
            .map_err(map_sql)?;
        if changed != 1 {
            return Err(CredentialLifecycleError::Conflict);
        }
    } else {
        let live: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM credential_cleanup_recovery_attempts
             WHERE operation_id=?1 AND state='ACCEPTED')",
                [request.operation_id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(map_sql)?;
        if live {
            return Err(CredentialLifecycleError::Conflict);
        }
    }

    // These updates and the admission insert share the claim CAS's write lock.
    // An old claim either committed already (rejected above), or loses forever.
    transaction
        .execute(
            "UPDATE provider_credential_ticket_attempts SET state='EXPIRED'
         WHERE operation_id=?1 AND state='ISSUED'",
            [request.operation_id().as_bytes().as_slice()],
        )
        .map_err(map_sql)?;
    transaction.execute(
        "UPDATE provider_credential_ticket_attempts SET state='TOMBSTONED', terminal_digest=ticket_digest
         WHERE operation_id=?1 AND state='EXPIRED'",
        [request.operation_id().as_bytes().as_slice()],
    ).map_err(map_sql)?;
    transaction.execute(
        "UPDATE provider_credential_process_attachments SET state='TOMBSTONED', terminal_digest=continuation_binding_digest
         WHERE operation_id=?1 AND state='ATTACHED'",
        [request.operation_id().as_bytes().as_slice()],
    ).map_err(map_sql)?;
    transaction.execute(
        "INSERT INTO credential_cleanup_recovery_attempts
         (operation_id, attempt, installation_owner_id, release_tuple_digest, protected_session_digest,
          database_generation, supervisor_generation, lifecycle_revision, credential_fence,
          continuation_digest, issued_at, expires_at, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'ACCEPTED')",
        params![request.operation_id().as_bytes().as_slice(), attempt, request.owner().as_bytes().as_slice(),
            request.release_digest().as_bytes().as_slice(), request.session_digest().as_bytes().as_slice(),
            request.database_generation(), request.supervisor_generation(), head.lifecycle, head.fence,
            request.continuation_digest().as_bytes().as_slice(), issued_at, expires_at],
    ).map_err(map_sql)?;
    transaction.execute(
        "UPDATE provider_credential_authority_heads SET observed_at_high_water=?1 WHERE provider_id=?2",
        params![issued_at, operation.provider().as_str()],
    ).map_err(map_sql)?;
    transaction.commit().map_err(map_sql)?;
    store
        .enrollment_authority
        .issue_cleanup_recovery(request, operation, attempt as u64, issued_at, expires_at)
        .map_err(|_| CredentialLifecycleError::CorruptState)
}
