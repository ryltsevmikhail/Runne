use super::rows::map_sql;
use runne_provider::{
    AcceptedCredentialCleanupRecovery, CredentialLifecycleError, CredentialOperationSnapshot,
};
use rusqlite::{Transaction, params};

pub(super) fn deadline(
    transaction: &Transaction<'_>,
    operation: &CredentialOperationSnapshot,
    accepted: Option<&AcceptedCredentialCleanupRecovery>,
) -> Result<Option<i64>, CredentialLifecycleError> {
    let Some(accepted) = accepted else {
        let recovery: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM credential_cleanup_recovery_attempts WHERE operation_id=?1)",
            [operation.operation_id().as_bytes().as_slice()], |row| row.get(0),
        ).map_err(map_sql)?;
        return if recovery {
            Err(CredentialLifecycleError::Conflict)
        } else {
            Ok(None)
        };
    };
    if accepted.operation() != operation {
        return Err(CredentialLifecycleError::Conflict);
    }
    let request = accepted.request();
    let current: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM credential_cleanup_recovery_attempts
         WHERE operation_id=?1 AND attempt=?2 AND continuation_digest=?3 AND state='ACCEPTED'
          AND installation_owner_id=?4 AND release_tuple_digest=?5 AND protected_session_digest=?6
          AND database_generation=?7 AND supervisor_generation=?8 AND lifecycle_revision=?9
          AND credential_fence=?10 AND issued_at=?11 AND expires_at=?12)
         AND NOT EXISTS(SELECT 1 FROM provider_credential_process_attachments
                        WHERE operation_id=?1 AND state='ATTACHED')",
            params![
                request.operation_id().as_bytes().as_slice(),
                accepted.attempt(),
                request.continuation_digest().as_bytes().as_slice(),
                request.owner().as_bytes().as_slice(),
                request.release_digest().as_bytes().as_slice(),
                request.session_digest().as_bytes().as_slice(),
                request.database_generation(),
                request.supervisor_generation(),
                request.lifecycle_revision().get(),
                request.credential_fence().get(),
                accepted.issued_at(),
                accepted.expires_at()
            ],
            |row| row.get(0),
        )
        .map_err(map_sql)?;
    if !current {
        return Err(CredentialLifecycleError::Conflict);
    }
    Ok(Some(accepted.expires_at()))
}
