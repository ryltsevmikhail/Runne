use runne_provider::{CredentialLifecycleError, CredentialOperationSnapshot, CredentialVersionRef};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::rows::{load_head, map_sql};

pub(super) fn prepared(
    store: &super::SqliteProviderCredentialLifecycleStore,
    owner: runne_provider::CredentialInstallationOwnerId,
    provider: &runne_provider::ProviderId,
) -> Result<Vec<CredentialOperationSnapshot>, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection.transaction().map_err(map_sql)?;
    let ids = transaction
        .prepare(
            "SELECT operation_id FROM provider_credential_operations
         WHERE installation_owner_id=?1 AND provider_id=?2 AND state='PREPARED'
           AND action IN ('REVOKE', 'RETIRED_VERSION_CLEANUP', 'LEGACY_SOURCE_CLEANUP')
         ORDER BY created_at, operation_id LIMIT 65",
        )
        .map_err(map_sql)?
        .query_map(
            params![owner.as_bytes().as_slice(), provider.as_str()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(map_sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql)?;
    if ids.len() > 64 {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let snapshots = ids
        .into_iter()
        .map(|id| {
            let id = runne_provider::CredentialOperationId::from_bytes(
                id.try_into()
                    .map_err(|_| CredentialLifecycleError::CorruptState)?,
            )
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
            super::rows::snapshot(&transaction, id, &store.enrollment_authority)
        })
        .collect::<Result<Vec<_>, _>>()?;
    transaction.commit().map_err(map_sql)?;
    Ok(snapshots)
}

/// Called only inside the successful rotation cutover transaction.
pub(super) fn create(
    transaction: &Transaction<'_>,
    parent: &CredentialOperationSnapshot,
    retired: &CredentialVersionRef,
    now: i64,
) -> Result<(), CredentialLifecycleError> {
    let head =
        load_head(transaction, parent.provider())?.ok_or(CredentialLifecycleError::CorruptState)?;
    let tuple = parent
        .metadata()
        .qualified_release_tuple_digest()
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let now = now.max(head.observed_at);
    if now < 0 || retired.provider() != parent.provider() {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let operation = binding(b"RUNNE_RETIRED_CLEANUP_OPERATION_V1\0", parent, retired);
    let command = binding(b"RUNNE_RETIRED_CLEANUP_COMMAND_V1\0", parent, retired);
    let proof = binding(b"RUNNE_RETIRED_CLEANUP_PROOF_V1\0", parent, retired);
    let key = format!("retired-cleanup-{}", hex(&operation[..16]));
    transaction
        .execute(
            "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id,
          idempotency_key, expected_lifecycle_revision, expected_credential_fence,
          target_credential_version, target_ref_digest, state, begin_proof_digest,
          begin_proof_expires_at_high_water, qualified_release_tuple_digest,
          created_at, updated_at)
         VALUES (?1, ?2, ?3, 'RETIRED_VERSION_CLEANUP', ?4, ?5, ?6, ?7,
                 ?8, ?9, 'PREPARED', ?10, ?11, ?12, ?13, ?13)",
            params![
                &operation[..16],
                parent.installation_owner_id().as_bytes().as_slice(),
                parent.provider().as_str(),
                &command[..16],
                key,
                head.lifecycle,
                head.fence,
                retired.version(),
                retired.ref_digest().as_slice(),
                proof.as_slice(),
                i64::MAX,
                tuple.as_bytes().as_slice(),
                now,
            ],
        )
        .map_err(map_sql)?;
    Ok(())
}

pub(super) fn supersede_prepared(
    transaction: &Transaction<'_>,
    provider: &runne_provider::ProviderId,
    now: i64,
) -> Result<(), CredentialLifecycleError> {
    let operation: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT operation_id FROM provider_credential_operations
             WHERE provider_id=?1 AND action='RETIRED_VERSION_CLEANUP' AND state='PREPARED'",
            [provider.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    let Some(operation) = operation else {
        return Ok(());
    };
    transaction
        .execute(
            "UPDATE provider_credential_ticket_attempts SET state='EXPIRED'
             WHERE operation_id=?1 AND state='ISSUED'",
            [operation.as_slice()],
        )
        .map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_ticket_attempts
             SET state='TOMBSTONED', terminal_digest=ticket_digest
             WHERE operation_id=?1 AND state='EXPIRED'",
            [operation.as_slice()],
        )
        .map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_process_attachments
             SET state='TOMBSTONED', terminal_digest=continuation_binding_digest
             WHERE operation_id=?1 AND state='ATTACHED'",
            [operation.as_slice()],
        )
        .map_err(map_sql)?;
    let changed = transaction
        .execute(
            "UPDATE provider_credential_operations
             SET state='CANCELLED', terminal_disposition='CANCELLED', updated_at=?1
             WHERE operation_id=?2 AND state='PREPARED'",
            params![now, operation],
        )
        .map_err(map_sql)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(CredentialLifecycleError::Conflict)
    }
}

pub(super) fn ensure_revoke_overlap_safe(
    transaction: &Transaction<'_>,
    provider: &runne_provider::ProviderId,
) -> Result<(), CredentialLifecycleError> {
    let state: Option<String> = transaction
        .query_row(
            "SELECT state FROM provider_credential_operations
             WHERE provider_id=?1 AND action='RETIRED_VERSION_CLEANUP'
               AND state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED')",
            [provider.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    match state.as_deref() {
        None | Some("CLAIMED" | "NATIVE_EFFECT_OBSERVED") => Ok(()),
        Some(_) => Err(CredentialLifecycleError::Conflict),
    }
}

pub(super) fn create_next(
    transaction: &Transaction<'_>,
    parent: &CredentialOperationSnapshot,
    now: i64,
) -> Result<(), CredentialLifecycleError> {
    let pending: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_credential_operations
             WHERE provider_id=?1 AND action='RETIRED_VERSION_CLEANUP'
               AND state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED'))",
            [parent.provider().as_str()],
            |row| row.get(0),
        )
        .map_err(map_sql)?;
    if pending {
        return Ok(());
    }
    let retired: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT credential_version, ref_digest FROM provider_credential_versions
             WHERE provider_id=?1 AND lifecycle_state='RETIRED'
             ORDER BY credential_version LIMIT 1",
            [parent.provider().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(map_sql)?;
    let Some((version, digest)) = retired else {
        return Ok(());
    };
    let version = u64::try_from(version).map_err(|_| CredentialLifecycleError::CorruptState)?;
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let retired = CredentialVersionRef::new(parent.provider().clone(), version)
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
    if retired.ref_digest() != &digest {
        return Err(CredentialLifecycleError::CorruptState);
    }
    create(transaction, parent, &retired, now)
}

pub(super) fn revoke_advanced_head(
    transaction: &Transaction<'_>,
    operation: &CredentialOperationSnapshot,
    head: &super::rows::Head,
) -> Result<bool, CredentialLifecycleError> {
    let expected_lifecycle = i64::try_from(operation.lifecycle_revision().get())
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let expected_fence =
        i64::try_from(operation.fence().get()).map_err(|_| CredentialLifecycleError::CorruptState)?;
    let advanced = head.lifecycle == expected_lifecycle + 1
        && head.fence == expected_fence + 1
        && head.active.is_none()
        && !head.hard_fenced;
    if !advanced {
        return Ok(false);
    }
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_credential_operations
             WHERE provider_id=?1 AND action='REVOKE'
               AND state NOT IN ('EXPIRED', 'CANCELLED', 'TOMBSTONED')
               AND expected_lifecycle_revision=?2 AND expected_credential_fence=?3)",
            params![operation.provider().as_str(), expected_lifecycle, expected_fence],
            |row| row.get(0),
        )
        .map_err(map_sql)
}

pub(super) fn revoke_in_progress(
    transaction: &Transaction<'_>,
    provider: &runne_provider::ProviderId,
) -> Result<bool, CredentialLifecycleError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_credential_operations
             WHERE provider_id=?1 AND action='REVOKE'
               AND state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED'))",
            [provider.as_str()],
            |row| row.get(0),
        )
        .map_err(map_sql)
}

fn binding(
    domain: &[u8],
    parent: &CredentialOperationSnapshot,
    retired: &CredentialVersionRef,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(parent.operation_id().as_bytes());
    hash.update(parent.installation_owner_id().as_bytes());
    hash.update(retired.ref_digest());
    hash.finalize().into()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
