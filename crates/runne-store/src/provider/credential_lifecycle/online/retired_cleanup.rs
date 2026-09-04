use runne_provider::{CredentialLifecycleError, CredentialOperationSnapshot, CredentialVersionRef};
use rusqlite::{Transaction, params};
use sha2::{Digest, Sha256};

use super::rows::{load_head, map_sql};

pub(super) fn prepared(
    store: &super::SqliteProviderCredentialLifecycleStore,
    owner: runne_provider::CredentialInstallationOwnerId,
    provider: &runne_provider::ProviderId,
) -> Result<Vec<CredentialOperationSnapshot>, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection.transaction().map_err(map_sql)?;
    let ids = transaction.prepare(
        "SELECT operation_id FROM provider_credential_operations
         WHERE installation_owner_id=?1 AND provider_id=?2 AND state='PREPARED'
           AND action IN ('REVOKE', 'RETIRED_VERSION_CLEANUP', 'LEGACY_SOURCE_CLEANUP')
         ORDER BY created_at, operation_id LIMIT 65",
    ).map_err(map_sql)?.query_map(
        params![owner.as_bytes().as_slice(), provider.as_str()],
        |row| row.get::<_, Vec<u8>>(0),
    ).map_err(map_sql)?.collect::<Result<Vec<_>, _>>().map_err(map_sql)?;
    if ids.len() > 64 {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let snapshots = ids.into_iter().map(|id| {
        let id = runne_provider::CredentialOperationId::from_bytes(
            id.try_into().map_err(|_| CredentialLifecycleError::CorruptState)?,
        ).map_err(|_| CredentialLifecycleError::CorruptState)?;
        super::rows::snapshot(&transaction, id, &store.enrollment_authority)
    }).collect::<Result<Vec<_>, _>>()?;
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
    let head = load_head(transaction, parent.provider())?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let tuple = parent.metadata().qualified_release_tuple_digest()
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let now = now.max(head.observed_at);
    if now < 0 || retired.provider() != parent.provider() {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let operation = binding(b"RUNNE_RETIRED_CLEANUP_OPERATION_V1\0", parent, retired);
    let command = binding(b"RUNNE_RETIRED_CLEANUP_COMMAND_V1\0", parent, retired);
    let proof = binding(b"RUNNE_RETIRED_CLEANUP_PROOF_V1\0", parent, retired);
    let key = format!("retired-cleanup-{}", hex(&operation[..16]));
    transaction.execute(
        "INSERT INTO provider_credential_operations
         (operation_id, installation_owner_id, provider_id, action, command_id,
          idempotency_key, expected_lifecycle_revision, expected_credential_fence,
          target_credential_version, target_ref_digest, state, begin_proof_digest,
          begin_proof_expires_at_high_water, qualified_release_tuple_digest,
          created_at, updated_at)
         VALUES (?1, ?2, ?3, 'RETIRED_VERSION_CLEANUP', ?4, ?5, ?6, ?7,
                 ?8, ?9, 'PREPARED', ?10, ?11, ?12, ?13, ?13)",
        params![
            &operation[..16], parent.installation_owner_id().as_bytes().as_slice(),
            parent.provider().as_str(), &command[..16], key, head.lifecycle, head.fence,
            retired.version(), retired.ref_digest().as_slice(), proof.as_slice(),
            i64::MAX, tuple.as_bytes().as_slice(), now,
        ],
    ).map_err(map_sql)?;
    Ok(())
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
