use runne_provider::{
    BeginCredentialOperation, CredentialLifecycleError, CredentialLifecycleSnapshot,
    CredentialOperationAction, CredentialOperationSnapshot,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{action_sql, ensure_head, map_sql, snapshot};

pub(super) fn admission_snapshot(
    store: &SqliteProviderCredentialLifecycleStore,
    provider: &runne_provider::ProviderId,
) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let head = ensure_head(&transaction, provider)?;
    let snapshot = CredentialLifecycleSnapshot::new(
        provider.clone(),
        head.active,
        super::rows::revision(head.lifecycle)?,
        super::rows::fence(head.fence)?,
        super::rows::readiness(head.readiness)?,
        u64::try_from(head.next_version).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)?;
    transaction.commit().map_err(map_sql)?;
    Ok(snapshot)
}

pub(super) fn begin(
    store: &SqliteProviderCredentialLifecycleStore,
    input: BeginCredentialOperation,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    if input.action() == CredentialOperationAction::MigrateLegacy {
        return Err(CredentialLifecycleError::LifecycleClosed);
    }
    let now = (store.now)();
    if now < 0 {
        return Err(CredentialLifecycleError::InvalidInput);
    }
    let head = ensure_head(&transaction, input.provider_id())?;
    match snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    ) {
        Ok(existing) => {
            if exact_replay(&existing, &input) {
                transaction.commit().map_err(map_sql)?;
                return Ok(existing);
            }
            return Err(CredentialLifecycleError::Conflict);
        }
        Err(CredentialLifecycleError::NotFound) => {}
        Err(error) => return Err(error),
    }
    if head.hard_fenced
        || head.lifecycle != input.expected_lifecycle_revision().get() as i64
        || head.fence != input.expected_prior_fence().get() as i64
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let duplicate: Option<i64> = transaction.query_row("SELECT 1 FROM provider_credential_operations WHERE command_id=?1 OR idempotency_key=?2 OR begin_proof_digest=?3", params![input.command_id().as_bytes().as_slice(), input.idempotency_key().as_str(), input.begin_proof_digest().as_bytes().as_slice()], |row| row.get(0)).optional().map_err(map_sql)?;
    if duplicate.is_some() {
        return Err(CredentialLifecycleError::Conflict);
    }
    if let Some(version) = input.allocated_credential_version()
        && version.version()
            != u64::try_from(head.next_version)
                .map_err(|_| CredentialLifecycleError::CorruptState)?
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    transaction.execute(
        "INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, target_credential_version, target_ref_digest, state, begin_proof_digest, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'PREPARED', ?13, ?14, ?14)",
        params![input.operation_id().as_bytes().as_slice(), input.installation_owner_id().as_bytes().as_slice(), input.provider_id().as_str(), action_sql(input.action()), input.command_id().as_bytes().as_slice(), input.idempotency_key().as_str(), input.expected_lifecycle_revision().get(), input.expected_prior_fence().get(), input.allocated_credential_version().map(|v| v.version()), input.allocated_credential_version().map(|v| v.ref_digest().to_vec()), input.target_credential_version().map(|v| v.version()), input.target_credential_version().map(|v| v.ref_digest().to_vec()), input.begin_proof_digest().as_bytes().as_slice(), now],
    ).map_err(map_sql)?;
    match input.action() {
        CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => {
            transaction.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water=?1 WHERE provider_id=?2 AND observed_at_high_water<=?1", params![now, input.provider_id().as_str()]).map_err(map_sql)?;
        }
        CredentialOperationAction::Revoke => {
            let changed = transaction.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision=lifecycle_revision+1, credential_fence=credential_fence+1, readiness_revision=readiness_revision+1, active_credential_version=NULL, active_ref_digest=NULL, observed_at_high_water=?1 WHERE provider_id=?2 AND lifecycle_revision=?3 AND credential_fence=?4", params![now, input.provider_id().as_str(), input.expected_lifecycle_revision().get(), input.expected_prior_fence().get()]).map_err(map_sql)?;
            if changed != 1 {
                return Err(CredentialLifecycleError::Conflict);
            }
        }
        _ => return Err(CredentialLifecycleError::InvalidInput),
    };
    let result = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    transaction.commit().map_err(map_sql)?;
    Ok(result)
}

fn exact_replay(existing: &CredentialOperationSnapshot, input: &BeginCredentialOperation) -> bool {
    existing.provider() == input.provider_id()
        && existing.installation_owner_id() == input.installation_owner_id()
        && existing.action() == input.action()
        && existing.allocated_credential_version() == input.allocated_credential_version()
        && existing.target_credential_version() == input.target_credential_version()
        && existing.lifecycle_revision() == input.expected_lifecycle_revision()
        && existing.fence() == input.expected_prior_fence()
        && existing.begin_proof_digest() == input.begin_proof_digest()
        && existing.metadata().command_id() == input.command_id()
        && existing.metadata().idempotency_key() == input.idempotency_key()
}
