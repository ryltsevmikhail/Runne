use runne_provider::{
    BeginCredentialOperation, BeginCredentialOperationOutcome, CredentialLifecycleError,
    CredentialLifecycleSnapshot, CredentialOperationAction, CredentialOperationSnapshot,
    WriterIdentityMigrationPhase,
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
) -> Result<BeginCredentialOperationOutcome, CredentialLifecycleError> {
    begin_with_legacy_allowed(store, input, false)
}

#[cfg(test)]
pub(super) fn begin_legacy_for_test(
    store: &SqliteProviderCredentialLifecycleStore,
    input: BeginCredentialOperation,
) -> Result<BeginCredentialOperationOutcome, CredentialLifecycleError> {
    begin_with_legacy_allowed(store, input, true)
}

fn begin_with_legacy_allowed(
    store: &SqliteProviderCredentialLifecycleStore,
    input: BeginCredentialOperation,
    legacy_allowed: bool,
) -> Result<BeginCredentialOperationOutcome, CredentialLifecycleError> {
    let qualified_release_tuple = input
        .qualified_release_tuple()
        .ok_or(CredentialLifecycleError::Conflict)?;
    let migration = input.migration();
    let is_migration = matches!(
        input.action(),
        CredentialOperationAction::WriterIdentityMigrationEffect
            | CredentialOperationAction::WriterIdentityMigrationVerify
    );
    if is_migration != migration.is_some()
        || migration.is_some_and(|value| {
            store
                .enrollment_authority
                .validate_credential_migration_metadata(value)
                .is_err()
        })
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    if input.action() == CredentialOperationAction::MigrateLegacy && !legacy_allowed {
        return Err(CredentialLifecycleError::LifecycleClosed);
    }
    let now = (store.now)();
    if now < 0 {
        return Err(CredentialLifecycleError::InvalidInput);
    }
    let head = ensure_head(&transaction, input.provider_id())?;
    let replay_id: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT operation_id FROM provider_credential_operations WHERE begin_proof_digest=?1",
            [input.begin_proof_digest().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    if let Some(replay_id) = replay_id {
        let operation = runne_provider::CredentialOperationId::from_bytes(
            replay_id
                .try_into()
                .map_err(|_| CredentialLifecycleError::CorruptState)?,
        )
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
        if input.operation_id() != operation {
            let occupied: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM provider_credential_operations WHERE operation_id=?1)",
                    [input.operation_id().as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .map_err(map_sql)?;
            if occupied {
                return Err(CredentialLifecycleError::Conflict);
            }
        }
        let expiry: i64 = transaction.query_row(
            "SELECT begin_proof_expires_at_high_water FROM provider_credential_operations WHERE operation_id=?1",
            [operation.as_bytes().as_slice()],
            |row| row.get(0),
        ).map_err(map_sql)?;
        let existing = snapshot(&transaction, operation, &store.enrollment_authority)?;
        if exact_replay(&existing, expiry, &input) {
            transaction.commit().map_err(map_sql)?;
            return Ok(BeginCredentialOperationOutcome::ExactReplay(existing));
        }
        return Err(CredentialLifecycleError::Conflict);
    }
    let expiry = i64::try_from(input.begin_proof_expires_at_high_water())
        .map_err(|_| CredentialLifecycleError::InvalidInput)?;
    if expiry <= 0 {
        return Err(CredentialLifecycleError::InvalidInput);
    }
    let effective_now = now.max(head.observed_at);
    if effective_now >= expiry {
        transaction.execute(
            "UPDATE provider_credential_authority_heads SET observed_at_high_water=?1 WHERE provider_id=?2 AND observed_at_high_water<=?1",
            params![effective_now, input.provider_id().as_str()],
        ).map_err(map_sql)?;
        transaction.commit().map_err(map_sql)?;
        return Err(CredentialLifecycleError::StaleLease);
    }
    if head.hard_fenced
        || head.lifecycle != input.expected_lifecycle_revision().get() as i64
        || head.fence != input.expected_prior_fence().get() as i64
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let duplicate: Option<i64> = transaction.query_row("SELECT 1 FROM provider_credential_operations WHERE operation_id=?1 OR command_id=?2 OR idempotency_key=?3", params![input.operation_id().as_bytes().as_slice(), input.command_id().as_bytes().as_slice(), input.idempotency_key().as_str()], |row| row.get(0)).optional().map_err(map_sql)?;
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
        "INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, target_credential_version, target_ref_digest, state, begin_proof_digest, begin_proof_expires_at_high_water, migration_id, migration_phase, migration_old_tuple_digest, migration_new_tuple_digest, broker_migration_binding_digest, qualified_release_tuple_digest, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'PREPARED', ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?21)",
        params![input.operation_id().as_bytes().as_slice(), input.installation_owner_id().as_bytes().as_slice(), input.provider_id().as_str(), action_sql(input.action()), input.command_id().as_bytes().as_slice(), input.idempotency_key().as_str(), input.expected_lifecycle_revision().get(), input.expected_prior_fence().get(), input.allocated_credential_version().map(|v| v.version()), input.allocated_credential_version().map(|v| v.ref_digest().to_vec()), input.target_credential_version().map(|v| v.version()), input.target_credential_version().map(|v| v.ref_digest().to_vec()), input.begin_proof_digest().as_bytes().as_slice(), expiry, migration.map(|v| v.migration_id().as_bytes().to_vec()), migration.map(|v| match v.phase() { WriterIdentityMigrationPhase::OldWriterEffect => "EFFECT", WriterIdentityMigrationPhase::NewWriterVerify => "VERIFY" }), migration.map(|v| v.old_tuple_digest().as_bytes().to_vec()), migration.map(|v| v.new_tuple_digest().as_bytes().to_vec()), migration.map(|v| v.binding_digest().as_bytes().to_vec()), qualified_release_tuple.digest().as_bytes().to_vec(), effective_now],
    ).map_err(map_sql)?;
    match input.action() {
        CredentialOperationAction::Pair
        | CredentialOperationAction::MigrateLegacy
        | CredentialOperationAction::WriterIdentityMigrationEffect
        | CredentialOperationAction::WriterIdentityMigrationVerify
        | CredentialOperationAction::LegacySourceCleanup => {
            transaction.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water=?1 WHERE provider_id=?2 AND observed_at_high_water<=?1", params![effective_now, input.provider_id().as_str()]).map_err(map_sql)?;
        }
        CredentialOperationAction::Revoke => {
            let changed = transaction.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision=lifecycle_revision+1, credential_fence=credential_fence+1, readiness_revision=readiness_revision+1, active_credential_version=NULL, active_ref_digest=NULL, observed_at_high_water=?1 WHERE provider_id=?2 AND lifecycle_revision=?3 AND credential_fence=?4", params![effective_now, input.provider_id().as_str(), input.expected_lifecycle_revision().get(), input.expected_prior_fence().get()]).map_err(map_sql)?;
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
    Ok(BeginCredentialOperationOutcome::FreshWinner(result))
}

pub(super) fn find_by_begin_proof(
    store: &SqliteProviderCredentialLifecycleStore,
    proof: runne_provider::CredentialBindingDigest,
) -> Result<Option<CredentialOperationSnapshot>, CredentialLifecycleError> {
    let connection = store.connection.lock().map_err(super::map_lock)?;
    let operation_id: Option<Vec<u8>> = connection
        .query_row(
            "SELECT operation_id FROM provider_credential_operations WHERE begin_proof_digest=?1",
            [proof.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    operation_id
        .map(|bytes| {
            let operation = runne_provider::CredentialOperationId::from_bytes(
                bytes
                    .try_into()
                    .map_err(|_| CredentialLifecycleError::CorruptState)?,
            )
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
            snapshot(&connection, operation, &store.enrollment_authority)
        })
        .transpose()
}

fn exact_replay(
    existing: &CredentialOperationSnapshot,
    expiry: i64,
    input: &BeginCredentialOperation,
) -> bool {
    existing.provider() == input.provider_id()
        && existing.installation_owner_id() == input.installation_owner_id()
        && existing.action() == input.action()
        && existing.allocated_credential_version() == input.allocated_credential_version()
        && existing.target_credential_version() == input.target_credential_version()
        && existing.lifecycle_revision() == input.expected_lifecycle_revision()
        && existing.fence() == input.expected_prior_fence()
        && existing.begin_proof_digest() == input.begin_proof_digest()
        && u64::try_from(expiry).ok() == Some(input.begin_proof_expires_at_high_water())
        && existing.metadata().command_id() == input.command_id()
        && existing.metadata().idempotency_key() == input.idempotency_key()
        && existing.metadata().migration() == input.migration()
        && existing.metadata().qualified_release_tuple_digest()
            == input.qualified_release_tuple().map(|tuple| tuple.digest())
}
