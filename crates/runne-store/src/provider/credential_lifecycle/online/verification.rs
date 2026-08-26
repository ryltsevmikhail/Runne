use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{ensure_head, map_sql};
use runne_provider::{
    BeginCredentialVerification, CompleteCredentialVerification, CredentialLifecycleError,
    CredentialVerificationLease, CredentialVerificationObservation,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

pub(super) fn begin(
    store: &SqliteProviderCredentialLifecycleStore,
    input: BeginCredentialVerification,
) -> Result<CredentialVerificationLease, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let head = ensure_head(&transaction, input.provider())?;
    if head.hard_fenced
        || head.lifecycle != input.expected_lifecycle_revision().get() as i64
        || head.fence != input.expected_prior_fence().get() as i64
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let active = head.active.ok_or(CredentialLifecycleError::Conflict)?;
    if let Some(operation) = input.operation_id() {
        let count: i64 = transaction.query_row("SELECT COUNT(*) FROM provider_credential_operations WHERE operation_id=?1 AND provider_id=?2 AND state NOT IN ('TOMBSTONED', 'CANCELLED', 'EXPIRED')", params![operation.as_bytes().as_slice(), input.provider().as_str()], |row| row.get(0)).map_err(map_sql)?;
        if count != 1 {
            return Err(CredentialLifecycleError::Conflict);
        }
    }
    let duplicate: Option<i64> = transaction.query_row("SELECT 1 FROM provider_credential_verification_observations WHERE observation_id=?1 OR intent_proof_digest=?2", params![input.observation_id().as_bytes().as_slice(), input.intent_proof_digest().as_bytes().as_slice()], |row| row.get(0)).optional().map_err(map_sql)?;
    if duplicate.is_some() {
        return Err(CredentialLifecycleError::Conflict);
    }
    transaction.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water=?1 WHERE provider_id=?2 AND observed_at_high_water<=?1", params![input.started_at_high_water(), input.provider().as_str()]).map_err(map_sql)?;
    transaction.execute("INSERT INTO provider_credential_verification_observations (observation_id, provider_id, verification_kind, lifecycle_revision, credential_fence, active_credential_version, active_ref_digest, state, intent_proof_digest, proof_consumed, verifier_revision, started_at, expires_at_high_water, operation_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'LEASED', ?8, 1, ?9, ?10, ?11, ?12)", params![input.observation_id().as_bytes().as_slice(), input.provider().as_str(), kind(input.kind()), input.expected_lifecycle_revision().get(), input.expected_prior_fence().get(), active.version(), active.ref_digest().as_slice(), input.intent_proof_digest().as_bytes().as_slice(), input.verifier_revision().get(), input.started_at_high_water(), input.expires_at_high_water(), input.operation_id().map(|id| id.as_bytes().to_vec())]).map_err(map_sql)?;
    transaction.commit().map_err(map_sql)?;
    Ok(store
        .enrollment_authority
        .issue_credential_verification_lease(input, active))
}

pub(super) fn complete(
    store: &SqliteProviderCredentialLifecycleStore,
    input: CompleteCredentialVerification,
) -> Result<CredentialVerificationObservation, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let row: Option<(String, i64, i64, i64, Vec<u8>, i64)> = transaction.query_row("SELECT provider_id, lifecycle_revision, credential_fence, active_credential_version, active_ref_digest, expires_at_high_water FROM provider_credential_verification_observations WHERE observation_id=?1 AND state='LEASED'", [input.observation_id().as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))).optional().map_err(map_sql)?;
    let (provider, lifecycle, fence, active_version, active_digest, expires) =
        row.ok_or(CredentialLifecycleError::Conflict)?;
    if lifecycle != input.expected_lifecycle_revision().get() as i64
        || fence != input.expected_prior_fence().get() as i64
        || input.observation().observed_at_high_water() >= expires
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let provider = runne_provider::ProviderId::new(provider)
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let active = runne_provider::CredentialVersionRef::new(
        provider.clone(),
        u64::try_from(active_version).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )?;
    if active.ref_digest() != active_digest.as_slice() {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let head = ensure_head(&transaction, &provider)?;
    if head.hard_fenced
        || head.lifecycle != lifecycle
        || head.fence != fence
        || head.active.as_ref() != Some(&active)
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    transaction.execute("UPDATE provider_credential_authority_heads SET observed_at_high_water=?1 WHERE provider_id=?2 AND observed_at_high_water<=?1", params![input.observation().observed_at_high_water(), provider.as_str()]).map_err(map_sql)?;
    let changed = transaction.execute("UPDATE provider_credential_verification_observations SET state='COMPLETED', result=?1, observed_at=?2 WHERE observation_id=?3 AND state='LEASED'", params![result(input.observation().result()), input.observation().observed_at_high_water(), input.observation_id().as_bytes().as_slice()]).map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    transaction.commit().map_err(map_sql)?;
    Ok(input.observation().clone())
}
fn kind(value: runne_provider::CredentialVerificationKind) -> &'static str {
    match value {
        runne_provider::CredentialVerificationKind::Local => "LOCAL",
        runne_provider::CredentialVerificationKind::Remote => "REMOTE",
    }
}
fn result(value: runne_provider::CredentialVerificationResult) -> &'static str {
    match value {
        runne_provider::CredentialVerificationResult::Verified => "VERIFIED",
        runne_provider::CredentialVerificationResult::Failed => "FAILED",
        runne_provider::CredentialVerificationResult::Unsupported => "UNSUPPORTED",
        runne_provider::CredentialVerificationResult::Unavailable => "UNAVAILABLE",
        runne_provider::CredentialVerificationResult::AccessDenied => "ACCESS_DENIED",
        runne_provider::CredentialVerificationResult::Conflict => "CONFLICT",
    }
}
