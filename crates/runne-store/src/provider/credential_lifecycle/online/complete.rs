use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{ensure_head, fence, load_head, map_sql, readiness, snapshot};
use runne_provider::{
    CompleteCredentialOperation, CredentialCompletionReceipt, CredentialFence,
    CredentialLifecycleError, CredentialLifecycleSnapshot, CredentialOperationAction,
    CredentialOperationState,
    HardFenceProvider, ProviderId,
};
use rusqlite::{TransactionBehavior, params};
use sha2::{Digest, Sha256};

pub(super) fn complete(
    store: &SqliteProviderCredentialLifecycleStore,
    input: CompleteCredentialOperation,
) -> Result<CredentialCompletionReceipt, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    let legacy_source_cleanup = operation.action() == CredentialOperationAction::LegacySourceCleanup;
    if input.readiness_observation().is_none() != legacy_source_cleanup {
        return Err(CredentialLifecycleError::Conflict);
    }
    if operation.state() == CredentialOperationState::Completed {
        if operation.lifecycle_revision() != input.expected_lifecycle_revision()
            || operation.fence() != input.expected_prior_fence()
        {
            return Err(CredentialLifecycleError::Conflict);
        }
        let result = super::completion_receipt::load(
            &transaction,
            &operation,
            &input,
            &store.enrollment_authority,
        )?;
        transaction.commit().map_err(map_sql)?;
        return Ok(result);
    }
    if operation.state() != CredentialOperationState::ReadbackVerified
        || operation.lifecycle_revision() != input.expected_lifecycle_revision()
        || operation.fence() != input.expected_prior_fence()
        || operation.metadata().readback_observation_digest()
            != Some(input.readback().observation_digest())
        || operation.metadata().readback_disposition() != Some(input.readback().disposition())
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let command = store
        .enrollment_authority
        .issue_transition_command(
            operation.action(),
            CredentialOperationState::ReadbackVerified,
            CredentialOperationState::Completed,
            input.readback().evidence(),
        )
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    store
        .enrollment_authority
        .validate_transition_command(&command)
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    let head = ensure_head(&transaction, operation.provider())?;
    if operation.action() == CredentialOperationAction::MigrateLegacy {
        let result =
            super::legacy_cutover::complete(&transaction, store, &operation, &input, &head)?;
        transaction.commit().map_err(map_sql)?;
        return Ok(result);
    }
    match operation.action() {
        CredentialOperationAction::Pair => {
            if head.hard_fenced
                || head.lifecycle != input.expected_lifecycle_revision().get() as i64
                || head.fence != input.expected_prior_fence().get() as i64
            {
                return Err(CredentialLifecycleError::Conflict);
            }
            let version = operation
                .allocated_credential_version()
                .ok_or(CredentialLifecycleError::CorruptState)?;
            super::compatibility_mirror::activate(&transaction, version)?;
            transaction.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision=lifecycle_revision+1, credential_fence=credential_fence+1, readiness_revision=readiness_revision+1, active_credential_version=?1, active_ref_digest=?2, observed_at_high_water=MAX(observed_at_high_water, ?3) WHERE provider_id=?4", params![version.version(), version.ref_digest().to_vec(), (store.now)(), operation.provider().as_str()]).map_err(map_sql)?;
        }
        CredentialOperationAction::Revoke => {
            let target = operation
                .target_credential_version()
                .ok_or(CredentialLifecycleError::CorruptState)?;
            super::compatibility_mirror::delete(&transaction, target)?;
        }
        CredentialOperationAction::RetiredVersionCleanup => {
            if head.hard_fenced
                || head.lifecycle != input.expected_lifecycle_revision().get() as i64
                || head.fence != input.expected_prior_fence().get() as i64
            {
                return Err(CredentialLifecycleError::Conflict);
            }
            let target = operation
                .target_credential_version()
                .ok_or(CredentialLifecycleError::CorruptState)?;
            super::compatibility_mirror::delete(&transaction, target)?;
            let changed = transaction.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision=lifecycle_revision+1, credential_fence=credential_fence+1, readiness_revision=readiness_revision+1, observed_at_high_water=MAX(observed_at_high_water, ?1) WHERE provider_id=?2 AND lifecycle_revision=?3 AND credential_fence=?4 AND hard_fence_disposition IS NULL", params![(store.now)(), operation.provider().as_str(), input.expected_lifecycle_revision().get(), input.expected_prior_fence().get()]).map_err(map_sql)?;
            if changed != 1 {
                return Err(CredentialLifecycleError::Conflict);
            }
        }
        CredentialOperationAction::LegacySourceCleanup => {
            if head.hard_fenced
                || head.lifecycle != input.expected_lifecycle_revision().get() as i64
                || head.fence != input.expected_prior_fence().get() as i64
            {
                return Err(CredentialLifecycleError::Conflict);
            }
        }
        _ => return Err(CredentialLifecycleError::Conflict),
    }
    if let Some(observation) = input.readiness_observation() {
        super::readiness_observation::persist(&transaction, &operation, observation)?;
    }
    let result = super::completion_receipt::persist(
        &transaction,
        &operation,
        &input,
        &store.enrollment_authority,
    )?;
    transaction.execute("UPDATE provider_credential_operations SET state='COMPLETED', terminal_disposition='COMPLETED', updated_at=?1 WHERE operation_id=?2 AND state='READBACK_VERIFIED'", params![(store.now)(), input.operation_id().as_bytes().as_slice()]).map_err(map_sql)?;
    transaction.commit().map_err(map_sql)?;
    Ok(result)
}

pub(super) fn lifecycle(
    store: &SqliteProviderCredentialLifecycleStore,
    provider: &ProviderId,
) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
    let connection = store.connection.lock().map_err(super::map_lock)?;
    lifecycle_from(&connection, provider)
}
pub(super) fn hard_fence(
    store: &SqliteProviderCredentialLifecycleStore,
    input: HardFenceProvider,
) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let head = ensure_head(&transaction, input.provider())?;
    if head.hard_fenced || head.fence != input.expected_prior_fence().get() as i64 {
        return Err(CredentialLifecycleError::Conflict);
    }
    let diagnostic = diagnostic(input.provider(), input.new_fence());
    let changed = transaction.execute("UPDATE provider_credential_authority_heads SET lifecycle_revision=lifecycle_revision+1, credential_fence=?1, readiness_revision=readiness_revision+1, active_credential_version=NULL, active_ref_digest=NULL, hard_fence_disposition='INVARIANT_FAILURE', hard_fence_diagnostic_digest=?2, observed_at_high_water=MAX(observed_at_high_water, ?3) WHERE provider_id=?4 AND credential_fence=?5 AND hard_fence_disposition IS NULL", params![input.new_fence().get(), diagnostic.as_slice(), (store.now)(), input.provider().as_str(), input.expected_prior_fence().get()]).map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    super::compatibility_mirror::retire_active(&transaction, input.provider())?;
    let result = lifecycle_from(&transaction, input.provider())?;
    transaction.commit().map_err(map_sql)?;
    Ok(result)
}

fn lifecycle_from(
    connection: &rusqlite::Connection,
    provider: &ProviderId,
) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
    let head = load_head(connection, provider)?.ok_or(CredentialLifecycleError::NotFound)?;
    let active = head.active;
    CredentialLifecycleSnapshot::new(
        provider.clone(),
        active,
        super::rows::revision(head.lifecycle)?,
        fence(head.fence)?,
        readiness(head.readiness)?,
        u64::try_from(head.next_version).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}
fn diagnostic(provider: &ProviderId, fence: CredentialFence) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GOCODE_CREDENTIAL_HARD_FENCE_V1\0");
    hasher.update(provider.as_str().as_bytes());
    hasher.update(fence.get().to_be_bytes());
    hasher.finalize().into()
}
