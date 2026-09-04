use runne_provider::{
    CompleteCredentialOperation, CredentialCompletionReceipt, CredentialLifecycleError,
    CredentialOperationSnapshot,
};
use rusqlite::{Transaction, params};
use sha2::{Digest, Sha256};

use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{Head, map_sql};

pub(super) fn complete(
    transaction: &Transaction<'_>,
    store: &SqliteProviderCredentialLifecycleStore,
    operation: &CredentialOperationSnapshot,
    input: &CompleteCredentialOperation,
    head: &Head,
) -> Result<CredentialCompletionReceipt, CredentialLifecycleError> {
    if head.hard_fenced
        || head.lifecycle != input.expected_lifecycle_revision().get() as i64
        || head.fence != input.expected_prior_fence().get() as i64
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let version = operation
        .allocated_credential_version()
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let tuple = operation
        .metadata()
        .qualified_release_tuple_digest()
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let cleanup = cleanup_values(operation)?;
    let now = head.observed_at.max((store.now)());
    if now < 0 {
        return Err(CredentialLifecycleError::InvalidInput);
    }
    transaction.execute(
        "INSERT INTO provider_credential_operations (operation_id, installation_owner_id, provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, state, begin_proof_digest, begin_proof_expires_at_high_water, qualified_release_tuple_digest, created_at, updated_at) VALUES (?1, ?2, ?3, 'LEGACY_SOURCE_CLEANUP', ?4, ?5, ?6, ?7, 'PREPARED', ?8, ?9, ?10, ?11, ?11)",
        params![cleanup.operation_id.as_slice(), operation.installation_owner_id().as_bytes().as_slice(), operation.provider().as_str(), cleanup.command_id.as_slice(), cleanup.idempotency_key, cleanup.lifecycle, cleanup.fence, cleanup.begin_proof.as_slice(), i64::MAX, tuple.as_bytes().as_slice(), now],
    ).map_err(map_sql)?;
    super::compatibility_mirror::activate(transaction, version)?;
    let changed = transaction.execute(
        "UPDATE provider_credential_authority_heads SET lifecycle_revision=lifecycle_revision+1, credential_fence=credential_fence+1, readiness_revision=readiness_revision+1, active_credential_version=?1, active_ref_digest=?2, legacy_import_consumed=1, legacy_source_binding_digest=?3, legacy_consumed_lifecycle_revision=lifecycle_revision+1, legacy_cleanup_operation_id=?4 WHERE provider_id=?5 AND lifecycle_revision=?6 AND credential_fence=?7 AND hard_fence_disposition IS NULL AND legacy_import_consumed=0",
        params![version.version(), version.ref_digest().to_vec(), input.readback().observation_digest().as_bytes().as_slice(), cleanup.operation_id.as_slice(), operation.provider().as_str(), input.expected_lifecycle_revision().get(), input.expected_prior_fence().get()],
    ).map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    let observation = input
        .readiness_observation()
        .ok_or(CredentialLifecycleError::Conflict)?;
    super::readiness_observation::persist(transaction, operation, observation)?;
    let receipt = super::completion_receipt::persist(
        transaction,
        operation,
        input,
        &store.enrollment_authority,
    )?;
    let completed = transaction.execute(
        "UPDATE provider_credential_operations SET state='COMPLETED', terminal_disposition='COMPLETED', updated_at=?1 WHERE operation_id=?2 AND state='READBACK_VERIFIED'",
        params![now, operation.operation_id().as_bytes().as_slice()],
    ).map_err(map_sql)?;
    if completed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    Ok(receipt)
}

pub(super) struct CleanupValues {
    pub(super) operation_id: [u8; 16],
    pub(super) command_id: [u8; 16],
    begin_proof: [u8; 32],
    idempotency_key: String,
    pub(super) lifecycle: u64,
    pub(super) fence: u64,
}

pub(super) fn cleanup_values(
    operation: &CredentialOperationSnapshot,
) -> Result<CleanupValues, CredentialLifecycleError> {
    let lifecycle = operation
        .lifecycle_revision()
        .get()
        .checked_add(1)
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let fence = operation
        .fence()
        .get()
        .checked_add(1)
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let operation_id = hash16(b"GOCODE_LEGACY_CLEANUP_OPERATION_V1\0", operation);
    let command_id = hash16(b"GOCODE_LEGACY_CLEANUP_COMMAND_V1\0", operation);
    let begin_proof = hash32(b"GOCODE_LEGACY_CLEANUP_BEGIN_V1\0", operation);
    Ok(CleanupValues {
        operation_id,
        command_id,
        begin_proof,
        idempotency_key: format!("legacy-cleanup-{}", hex(&operation_id)),
        lifecycle,
        fence,
    })
}

fn hash16(domain: &[u8], operation: &CredentialOperationSnapshot) -> [u8; 16] {
    hash32(domain, operation)[..16]
        .try_into()
        .expect("slice has 16 bytes")
}

fn hash32(domain: &[u8], operation: &CredentialOperationSnapshot) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(operation.operation_id().as_bytes());
    hash.update(operation.provider().as_str().as_bytes());
    hash.update(operation.lifecycle_revision().get().to_be_bytes());
    hash.update(operation.fence().get().to_be_bytes());
    hash.finalize().into()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
