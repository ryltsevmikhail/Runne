use runne_provider::{
    CompleteCredentialOperation, CredentialBindingDigest, CredentialCompletionReceipt,
    CredentialLifecycleError, CredentialLifecycleSnapshot, CredentialOperationSnapshot,
    CredentialReadbackDisposition, CredentialReadinessObservation, CredentialVersionRef,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::rows::{action, digest, fence, load_head, map_sql, readiness, revision};

pub(super) fn persist(
    transaction: &Transaction<'_>,
    operation: &CredentialOperationSnapshot,
    input: &CompleteCredentialOperation,
    authority: &runne_provider::CredentialEnrollmentStoreAuthority,
) -> Result<CredentialCompletionReceipt, CredentialLifecycleError> {
    let receipt = hydrate(transaction, operation, input, authority)?;
    transaction
        .execute(
            "INSERT INTO provider_credential_completion_receipts (operation_id, installation_owner_id, provider_id, action, target_credential_version, target_ref_digest, predecessor_lifecycle_revision, predecessor_credential_fence, claimed_ticket_attempt, broker_migration_binding_digest, qualified_release_tuple_digest, readback_disposition, readback_observation_digest, readiness_observation_id, successor_lifecycle_revision, successor_credential_fence, successor_readiness_revision, active_credential_version, active_ref_digest, next_credential_version) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![receipt.operation_id().as_bytes().as_slice(), receipt.installation_owner_id().as_bytes().as_slice(), receipt.provider().as_str(), super::rows::action_sql(receipt.action()), receipt.target().map(|target| target.version()), receipt.target().map(|target| target.ref_digest().to_vec()), receipt.predecessor_lifecycle_revision().get(), receipt.predecessor_fence().get(), receipt.claimed_ticket_attempt().get(), receipt.broker_migration_binding_digest().map(|digest| digest.as_bytes().to_vec()), receipt.qualified_release_tuple_digest().as_bytes().to_vec(), readback_sql(receipt.readback_disposition()), receipt.readback_observation_digest().as_bytes().to_vec(), receipt.readiness_observation_id().map(|id| id.as_bytes().to_vec()), receipt.lifecycle_revision().get(), receipt.fence().get(), receipt.readiness_revision().get(), receipt.active_version().map(|active| active.version()), receipt.active_version().map(|active| active.ref_digest().to_vec()), receipt.next_credential_version()],
        )
        .map_err(map_sql)?;
    Ok(receipt)
}

pub(super) fn load(
    transaction: &Transaction<'_>,
    operation: &CredentialOperationSnapshot,
    input: &CompleteCredentialOperation,
    authority: &runne_provider::CredentialEnrollmentStoreAuthority,
) -> Result<CredentialCompletionReceipt, CredentialLifecycleError> {
    let raw = transaction
        .query_row(
            "SELECT installation_owner_id, provider_id, action, target_credential_version, target_ref_digest, predecessor_lifecycle_revision, predecessor_credential_fence, claimed_ticket_attempt, broker_migration_binding_digest, qualified_release_tuple_digest, readback_disposition, readback_observation_digest, readiness_observation_id, successor_lifecycle_revision, successor_credential_fence, successor_readiness_revision, active_credential_version, active_ref_digest, next_credential_version FROM provider_credential_completion_receipts WHERE operation_id=?1",
            [operation.operation_id().as_bytes().as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<i64>>(3)?, row.get::<_, Option<Vec<u8>>>(4)?, row.get::<_, i64>(5)?, row.get::<_, i64>(6)?, row.get::<_, i64>(7)?, row.get::<_, Option<Vec<u8>>>(8)?, row.get::<_, Vec<u8>>(9)?, row.get::<_, String>(10)?, row.get::<_, Vec<u8>>(11)?, row.get::<_, Option<Vec<u8>>>(12)?, row.get::<_, i64>(13)?, row.get::<_, i64>(14)?, row.get::<_, i64>(15)?, row.get::<_, Option<i64>>(16)?, row.get::<_, Option<Vec<u8>>>(17)?, row.get::<_, i64>(18)?)),
        )
        .optional()
        .map_err(map_sql)?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let provider = runne_provider::ProviderId::new(raw.1)
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let target = version(&provider, raw.3, raw.4)?;
    let active = version(&provider, raw.16, raw.17)?;
    let lifecycle = CredentialLifecycleSnapshot::new(
        provider.clone(),
        active,
        revision(raw.13)?,
        fence(raw.14)?,
        readiness(raw.15)?,
        u64::try_from(raw.18).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let receipt = authority.hydrate_persisted_credential_completion_receipt(
        operation.operation_id(),
        owner(raw.0)?,
        provider,
        action(&raw.2)?,
        target,
        revision(raw.5)?,
        fence(raw.6)?,
        attempt(raw.7)?,
        raw.8.map(digest).transpose()?,
        digest(raw.9)?,
        readback(&raw.10)?,
        digest(raw.11)?,
        raw.12.map(operation_id).transpose()?,
        lifecycle,
    );
    validate(operation, input, &receipt)?;
    Ok(receipt)
}

fn hydrate(
    transaction: &Transaction<'_>,
    operation: &CredentialOperationSnapshot,
    input: &CompleteCredentialOperation,
    authority: &runne_provider::CredentialEnrollmentStoreAuthority,
) -> Result<CredentialCompletionReceipt, CredentialLifecycleError> {
    let head = load_head(transaction, operation.provider())?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let lifecycle = CredentialLifecycleSnapshot::new(
        operation.provider().clone(),
        head.active,
        revision(head.lifecycle)?,
        fence(head.fence)?,
        readiness(head.readiness)?,
        u64::try_from(head.next_version).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let target = operation
        .allocated_credential_version()
        .or(operation.target_credential_version())
        .cloned();
    let tuple = operation
        .metadata()
        .qualified_release_tuple_digest()
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let receipt = authority.hydrate_persisted_credential_completion_receipt(
        operation.operation_id(),
        operation.installation_owner_id(),
        operation.provider().clone(),
        operation.action(),
        target,
        operation.lifecycle_revision(),
        operation.fence(),
        operation
            .metadata()
            .claimed_ticket_attempt()
            .ok_or(CredentialLifecycleError::CorruptState)?,
        operation
            .metadata()
            .migration()
            .map(|metadata| metadata.binding_digest()),
        tuple,
        input.readback().disposition(),
        input.readback().observation_digest(),
        input
            .readiness_observation()
            .map(CredentialReadinessObservation::observation_id),
        lifecycle,
    );
    validate(operation, input, &receipt)?;
    Ok(receipt)
}

fn validate(
    operation: &CredentialOperationSnapshot,
    input: &CompleteCredentialOperation,
    receipt: &CredentialCompletionReceipt,
) -> Result<(), CredentialLifecycleError> {
    let observation = input.readiness_observation();
    let legacy_source_cleanup =
        operation.action() == runne_provider::CredentialOperationAction::LegacySourceCleanup;
    let active = receipt
        .active_version()
        .map(|version| CredentialBindingDigest::from_measured(*version.ref_digest()))
        .transpose()
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
    if receipt.operation_id() != operation.operation_id()
        || receipt.installation_owner_id() != operation.installation_owner_id()
        || receipt.provider() != operation.provider()
        || receipt.action() != operation.action()
        || receipt.target()
            != operation
                .allocated_credential_version()
                .or(operation.target_credential_version())
        || receipt.predecessor_lifecycle_revision() != operation.lifecycle_revision()
        || receipt.predecessor_fence() != operation.fence()
        || receipt.claimed_ticket_attempt()
            != operation
                .metadata()
                .claimed_ticket_attempt()
                .ok_or(CredentialLifecycleError::CorruptState)?
        || receipt.broker_migration_binding_digest()
            != operation
                .metadata()
                .migration()
                .map(|metadata| metadata.binding_digest())
        || receipt.qualified_release_tuple_digest()
            != operation
                .metadata()
                .qualified_release_tuple_digest()
                .ok_or(CredentialLifecycleError::CorruptState)?
        || receipt.readback_disposition() != input.readback().disposition()
        || receipt.readback_observation_digest() != input.readback().observation_digest()
        || (legacy_source_cleanup
            && (receipt.lifecycle_revision().get()
                < receipt.predecessor_lifecycle_revision().get()
                || receipt.fence().get() < receipt.predecessor_fence().get()
                || operation.metadata().legacy_cleanup_binding().is_none()
                || receipt.readiness_observation_id().is_some()
                || observation.is_some()
                || receipt.readback_disposition() != CredentialReadbackDisposition::ExactAbsence))
        || (!legacy_source_cleanup
            && (receipt.lifecycle_revision().get()
                != receipt.predecessor_lifecycle_revision().get() + 1
                || receipt.fence().get() != receipt.predecessor_fence().get() + 1
                || !observation.is_some_and(|observation| {
                    Some(observation.observation_id()) == receipt.readiness_observation_id()
                        && observation.operation_id() == Some(operation.operation_id())
                        && observation.provider() == receipt.provider()
                        && observation.lifecycle_revision() == receipt.lifecycle_revision()
                        && observation.readiness_revision() == receipt.readiness_revision()
                        && observation.release_tuple_digest()
                            == receipt.qualified_release_tuple_digest()
                        && observation.active_binding_digest() == active
                })))
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    Ok(())
}

fn owner(
    value: Vec<u8>,
) -> Result<runne_provider::CredentialInstallationOwnerId, CredentialLifecycleError> {
    runne_provider::CredentialInstallationOwnerId::from_bytes(
        value
            .try_into()
            .map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}
fn operation_id(
    value: Vec<u8>,
) -> Result<runne_provider::CredentialOperationId, CredentialLifecycleError> {
    runne_provider::CredentialOperationId::from_bytes(
        value
            .try_into()
            .map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}
fn attempt(
    value: i64,
) -> Result<runne_provider::CredentialTicketAttempt, CredentialLifecycleError> {
    runne_provider::CredentialTicketAttempt::new(
        u64::try_from(value).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}
fn version(
    provider: &runne_provider::ProviderId,
    value: Option<i64>,
    digest: Option<Vec<u8>>,
) -> Result<Option<CredentialVersionRef>, CredentialLifecycleError> {
    match (value, digest) {
        (Some(value), Some(digest)) => {
            let version = CredentialVersionRef::new(
                provider.clone(),
                u64::try_from(value).map_err(|_| CredentialLifecycleError::CorruptState)?,
            )?;
            (digest == version.ref_digest())
                .then_some(version)
                .ok_or(CredentialLifecycleError::CorruptState)
                .map(Some)
        }
        (None, None) => Ok(None),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}
fn readback(value: &str) -> Result<CredentialReadbackDisposition, CredentialLifecycleError> {
    match value {
        "EXACT_VERSION" => Ok(CredentialReadbackDisposition::ExactVersion),
        "EXACT_ABSENCE" => Ok(CredentialReadbackDisposition::ExactAbsence),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}
fn readback_sql(value: CredentialReadbackDisposition) -> &'static str {
    match value {
        CredentialReadbackDisposition::ExactVersion => "EXACT_VERSION",
        CredentialReadbackDisposition::ExactAbsence => "EXACT_ABSENCE",
    }
}
