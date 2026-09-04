use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    CredentialBindingDigest, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleError, CredentialLifecycleRevision, CredentialNativeEffectDisposition,
    CredentialOperationAction, CredentialOperationId, CredentialOperationSnapshot,
    CredentialOperationState, CredentialReadbackDisposition,
    CredentialReadinessRevision, CredentialTerminalDisposition, CredentialVersionRef, ProviderId,
};
use rusqlite::{Connection, OptionalExtension};

pub(super) use super::head::{Head, ensure_head, load_head};

pub(super) fn validate_dispatch_head(
    connection: &Connection,
    provider: &ProviderId,
) -> Result<(), CredentialLifecycleError> {
    if load_head(connection, provider)?.is_some() {
        return Err(CredentialLifecycleError::StaleLease);
    }
    Ok(())
}

pub(super) fn snapshot(
    connection: &Connection,
    operation: CredentialOperationId,
    authority: &runne_provider::CredentialEnrollmentStoreAuthority,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    let installation_owner_id = connection
        .query_row(
            "SELECT installation_owner_id FROM provider_credential_operations WHERE operation_id=?1",
            [operation.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(map_sql)?
        .ok_or(CredentialLifecycleError::NotFound)?;
    let installation_owner_id =
        CredentialInstallationOwnerId::from_bytes(bytes32(installation_owner_id)?)
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let raw = connection.query_row(
        "SELECT provider_id, action, command_id, idempotency_key, expected_lifecycle_revision, expected_credential_fence, allocated_credential_version, allocated_ref_digest, target_credential_version, target_ref_digest, state, begin_proof_digest, continuation_binding_digest, process_release_binding_digest, native_effect_disposition, readback_observation_digest, terminal_disposition, migration_id, migration_phase, migration_old_tuple_digest, migration_new_tuple_digest, broker_migration_binding_digest, created_at, updated_at, tombstone_digest, qualified_release_tuple_digest, claimed_ticket_attempt FROM provider_credential_operations WHERE operation_id=?1",
        [operation.as_bytes().as_slice()],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?, r.get::<_, Option<i64>>(6)?, r.get::<_, Option<Vec<u8>>>(7)?, r.get::<_, Option<i64>>(8)?, r.get::<_, Option<Vec<u8>>>(9)?, r.get::<_, String>(10)?, r.get::<_, Vec<u8>>(11)?, r.get::<_, Option<Vec<u8>>>(12)?, r.get::<_, Option<Vec<u8>>>(13)?, r.get::<_, Option<String>>(14)?, r.get::<_, Option<Vec<u8>>>(15)?, r.get::<_, Option<String>>(16)?, r.get::<_, Option<Vec<u8>>>(17)?, r.get::<_, Option<String>>(18)?, r.get::<_, Option<Vec<u8>>>(19)?, r.get::<_, Option<Vec<u8>>>(20)?, r.get::<_, Option<Vec<u8>>>(21)?, r.get::<_, i64>(22)?, r.get::<_, i64>(23)?, r.get::<_, Option<Vec<u8>>>(24)?, r.get::<_, Option<Vec<u8>>>(25)?, r.get::<_, Option<i64>>(26)?)),
    ).optional().map_err(map_sql)?.ok_or(CredentialLifecycleError::NotFound)?;
    let provider = ProviderId::new(raw.0).map_err(|_| CredentialLifecycleError::CorruptState)?;
    let action = action(&raw.1)?;
    let state = state(&raw.10)?;
    let decode_version = |value, digest: Option<Vec<u8>>| match (value, digest) {
        (Some(value), Some(digest)) => {
            let value = u64::try_from(value).map_err(|_| CredentialLifecycleError::CorruptState)?;
            let reference = CredentialVersionRef::new(provider.clone(), value)?;
            if digest != reference.ref_digest() {
                return Err(CredentialLifecycleError::CorruptState);
            }
            Ok(Some(reference))
        }
        (None, None) => Ok(None),
        _ => Err(CredentialLifecycleError::CorruptState),
    };
    let version = decode_version(raw.6, raw.7)?;
    let target = decode_version(raw.8, raw.9)?;
    let command = bytes16(raw.2).map(CommandId::from_bytes)?;
    let qualified_release_tuple_digest = raw.25.map(digest).transpose()?;
    let claimed_ticket_attempt = raw
        .26
        .map(|value| {
            runne_provider::CredentialTicketAttempt::new(
                u64::try_from(value).map_err(|_| CredentialLifecycleError::CorruptState)?,
            )
            .map_err(|_| CredentialLifecycleError::CorruptState)
        })
        .transpose()?;
    let mut metadata = authority.hydrate_persisted_credential_operation_metadata(
        command,
        IdempotencyKey::new(raw.3).map_err(|_| CredentialLifecycleError::CorruptState)?,
        installation_owner_id,
        revision(raw.4)?,
        fence(raw.5)?,
        digest(raw.11)?,
        raw.22,
        raw.23,
        qualified_release_tuple_digest,
        claimed_ticket_attempt,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)?;
    match (raw.12, raw.13) {
        (Some(continuation), Some(binding)) => {
            metadata = metadata.with_claim(digest(continuation)?, digest(binding)?)
        }
        (None, None) => {}
        _ => return Err(CredentialLifecycleError::CorruptState),
    }
    let terminal_disposition = raw.16.as_deref().map(terminal).transpose()?;
    if let Some(value) = raw.14 {
        metadata = metadata.with_native_effect(native(&value)?);
    }
    if let Some(value) = raw.15 {
        metadata = metadata.with_readback(
            readback_for(action, state, terminal_disposition)?,
            digest(value)?,
        );
    }
    if let Some(value) = terminal_disposition {
        metadata = metadata.with_terminal(value);
    }
    match (raw.17, raw.18, raw.19, raw.20, raw.21) {
        (Some(id), Some(phase), Some(old), Some(new), Some(binding)) => {
            let migration_id = CredentialOperationId::from_bytes(bytes16(id)?)
                .map_err(|_| CredentialLifecycleError::CorruptState)?;
            let phase = match phase.as_str() {
                "EFFECT" => runne_provider::WriterIdentityMigrationPhase::OldWriterEffect,
                "VERIFY" => runne_provider::WriterIdentityMigrationPhase::NewWriterVerify,
                _ => return Err(CredentialLifecycleError::CorruptState),
            };
            metadata =
                metadata.with_migration(authority.hydrate_persisted_credential_migration_metadata(
                    migration_id,
                    phase,
                    digest(old)?,
                    digest(new)?,
                    digest(binding)?,
                ));
        }
        (None, None, None, None, None) => {}
        _ => return Err(CredentialLifecycleError::CorruptState),
    }
    if let Some(value) = raw.24 {
        metadata = metadata.with_tombstone(digest(value)?);
    }
    if action == CredentialOperationAction::LegacySourceCleanup
        && let Some(binding) = super::legacy_cleanup_binding::load(
            connection, authority, operation, &provider, &metadata,
        )? {
        metadata = metadata.with_legacy_cleanup_binding(binding);
    }
    CredentialOperationSnapshot::new(
        operation, provider, action, state, version, target, metadata,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}

pub(super) fn action(value: &str) -> Result<CredentialOperationAction, CredentialLifecycleError> {
    match value {
        "PAIR" => Ok(CredentialOperationAction::Pair),
        "REVOKE" => Ok(CredentialOperationAction::Revoke),
        "MIGRATE_LEGACY" => Ok(CredentialOperationAction::MigrateLegacy),
        "RETIRED_VERSION_CLEANUP" => Ok(CredentialOperationAction::RetiredVersionCleanup),
        "LEGACY_SOURCE_CLEANUP" => Ok(CredentialOperationAction::LegacySourceCleanup),
        "WRITER_IDENTITY_MIGRATION_EFFECT" => {
            Ok(CredentialOperationAction::WriterIdentityMigrationEffect)
        }
        "WRITER_IDENTITY_MIGRATION_VERIFY" => {
            Ok(CredentialOperationAction::WriterIdentityMigrationVerify)
        }
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}
pub(super) fn action_sql(value: CredentialOperationAction) -> &'static str {
    match value {
        CredentialOperationAction::Pair => "PAIR",
        CredentialOperationAction::Revoke => "REVOKE",
        CredentialOperationAction::MigrateLegacy => "MIGRATE_LEGACY",
        CredentialOperationAction::RetiredVersionCleanup => "RETIRED_VERSION_CLEANUP",
        CredentialOperationAction::LegacySourceCleanup => "LEGACY_SOURCE_CLEANUP",
        CredentialOperationAction::WriterIdentityMigrationEffect => {
            "WRITER_IDENTITY_MIGRATION_EFFECT"
        }
        CredentialOperationAction::WriterIdentityMigrationVerify => {
            "WRITER_IDENTITY_MIGRATION_VERIFY"
        }
    }
}
pub(super) fn state(value: &str) -> Result<CredentialOperationState, CredentialLifecycleError> {
    match value {
        "PREPARED" => Ok(CredentialOperationState::Prepared),
        "CLAIMED" => Ok(CredentialOperationState::Claimed),
        "NATIVE_EFFECT_OBSERVED" => Ok(CredentialOperationState::NativeEffectObserved),
        "READBACK_VERIFIED" => Ok(CredentialOperationState::ReadbackVerified),
        "COMPLETED" => Ok(CredentialOperationState::Completed),
        "FAILED" => Ok(CredentialOperationState::Failed),
        "EXPIRED" => Ok(CredentialOperationState::Expired),
        "CANCELLED" => Ok(CredentialOperationState::Cancelled),
        "TOMBSTONED" => Ok(CredentialOperationState::Tombstoned),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}
pub(super) fn state_sql(value: CredentialOperationState) -> &'static str {
    match value {
        CredentialOperationState::Prepared => "PREPARED",
        CredentialOperationState::Claimed => "CLAIMED",
        CredentialOperationState::NativeEffectObserved => "NATIVE_EFFECT_OBSERVED",
        CredentialOperationState::ReadbackVerified => "READBACK_VERIFIED",
        CredentialOperationState::Completed => "COMPLETED",
        CredentialOperationState::Failed => "FAILED",
        CredentialOperationState::Expired => "EXPIRED",
        CredentialOperationState::Cancelled => "CANCELLED",
        CredentialOperationState::Tombstoned => "TOMBSTONED",
    }
}
pub(super) fn digest(value: Vec<u8>) -> Result<CredentialBindingDigest, CredentialLifecycleError> {
    CredentialBindingDigest::from_measured(bytes32(value)?)
        .map_err(|_| CredentialLifecycleError::CorruptState)
}
pub(super) fn revision(
    value: i64,
) -> Result<CredentialLifecycleRevision, CredentialLifecycleError> {
    CredentialLifecycleRevision::new(
        u64::try_from(value).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}
pub(super) fn fence(value: i64) -> Result<CredentialFence, CredentialLifecycleError> {
    CredentialFence::new(u64::try_from(value).map_err(|_| CredentialLifecycleError::CorruptState)?)
        .map_err(|_| CredentialLifecycleError::CorruptState)
}
pub(super) fn readiness(
    value: i64,
) -> Result<CredentialReadinessRevision, CredentialLifecycleError> {
    CredentialReadinessRevision::new(
        u64::try_from(value).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}
pub(super) fn map_sql(error: rusqlite::Error) -> CredentialLifecycleError {
    match error {
        rusqlite::Error::SqliteFailure(value, _)
            if value.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            CredentialLifecycleError::Conflict
        }
        _ => CredentialLifecycleError::StoreUnavailable,
    }
}
fn bytes16(value: Vec<u8>) -> Result<[u8; 16], CredentialLifecycleError> {
    value
        .try_into()
        .map_err(|_| CredentialLifecycleError::CorruptState)
}
fn bytes32(value: Vec<u8>) -> Result<[u8; 32], CredentialLifecycleError> {
    value
        .try_into()
        .map_err(|_| CredentialLifecycleError::CorruptState)
}
fn native(value: &str) -> Result<CredentialNativeEffectDisposition, CredentialLifecycleError> {
    match value {
        "POSSIBLE_EFFECT" => Ok(CredentialNativeEffectDisposition::PossibleEffect),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}
fn readback_for(
    action: CredentialOperationAction,
    state: CredentialOperationState,
    terminal: Option<CredentialTerminalDisposition>,
) -> Result<CredentialReadbackDisposition, CredentialLifecycleError> {
    if terminal == Some(CredentialTerminalDisposition::FailedWithVerifiedAbsence) {
        if matches!(
            (action, state),
            (
                CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy,
                CredentialOperationState::Failed | CredentialOperationState::Tombstoned
            )
        ) {
            return Ok(CredentialReadbackDisposition::ExactAbsence);
        }
        return Err(CredentialLifecycleError::CorruptState);
    }
    match action {
        CredentialOperationAction::Pair
        | CredentialOperationAction::MigrateLegacy
        | CredentialOperationAction::WriterIdentityMigrationVerify => {
            Ok(CredentialReadbackDisposition::ExactVersion)
        }
        CredentialOperationAction::Revoke
        | CredentialOperationAction::RetiredVersionCleanup
        | CredentialOperationAction::LegacySourceCleanup => {
            Ok(CredentialReadbackDisposition::ExactAbsence)
        }
        CredentialOperationAction::WriterIdentityMigrationEffect => {
            Err(CredentialLifecycleError::CorruptState)
        }
    }
}
fn terminal(value: &str) -> Result<CredentialTerminalDisposition, CredentialLifecycleError> {
    match value {
        "COMPLETED" => Ok(CredentialTerminalDisposition::Completed),
        "FAILED_WITH_VERIFIED_ABSENCE" => {
            Ok(CredentialTerminalDisposition::FailedWithVerifiedAbsence)
        }
        "EXPIRED" => Ok(CredentialTerminalDisposition::Expired),
        "CANCELLED" => Ok(CredentialTerminalDisposition::Cancelled),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}
