use runne_provider::{
    CredentialEnrollmentStoreAuthority, CredentialLegacyCleanupBinding, CredentialLifecycleError,
    CredentialOperationId, CredentialOperationMetadata, ProviderId,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::rows::{digest, map_sql, snapshot};

pub(super) fn load(
    connection: &Connection,
    authority: &CredentialEnrollmentStoreAuthority,
    cleanup: CredentialOperationId,
    provider: &ProviderId,
    metadata: &CredentialOperationMetadata,
) -> Result<Option<CredentialLegacyCleanupBinding>, CredentialLifecycleError> {
    let head = connection
        .query_row(
            "SELECT legacy_import_consumed, legacy_source_binding_digest,
                legacy_consumed_lifecycle_revision, legacy_cleanup_operation_id
         FROM provider_credential_authority_heads WHERE provider_id=?1",
            [provider.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(map_sql)?;
    let (expected_digest, consumed_revision, linked_cleanup) = match head {
        // Old unbound operations remain inspectable but acquire no cleanup binding.
        None | Some((0, None, None, None)) => return Ok(None),
        Some((1, Some(digest), Some(revision), Some(cleanup))) if revision > 1 => {
            (digest, revision, cleanup)
        }
        _ => return Err(CredentialLifecycleError::CorruptState),
    };
    if linked_cleanup.as_slice() != cleanup.as_bytes() {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let expected_digest = digest(expected_digest)?;
    let mut statement = connection
        .prepare(
            "SELECT operation_id FROM provider_credential_operations
         WHERE provider_id=?1 AND action='MIGRATE_LEGACY'
           AND state IN ('COMPLETED', 'TOMBSTONED') AND terminal_disposition='COMPLETED'
           AND expected_lifecycle_revision=?2 AND installation_owner_id=?3
           AND readback_observation_digest=?4 LIMIT 2",
        )
        .map_err(map_sql)?;
    let ids = statement
        .query_map(
            params![
                provider.as_str(),
                consumed_revision - 1,
                metadata.installation_owner_id().as_bytes().as_slice(),
                expected_digest.as_bytes().as_slice()
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(map_sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql)?;
    let [id] = ids.as_slice() else {
        return Err(CredentialLifecycleError::CorruptState);
    };
    let id = CredentialOperationId::from_bytes(
        id.as_slice()
            .try_into()
            .map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let import = snapshot(connection, id, authority)?;
    let derived = super::legacy_cutover::cleanup_values(&import)?;
    if derived.operation_id != cleanup.as_bytes()
        || derived.command_id != *metadata.command_id().as_bytes()
        || derived.lifecycle != metadata.expected_lifecycle_revision().get()
        || derived.fence != metadata.expected_prior_fence().get()
    {
        return Err(CredentialLifecycleError::CorruptState);
    }
    CredentialLegacyCleanupBinding::from_completed_import(&import)
        .map(Some)
        .map_err(|_| CredentialLifecycleError::CorruptState)
}
