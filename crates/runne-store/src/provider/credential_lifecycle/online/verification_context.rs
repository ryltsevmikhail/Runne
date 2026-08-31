use runne_provider::{
    CredentialBindingDigest, CredentialLifecycleError, CredentialLifecycleSnapshot,
    CredentialVerificationContext, ProviderId,
};
use rusqlite::{OptionalExtension, params};

use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{fence, load_head, map_sql, readiness, revision};

type CurrentReadinessRow = (String, Vec<u8>, Vec<u8>, i64);

/// Loads only a current `READY` observation matching the authoritative head.
pub(super) fn load(
    store: &SqliteProviderCredentialLifecycleStore,
    provider: &ProviderId,
) -> Result<CredentialVerificationContext, CredentialLifecycleError> {
    let connection = store.connection.lock().map_err(super::map_lock)?;
    let head = load_head(&connection, provider)?.ok_or(CredentialLifecycleError::NotFound)?;
    let active = head
        .active
        .clone()
        .ok_or(CredentialLifecycleError::Conflict)?;
    if head.hard_fenced {
        return Err(CredentialLifecycleError::Conflict);
    }
    let row: Option<CurrentReadinessRow> = connection
        .query_row(
            "SELECT disposition, active_binding_digest, release_tuple_digest, observed_at
             FROM provider_credential_readiness_observations
             WHERE provider_id=?1 AND lifecycle_revision=?2 AND readiness_revision=?3",
            params![provider.as_str(), head.lifecycle, head.readiness],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(map_sql)?;
    let (disposition, active_binding, release_tuple, observed_at) =
        row.ok_or(CredentialLifecycleError::Conflict)?;
    if disposition != "READY" || observed_at < 0 || observed_at > head.observed_at {
        return Err(CredentialLifecycleError::Conflict);
    }
    let lifecycle = CredentialLifecycleSnapshot::new(
        provider.clone(),
        Some(active),
        revision(head.lifecycle)?,
        fence(head.fence)?,
        readiness(head.readiness)?,
        u64::try_from(head.next_version).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)?;
    CredentialVerificationContext::new(
        lifecycle,
        CredentialBindingDigest::from_measured(
            active_binding
                .try_into()
                .map_err(|_| CredentialLifecycleError::CorruptState)?,
        )
        .map_err(|_| CredentialLifecycleError::CorruptState)?,
        CredentialBindingDigest::from_measured(
            release_tuple
                .try_into()
                .map_err(|_| CredentialLifecycleError::CorruptState)?,
        )
        .map_err(|_| CredentialLifecycleError::CorruptState)?,
        observed_at,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}
