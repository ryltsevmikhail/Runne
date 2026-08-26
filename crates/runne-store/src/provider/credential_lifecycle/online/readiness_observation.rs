use runne_provider::{
    CredentialLifecycleError, CredentialLifecycleSnapshot, CredentialOperationAction,
    CredentialOperationSnapshot, CredentialReadinessDisposition, CredentialReadinessObservation,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::rows::{fence, load_head, map_sql, readiness, revision};

pub(super) fn persist(
    transaction: &Transaction<'_>,
    operation: &CredentialOperationSnapshot,
    observation: &CredentialReadinessObservation,
) -> Result<(), CredentialLifecycleError> {
    if observation.provider() != operation.provider()
        || observation.operation_id() != Some(operation.operation_id())
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    let changed = transaction
        .execute(
            "UPDATE provider_credential_authority_heads
             SET observed_at_high_water=?1
             WHERE provider_id=?2 AND lifecycle_revision=?3 AND readiness_revision=?4
               AND observed_at_high_water<=?1",
            params![
                observation.observed_at_high_water(),
                observation.provider().as_str(),
                observation.lifecycle_revision().get(),
                observation.readiness_revision().get(),
            ],
        )
        .map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    transaction
        .execute(
            "INSERT INTO provider_credential_readiness_observations
             (observation_id, provider_id, lifecycle_revision, readiness_revision,
              disposition, active_binding_digest, release_tuple_digest, observed_at,
              operation_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                observation.observation_id().as_bytes().as_slice(),
                observation.provider().as_str(),
                observation.lifecycle_revision().get(),
                observation.readiness_revision().get(),
                disposition(observation.disposition()),
                observation
                    .active_binding_digest()
                    .map(|digest| digest.as_bytes().to_vec()),
                observation.release_tuple_digest().as_bytes().as_slice(),
                observation.observed_at_high_water(),
                operation.operation_id().as_bytes().as_slice(),
            ],
        )
        .map_err(map_sql)?;
    Ok(())
}

pub(super) fn matches_replay(
    transaction: &Transaction<'_>,
    operation: &CredentialOperationSnapshot,
    observation: Option<&CredentialReadinessObservation>,
) -> Result<bool, CredentialLifecycleError> {
    match observation {
        Some(observation) => matches_persisted(transaction, operation, observation),
        None => transaction
            .query_row(
                "SELECT 1 FROM provider_credential_readiness_observations
                 WHERE operation_id=?1",
                [operation.operation_id().as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_none())
            .map_err(map_sql),
    }
}

fn matches_persisted(
    transaction: &Transaction<'_>,
    operation: &CredentialOperationSnapshot,
    observation: &CredentialReadinessObservation,
) -> Result<bool, CredentialLifecycleError> {
    if observation.provider() != operation.provider()
        || observation.operation_id() != Some(operation.operation_id())
    {
        return Ok(false);
    }
    let active = observation
        .active_binding_digest()
        .map(|digest| digest.as_bytes().to_vec());
    transaction
        .query_row(
            "SELECT 1 FROM provider_credential_readiness_observations
             WHERE observation_id=?1 AND provider_id=?2 AND lifecycle_revision=?3
               AND readiness_revision=?4 AND disposition=?5
               AND active_binding_digest IS ?6 AND release_tuple_digest=?7
               AND observed_at=?8 AND operation_id=?9",
            params![
                observation.observation_id().as_bytes().as_slice(),
                observation.provider().as_str(),
                observation.lifecycle_revision().get(),
                observation.readiness_revision().get(),
                disposition(observation.disposition()),
                active,
                observation.release_tuple_digest().as_bytes().as_slice(),
                observation.observed_at_high_water(),
                operation.operation_id().as_bytes().as_slice(),
            ],
            |_| Ok(true),
        )
        .optional()
        .map(|matched| matched.unwrap_or(false))
        .map_err(map_sql)
}

pub(super) fn completion_receipt(
    transaction: &Transaction<'_>,
    operation: &CredentialOperationSnapshot,
) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
    let mut statement = transaction
        .prepare(
            "SELECT lifecycle_revision, readiness_revision, disposition,
                    active_binding_digest
             FROM provider_credential_readiness_observations WHERE operation_id=?1",
        )
        .map_err(map_sql)?;
    let rows = statement
        .query_map([operation.operation_id().as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })
        .map_err(map_sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql)?;
    let [(lifecycle, readiness_revision, disposition, active_digest)] = rows.as_slice() else {
        return Err(CredentialLifecycleError::CorruptState);
    };
    let expected_lifecycle = operation
        .lifecycle_revision()
        .get()
        .checked_add(1)
        .ok_or(CredentialLifecycleError::CorruptState)?;
    let expected_fence = operation
        .fence()
        .get()
        .checked_add(1)
        .ok_or(CredentialLifecycleError::CorruptState)?;
    if u64::try_from(*lifecycle).ok() != Some(expected_lifecycle) {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let active = match operation.action() {
        CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => {
            let version = operation
                .allocated_credential_version()
                .cloned()
                .ok_or(CredentialLifecycleError::CorruptState)?;
            if disposition != "READY"
                || active_digest.as_deref() != Some(version.ref_digest().as_slice())
            {
                return Err(CredentialLifecycleError::CorruptState);
            }
            Some(version)
        }
        CredentialOperationAction::Revoke => {
            if disposition != "MISSING" || active_digest.is_some() {
                return Err(CredentialLifecycleError::CorruptState);
            }
            None
        }
        _ => return Err(CredentialLifecycleError::CorruptState),
    };
    let head = load_head(transaction, operation.provider())?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    CredentialLifecycleSnapshot::new(
        operation.provider().clone(),
        active,
        revision(*lifecycle)?,
        fence(i64::try_from(expected_fence).map_err(|_| CredentialLifecycleError::CorruptState)?)?,
        readiness(*readiness_revision)?,
        u64::try_from(head.next_version).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}

fn disposition(value: CredentialReadinessDisposition) -> &'static str {
    match value {
        CredentialReadinessDisposition::Ready => "READY",
        CredentialReadinessDisposition::Missing => "MISSING",
        CredentialReadinessDisposition::Stale => "STALE",
        CredentialReadinessDisposition::Unavailable => "UNAVAILABLE",
        CredentialReadinessDisposition::Unsupported => "UNSUPPORTED",
        CredentialReadinessDisposition::AccessDenied => "ACCESS_DENIED",
        CredentialReadinessDisposition::Conflict => "CONFLICT",
        CredentialReadinessDisposition::InvariantFailure => "INVARIANT_FAILURE",
    }
}
