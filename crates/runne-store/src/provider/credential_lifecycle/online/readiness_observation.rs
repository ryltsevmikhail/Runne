use runne_provider::{
    CredentialLifecycleError, CredentialOperationSnapshot, CredentialReadinessDisposition,
    CredentialReadinessObservation,
};
use rusqlite::{Transaction, params};

use super::rows::map_sql;

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
