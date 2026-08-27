use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{load_head, map_sql, readiness as readiness_revision, revision};
use runne_provider::{
    CredentialLifecycleError, CredentialReadinessDisposition, CredentialSafeSnapshot,
    CredentialVerificationKind, CredentialVerificationResult, CredentialVerificationSnapshot,
    CredentialVerifierRevision, ProviderId,
};
use rusqlite::{Connection, OptionalExtension};

type VerificationRow = (String, String, Option<String>, i64, Option<i64>);

pub(super) fn load(
    store: &SqliteProviderCredentialLifecycleStore,
    provider: &ProviderId,
) -> Result<CredentialSafeSnapshot, CredentialLifecycleError> {
    let connection = store.connection.lock().map_err(super::map_lock)?;
    let head = load_head(&connection, provider)?.ok_or(CredentialLifecycleError::NotFound)?;
    let readiness = readiness(&connection, provider, &head)?;
    let verification = verification(&connection, provider, &head)?;
    CredentialSafeSnapshot::new(
        provider.clone(),
        head.active.is_some(),
        revision(head.lifecycle)?,
        readiness_revision(head.readiness)?,
        readiness,
        head.observed_at,
        verification,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}

fn readiness(
    connection: &Connection,
    provider: &ProviderId,
    head: &super::head::Head,
) -> Result<CredentialReadinessDisposition, CredentialLifecycleError> {
    if head.hard_fenced {
        return Ok(CredentialReadinessDisposition::InvariantFailure);
    }
    let value: Option<String> = connection
        .query_row(
            "SELECT disposition FROM provider_credential_readiness_observations
             WHERE provider_id=?1 AND lifecycle_revision=?2 AND readiness_revision=?3",
            (provider.as_str(), head.lifecycle, head.readiness),
            |row| row.get(0),
        )
        .optional()
        .map_err(map_sql)?;
    match value {
        Some(value) => parse_readiness(&value),
        None if head.active.is_some() => Ok(CredentialReadinessDisposition::Stale),
        None => Ok(CredentialReadinessDisposition::Missing),
    }
}

fn verification(
    connection: &Connection,
    provider: &ProviderId,
    head: &super::head::Head,
) -> Result<CredentialVerificationSnapshot, CredentialLifecycleError> {
    let Some(active) = head.active.as_ref() else {
        return Ok(CredentialVerificationSnapshot::not_verified());
    };
    let row: Option<VerificationRow> = connection
        .query_row(
            "SELECT verification_kind, state, result, verifier_revision, observed_at
             FROM provider_credential_verification_observations
             WHERE provider_id=?1 AND lifecycle_revision=?2 AND credential_fence=?3
               AND active_credential_version=?4 AND active_ref_digest=?5
             ORDER BY started_at DESC, observation_id DESC LIMIT 1",
            (
                provider.as_str(),
                head.lifecycle,
                head.fence,
                i64::try_from(active.version()).map_err(|_| CredentialLifecycleError::CorruptState)?,
                active.ref_digest().as_slice(),
            ),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
        .map_err(map_sql)?;
    let Some((kind, state, result, revision, observed)) = row else {
        return Ok(CredentialVerificationSnapshot::not_verified());
    };
    let kind = parse_kind(&kind)?;
    let revision = CredentialVerifierRevision::new(
        u64::try_from(revision).map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let snapshot = match (state.as_str(), result, observed) {
        ("LEASED", None, None) => CredentialVerificationSnapshot::pending(kind, revision),
        ("COMPLETED", Some(result), Some(observed)) => CredentialVerificationSnapshot::completed(
            kind,
            parse_result(&result)?,
            revision,
            observed,
        ),
        _ => return Err(CredentialLifecycleError::CorruptState),
    };
    snapshot.map_err(|_| CredentialLifecycleError::CorruptState)
}

fn parse_readiness(value: &str) -> Result<CredentialReadinessDisposition, CredentialLifecycleError> {
    match value {
        "READY" => Ok(CredentialReadinessDisposition::Ready),
        "MISSING" => Ok(CredentialReadinessDisposition::Missing),
        "STALE" => Ok(CredentialReadinessDisposition::Stale),
        "UNAVAILABLE" => Ok(CredentialReadinessDisposition::Unavailable),
        "UNSUPPORTED" => Ok(CredentialReadinessDisposition::Unsupported),
        "ACCESS_DENIED" => Ok(CredentialReadinessDisposition::AccessDenied),
        "CONFLICT" => Ok(CredentialReadinessDisposition::Conflict),
        "INVARIANT_FAILURE" => Ok(CredentialReadinessDisposition::InvariantFailure),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}

fn parse_kind(value: &str) -> Result<CredentialVerificationKind, CredentialLifecycleError> {
    match value {
        "LOCAL" => Ok(CredentialVerificationKind::Local),
        "REMOTE" => Ok(CredentialVerificationKind::Remote),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}

fn parse_result(value: &str) -> Result<CredentialVerificationResult, CredentialLifecycleError> {
    match value {
        "VERIFIED" => Ok(CredentialVerificationResult::Verified),
        "FAILED" => Ok(CredentialVerificationResult::Failed),
        "UNSUPPORTED" => Ok(CredentialVerificationResult::Unsupported),
        "UNAVAILABLE" => Ok(CredentialVerificationResult::Unavailable),
        "ACCESS_DENIED" => Ok(CredentialVerificationResult::AccessDenied),
        "CONFLICT" => Ok(CredentialVerificationResult::Conflict),
        _ => Err(CredentialLifecycleError::CorruptState),
    }
}
