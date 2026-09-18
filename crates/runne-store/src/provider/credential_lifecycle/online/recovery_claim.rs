use runne_provider::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialEnrollmentStoreAuthority,
    CredentialLifecycleError, CredentialOperationAction,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::rows::map_sql;

pub(super) fn lease_deadline(
    transaction: &Transaction<'_>,
    operation: runne_provider::CredentialOperationId,
    continuation: CredentialBindingDigest,
    now: i64,
) -> Result<Option<i64>, CredentialLifecycleError> {
    let row: Option<(Vec<u8>, i64, i64, String)> = transaction.query_row(
        "SELECT continuation_digest, issued_at, expires_at, state
         FROM credential_cleanup_recovery_attempts WHERE operation_id=?1 ORDER BY attempt DESC LIMIT 1",
        [operation.as_bytes().as_slice()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    ).optional().map_err(map_sql)?;
    let Some((proof, issued, expires, state)) = row else {
        return Ok(None);
    };
    if state != "ACCEPTED" || proof != continuation.as_bytes() {
        return Err(CredentialLifecycleError::Conflict);
    }
    if now < issued || now >= expires {
        return Err(CredentialLifecycleError::StaleLease);
    }
    Ok(Some(expires))
}

pub(super) fn consume(
    transaction: &Transaction<'_>,
    authority: &CredentialEnrollmentStoreAuthority,
    claim: &ClaimCredentialOperation,
    now: i64,
) -> Result<(), CredentialLifecycleError> {
    let row = transaction.query_row(
        "SELECT installation_owner_id, release_tuple_digest, protected_session_digest,
                database_generation, supervisor_generation, lifecycle_revision, credential_fence,
                continuation_digest, issued_at, expires_at, state
         FROM credential_cleanup_recovery_attempts WHERE operation_id=?1 ORDER BY attempt DESC LIMIT 1",
        [claim.operation_id().as_bytes().as_slice()],
        |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?,
            r.get::<_, i64>(3)?, r.get::<_, i64>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?,
            r.get::<_, Vec<u8>>(7)?, r.get::<_, i64>(8)?, r.get::<_, i64>(9)?, r.get::<_, String>(10)?)),
    ).optional().map_err(map_sql)?;
    let Some((
        owner,
        release,
        session,
        database,
        supervisor,
        lifecycle,
        fence,
        proof,
        issued,
        expires,
        state,
    )) = row
    else {
        return Ok(());
    };
    let offset = u64::from(claim.action() == CredentialOperationAction::Revoke);
    let head_matches = if claim.action() == CredentialOperationAction::LegacySourceCleanup {
        let operation = super::rows::snapshot(transaction, claim.operation_id(), authority)?;
        let head = super::rows::load_head(transaction, operation.provider())?
            .ok_or(CredentialLifecycleError::CorruptState)?;
        operation.metadata().legacy_cleanup_binding().is_some()
            && !head.hard_fenced
            && head.lifecycle == lifecycle
            && head.fence == fence
            && lifecycle >= claim.expected_lifecycle_revision().get() as i64
            && fence >= claim.expected_prior_fence().get() as i64
    } else {
        u64::try_from(lifecycle).ok()
            == claim
                .expected_lifecycle_revision()
                .get()
                .checked_add(offset)
            && u64::try_from(fence).ok() == claim.expected_prior_fence().get().checked_add(offset)
    };
    if state != "ACCEPTED"
        || proof != claim.continuation_binding_digest().as_bytes()
        || owner != claim.installation_owner_id().as_bytes()
        || u64::try_from(database).ok() != Some(claim.database_generation())
        || u64::try_from(supervisor).ok() != Some(claim.desktop_supervisor_generation())
        || !head_matches
        || claim.issued_at_high_water() < issued
        || claim.expires_at_high_water() > expires
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    if now < issued || now >= expires {
        return Err(CredentialLifecycleError::StaleLease);
    }
    authority
        .validate_cleanup_claim_context(claim, digest(release)?, digest(session)?)
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    let changed = transaction
        .execute(
            "UPDATE credential_cleanup_recovery_attempts
         SET state='CONSUMED', terminal_digest=continuation_digest
         WHERE operation_id=?1 AND continuation_digest=?2 AND state='ACCEPTED'",
            params![
                claim.operation_id().as_bytes().as_slice(),
                claim.continuation_binding_digest().as_bytes().as_slice()
            ],
        )
        .map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    Ok(())
}

fn digest(bytes: Vec<u8>) -> Result<CredentialBindingDigest, CredentialLifecycleError> {
    CredentialBindingDigest::from_measured(
        bytes
            .try_into()
            .map_err(|_| CredentialLifecycleError::CorruptState)?,
    )
    .map_err(|_| CredentialLifecycleError::CorruptState)
}
