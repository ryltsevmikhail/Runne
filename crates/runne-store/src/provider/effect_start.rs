use runne_application::provider::ProviderAdmissionError;
use std::time::{Duration, Instant};

use super::CredentialDispatchBinding;
use crate::schema::ManagedConnection;
use runne_provider::ProviderDispatchClaim;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

include!("effect_start/receipt.rs");
mod online;
mod online_helpers;
mod online_proof;
mod online_receipt;
mod profile_check;
#[cfg(test)]
mod receipt_tests;

pub(super) use online::start_online_effect;
pub(crate) use online_proof::verify_historical_issuance;
pub(crate) use online_receipt::ProviderOnlineEffectStartReceipt;

pub(crate) fn verify_legacy_final_send(
    transaction: &rusqlite::Transaction<'_>,
    claim: &ProviderDispatchClaim,
    credential: &CredentialDispatchBinding,
    observed: i64,
) -> Result<(), ProviderAdmissionError> {
    if profile_check::verify_effect_authority(transaction, claim, credential, observed)? {
        Ok(())
    } else {
        Err(ProviderAdmissionError::AuthorityDenied)
    }
}

pub(crate) fn verify_online_final_send(
    transaction: &rusqlite::Transaction<'_>,
    claim: &ProviderDispatchClaim,
    proof_state: &super::execution_store::online_effect_proof::OnlineEffectProofState,
    observed: i64,
) -> Result<(), ProviderAdmissionError> {
    let proof = proof_state.lock()?;
    let proof = proof
        .as_ref()
        .ok_or(ProviderAdmissionError::AuthorityDenied)?;
    proof.ensure_current_active(transaction)?;
    online::verify_final_send(transaction, claim, proof, observed)
}

pub(super) fn start_effect(
    connection: &mut ManagedConnection,
    claim: &ProviderDispatchClaim,
    credential: &CredentialDispatchBinding,
    now: impl Fn() -> i64,
    before_receipt_lock: impl FnOnce(),
    fail_readback: bool,
) -> Result<ProviderEffectStartReceipt, ProviderAdmissionError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    crate::store::taskrun_provider_start::verify_admitted_running_attempt(
        &transaction,
        claim.attempt_id.as_bytes(),
    )
    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
    let wall_before = now();
    if super::credential_lifecycle::advance_provider_clock(
        &transaction,
        credential.version_ref().provider(),
        wall_before,
    )
    .is_err()
    {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    if !profile_check::verify_effect_authority(&transaction, claim, credential, wall_before)? {
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    let effect_started_at = now();
    if super::credential_lifecycle::advance_provider_clock(
        &transaction,
        credential.version_ref().provider(),
        effect_started_at,
    )
    .is_err()
    {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    if credential.expires_at() <= effect_started_at {
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    let Some(expires_at) = effect_started_at.checked_add(120) else {
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        return Err(ProviderAdmissionError::AuthorityDenied);
    };
    let changed = transaction
        .execute(
            "INSERT INTO provider_effect_starts (
             dispatch_attempt_id, provider_idempotency_key, permit_id,
             effect_started_at, effect_expires_at, state
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.provider_idempotency_key,
                claim.permit_id.as_slice(),
                effect_started_at,
                expires_at
            ],
        )
        .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
    if changed != 1 {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    transaction
        .execute(
            "INSERT INTO provider_credential_effect_bindings (
                dispatch_attempt_id, provider_id, credential_version, ref_digest,
                lease_owner, lease_expires_at, lease_fencing_token
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                credential.version_ref().provider().as_str(),
                i64::try_from(credential.version_ref().version())
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                credential.version_ref().ref_digest().as_slice(),
                credential.owner().as_slice(),
                credential.expires_at(),
                i64::try_from(credential.fencing_token())
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            ],
        )
        .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
    let intent_id = format!("provider:{}", encode_hex(claim.attempt_id.as_bytes()));
    transaction
        .execute(
            "INSERT INTO security_audit_pre_effect (intent_id, side_effect_started) VALUES (?1, 1)",
            [&intent_id],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    transaction
        .commit()
        .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
    if fail_readback {
        return Err(ProviderAdmissionError::PostClaimUncertain);
    }
    before_receipt_lock();
    let clock_transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
    let wall_after = now();
    super::credential_lifecycle::advance_provider_clock(
        &clock_transaction,
        credential.version_ref().provider(),
        wall_after,
    )
    .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
    clock_transaction
        .commit()
        .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
    if credential.expires_at() <= effect_started_at.max(wall_after) {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    connection
        .query_row(
            "SELECT effect_started_at, effect_expires_at FROM provider_effect_starts
             WHERE dispatch_attempt_id = ?1 AND permit_id = ?2 AND effect_started_at = ?3
           AND effect_expires_at = ?4 AND state = 1",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.permit_id.as_slice(),
                effect_started_at,
                expires_at
            ],
            |row| {
                let effective_wall = effect_started_at.max(wall_after).max(row.get::<_, i64>(0)?);
                let effect_expires_at = row.get::<_, i64>(1)?;
                let remaining = effect_expires_at
                    .checked_sub(effective_wall)
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                let remaining =
                    u64::try_from(remaining).map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(ProviderEffectStartReceipt {
                    expires_at: effect_expires_at,
                    attempt_id: *claim.attempt_id.as_bytes(),
                    permit_id: claim.permit_id,
                    provider_idempotency_key: claim.provider_idempotency_key.clone(),
                    prepared_digest: claim.prepared_digest,
                    render_digest: claim.render_digest,
                    profile_digest: claim.profile_digest,
                    fencing_token: claim.fencing_token,
                    token_reservation_id: claim.token_reservation_id,
                    cost_reservation_id: claim.cost_reservation_id,
                    deadline: Instant::now() + Duration::from_secs(remaining.min(120)),
                    credential_provider: credential.version_ref().provider().as_str().to_owned(),
                    credential_version: credential.version_ref().version(),
                    credential_ref_digest: *credential.version_ref().ref_digest(),
                    credential_owner: *credential.owner(),
                    credential_expires_at: credential.expires_at(),
                    credential_fencing_token: credential.fencing_token(),
                    final_send: None,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?
        .ok_or(ProviderAdmissionError::PostClaimUncertain)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            use core::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}
