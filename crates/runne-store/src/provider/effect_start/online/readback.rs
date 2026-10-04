use super::super::online_receipt::{OnlineEffectReadback, ProviderOnlineEffectStartReceipt};
use crate::provider::execution_store::online_effect_proof::{
    CommittedEffectProofFields, OnlineEffectProofCapabilitySet,
};
use runne_application::provider::{ProviderAdmissionError, ProviderJournalKeyBinding};
use runne_provider::ProviderDispatchClaim;
use rusqlite::{Connection, OptionalExtension, params};

pub(super) fn load(
    connection: &Connection,
    claim: &ProviderDispatchClaim,
    proof: &OnlineEffectProofCapabilitySet,
    observed: i64,
    expires: i64,
    now: impl Fn() -> i64,
) -> Result<ProviderOnlineEffectStartReceipt, ProviderAdmissionError> {
    connection.query_row(
        "SELECT binding.dispatch_attempt_id, binding.provider_id, binding.launch_generation, binding.lifecycle_revision,
                binding.credential_fence, binding.active_credential_version, binding.active_ref_digest,
                effect.effect_started_at, effect.effect_expires_at, admission.permit_id, admission.provider_idempotency_key,
                admission.prepared_digest, admission.render_digest, admission.profile_digest,
                admission.fencing_token, admission.token_reservation_id, admission.cost_reservation_id,
                version.lease_owner, version.lease_expires_at, version.lease_fencing_token, binding.effect_mac,
                evidence.journal_key_id, evidence.journal_key_version,
                evidence.journal_runtime_authority_id, evidence.journal_database_generation,
                evidence.issuance_mac
           FROM provider_effect_starts effect
           JOIN provider_online_credential_effect_bindings binding ON binding.dispatch_attempt_id=effect.dispatch_attempt_id
           JOIN provider_execution_admissions admission ON admission.dispatch_attempt_id=effect.dispatch_attempt_id
           JOIN provider_online_dispatch_issuance_evidence evidence
             ON evidence.dispatch_attempt_id=effect.dispatch_attempt_id
            AND evidence.provider_id=binding.provider_id
           JOIN provider_credential_versions version ON version.provider_id=binding.provider_id
             AND version.credential_version=binding.active_credential_version AND version.ref_digest=binding.active_ref_digest
          WHERE effect.dispatch_attempt_id=?1 AND effect.permit_id=?2 AND effect.effect_started_at=?3
            AND effect.effect_expires_at=?4 AND effect.state=1",
        params![claim.attempt_id.as_bytes().as_slice(), claim.permit_id.as_slice(), observed, expires],
        |row| {
            let attempt_id: Vec<u8> = row.get(0)?;
            let attempt_id: [u8; 16] = attempt_id
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let fixed = |index| -> rusqlite::Result<[u8; 16]> {
                row.get::<_, Vec<u8>>(index)?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
            };
            let digest = |index| -> rusqlite::Result<[u8; 32]> {
                row.get::<_, Vec<u8>>(index)?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
            };
            Ok(OnlineEffectReadback {
                attempt_id,
                provider: row.get(1)?,
                launch_generation: u64::try_from(row.get::<_, i64>(2)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                lifecycle_revision: u64::try_from(row.get::<_, i64>(3)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                credential_fence: u64::try_from(row.get::<_, i64>(4)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                credential_version: u64::try_from(row.get::<_, i64>(5)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                ref_digest: digest(6)?,
                effect_started_at: row.get(7)?,
                effect_expires_at: row.get(8)?,
                permit_id: fixed(9)?,
                idempotency_key: row.get(10)?,
                prepared_digest: digest(11)?,
                render_digest: digest(12)?,
                profile_digest: digest(13)?,
                dispatch_fence: u64::try_from(row.get::<_, i64>(14)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                token_reservation_id: fixed(15)?,
                cost_reservation_id: fixed(16)?,
                lease_owner: fixed(17)?,
                lease_expires_at: row.get(18)?,
                lease_fence: u64::try_from(row.get::<_, i64>(19)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                effect_mac: digest(20)?,
                proof_binding: ProviderJournalKeyBinding::new(
                    fixed(21)?,
                    u64::try_from(row.get::<_, i64>(22)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    fixed(23)?,
                    u64::try_from(row.get::<_, i64>(24)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                ).map_err(|_| rusqlite::Error::InvalidQuery)?,
                issuance_mac: digest(25)?,
            })
        },
    )
    .optional()
    .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?
    .ok_or(ProviderAdmissionError::PostClaimUncertain)
    .and_then(|readback| {
        let fields = CommittedEffectProofFields {
            issuance_mac: readback.issuance_mac,
            attempt_id: readback.attempt_id,
            provider_id: readback.provider.clone(),
            launch_generation: readback.launch_generation,
            lifecycle_revision: readback.lifecycle_revision,
            credential_fence: readback.credential_fence,
            credential_version: readback.credential_version,
            credential_ref_digest: readback.ref_digest,
            lease_owner: readback.lease_owner,
            lease_expires_at: readback.lease_expires_at,
            lease_fence: readback.lease_fence,
            effect_started_at: readback.effect_started_at,
            effect_expires_at: readback.effect_expires_at,
        };
        if !proof.verify_effect(readback.proof_binding, &fields, &readback.effect_mac) {
            return Err(ProviderAdmissionError::PostClaimUncertain);
        }
        let effective_now = now().max(readback.effect_started_at);
        let remaining = readback
            .effect_expires_at
            .saturating_sub(effective_now)
            .max(0);
        let remaining = u64::try_from(remaining)
            .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?
            .min(120);
        if remaining == 0 {
            return Err(ProviderAdmissionError::PostClaimUncertain);
        }
        Ok(ProviderOnlineEffectStartReceipt::from_readback(readback, remaining))
    })
}

pub(super) fn verify_final_send(
    connection: &Connection,
    claim: &ProviderDispatchClaim,
    proof: &OnlineEffectProofCapabilitySet,
    observed: i64,
) -> Result<(), ProviderAdmissionError> {
    let times: Option<(i64, i64)> = connection
        .query_row(
            "SELECT effect_started_at, effect_expires_at FROM provider_effect_starts
             WHERE dispatch_attempt_id=?1 AND permit_id=?2 AND state=1",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.permit_id.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    let (started, expires) = times.ok_or(ProviderAdmissionError::AuthorityDenied)?;
    let receipt = load(connection, claim, proof, started, expires, || observed)?;
    if receipt.into_effect_receipt().matches_claim(claim) {
        Ok(())
    } else {
        Err(ProviderAdmissionError::AuthorityDenied)
    }
}
