use crate::provider::execution_store::online_effect_proof::{
    IssuanceProofFields, OnlineEffectProofCapabilitySet,
};
use runne_application::provider::{ProviderAdmissionError, ProviderJournalKeyBinding};
use runne_provider::ProviderDispatchClaim;
use rusqlite::{OptionalExtension, Transaction, params};

pub(super) struct VerifiedIssuanceProof {
    pub(super) binding: ProviderJournalKeyBinding,
    pub(super) mac: [u8; 32],
}

pub(super) fn verify_issuance(
    transaction: &Transaction<'_>,
    claim: &ProviderDispatchClaim,
    proof: &OnlineEffectProofCapabilitySet,
) -> Result<VerifiedIssuanceProof, ProviderAdmissionError> {
    let row = transaction
        .query_row(
            "SELECT evidence.proof_version, evidence.journal_key_id,
                    evidence.journal_key_version, evidence.journal_runtime_authority_id,
                    evidence.journal_database_generation, evidence.issuance_mac,
                    admission.runtime_authority_id, admission.database_generation,
                    evidence.provider_id, admission.provider_idempotency_key,
                    admission.call_id, admission.dispatch_attempt_id, admission.authority_id,
                    admission.authority_revision, admission.semantic_digest, admission.permit_id,
                    admission.token_reservation_id, admission.cost_reservation_id,
                    admission.generation, admission.fencing_token, admission.prepared_digest,
                    admission.render_digest, admission.profile_digest,
                    admission.pricing_revision_digest, admission.issued_at, admission.expires_at
               FROM provider_online_dispatch_issuance_evidence evidence
               JOIN provider_execution_admissions admission
                 ON admission.dispatch_attempt_id=evidence.dispatch_attempt_id
                AND admission.authority_id=evidence.authority_id
                AND admission.authority_revision=evidence.authority_revision
                AND admission.issued_at=evidence.issued_at
              WHERE evidence.dispatch_attempt_id=?1 AND evidence.provider_id=?2",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.provider_id.as_str()
            ],
            |row| {
                let binding = ProviderJournalKeyBinding::new(
                    proof_array(row, 1)?,
                    proof_u64(row, 2)?,
                    proof_array(row, 3)?,
                    proof_u64(row, 4)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let mac = proof_array(row, 5)?;
                Ok((
                    IssuanceProofFields {
                        proof_version: proof_u64(row, 0)?,
                        key: binding,
                        runtime_authority_id: proof_array(row, 6)?,
                        database_generation: proof_u64(row, 7)?,
                        provider_id: row.get(8)?,
                        provider_idempotency_key: row.get(9)?,
                        call_id: proof_array(row, 10)?,
                        attempt_id: proof_array(row, 11)?,
                        authority_id: proof_array(row, 12)?,
                        authority_revision: proof_u64(row, 13)?,
                        semantic_digest: proof_array(row, 14)?,
                        permit_id: proof_array(row, 15)?,
                        token_reservation_id: proof_array(row, 16)?,
                        cost_reservation_id: proof_array(row, 17)?,
                        generation: proof_u64(row, 18)?,
                        fencing_token: proof_u64(row, 19)?,
                        prepared_digest: proof_array(row, 20)?,
                        render_digest: proof_array(row, 21)?,
                        profile_digest: proof_array(row, 22)?,
                        pricing_revision_digest: proof_array(row, 23)?,
                        issued_at: row.get(24)?,
                        expires_at: row.get(25)?,
                    },
                    binding,
                    mac,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
        .ok_or(ProviderAdmissionError::AuthorityDenied)?;
    let (fields, binding, mac) = row;
    if !proof.verify_issue(&fields, &mac) {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    Ok(VerifiedIssuanceProof { binding, mac })
}

fn proof_array<const N: usize>(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<[u8; N]> {
    row.get::<_, Vec<u8>>(index)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn proof_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(index)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
