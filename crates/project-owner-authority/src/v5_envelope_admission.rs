//! Trusted-context admission for prevalidated V5 envelopes and allowlists.

use sha2::{Digest, Sha256};

use crate::{
    AuthorityError, DestinationAllowlistVerificationContext, PrevalidatedDestinationAllowlistV1,
    PrevalidatedEvidenceEnvelopeV2, PrevalidatedStageEnvelopeV2, V5EnvelopeVerificationContext,
    VerifiedDestinationAllowlist, VerifiedEvidenceEnvelopeV2, VerifiedStageEnvelopeV2,
};

/// Admit a cryptographically prevalidated stage envelope.
///
/// # Errors
/// Returns an error when the trusted backend rejects the immutable request.
pub fn admit_prevalidated_stage_envelope_v2(
    value: PrevalidatedStageEnvelopeV2,
    context: &dyn V5EnvelopeVerificationContext,
) -> Result<VerifiedStageEnvelopeV2, AuthorityError> {
    let expected = context.read_authority_state()?;
    crate::v5_state_validation::envelope(&expected, &value.scope)?;
    let newly_admitted_state = crate::v5_state_validation::newly_admitted_state(&expected, 5)?;
    let (promotion, revision, command, persisted) = envelope_identities(&value.scope);
    let result = context.admit_or_recover_stage(&crate::StageEnvelopeAdmissionRequest {
        expected: expected.clone(),
        newly_admitted_state: newly_admitted_state.clone(),
        scope: value.scope.clone(),
        promotion,
        revision,
        command,
        reservation: persisted.reservation.clone(),
        outcome: persisted.outcome.clone(),
    })?;
    require_exact(&result, &persisted, &expected, &newly_admitted_state)?;
    Ok(crate::stage_envelope_v2::verified_stage_envelope_v2(
        value.envelope_sha256,
        value.receipt_sha256,
        value.payload_sha256,
        value.payload_schema_id,
        value.payload,
        value.issuer,
        value.validity,
    ))
}

/// Admit a cryptographically prevalidated evidence envelope.
///
/// # Errors
/// Returns an error when the trusted backend rejects the immutable request.
pub fn admit_prevalidated_evidence_envelope_v2(
    value: PrevalidatedEvidenceEnvelopeV2,
    context: &dyn V5EnvelopeVerificationContext,
) -> Result<VerifiedEvidenceEnvelopeV2, AuthorityError> {
    let expected = context.read_authority_state()?;
    crate::v5_state_validation::envelope(&expected, &value.scope)?;
    let newly_admitted_state = crate::v5_state_validation::newly_admitted_state(&expected, 5)?;
    let (promotion, revision, command, persisted) = envelope_identities(&value.scope);
    let result = context.admit_or_recover_evidence(&crate::EvidenceEnvelopeAdmissionRequest {
        expected: expected.clone(),
        newly_admitted_state: newly_admitted_state.clone(),
        scope: value.scope.clone(),
        promotion,
        revision,
        command,
        reservation: persisted.reservation.clone(),
        outcome: persisted.outcome.clone(),
    })?;
    require_exact(&result, &persisted, &expected, &newly_admitted_state)?;
    Ok(crate::evidence_envelope_v2::verified_evidence_envelope_v2(
        value.envelope_sha256,
        value.receipt_sha256,
        value.validity.trust_generation,
        value.payload_sha256,
        value.payload_schema_id,
        value.payload,
        value.issuer,
        value.validity,
    ))
}

/// Admit a cryptographically prevalidated root-signed destination allowlist.
///
/// # Errors
/// Returns an error when the trusted backend rejects the immutable request.
pub fn admit_prevalidated_destination_allowlist_v1(
    value: PrevalidatedDestinationAllowlistV1,
    context: &dyn DestinationAllowlistVerificationContext,
) -> Result<VerifiedDestinationAllowlist, AuthorityError> {
    let expected = context.read_authority_state()?;
    crate::v5_state_validation::allowlist(&expected, &value.scope)?;
    let newly_admitted_state = crate::v5_state_validation::newly_admitted_state(&expected, 5)?;
    let (promotion, revision, command, persisted) = crate::v5_admission_identity::identities(
        crate::v5_admission_identity::IdentityInput {
            receipt_sha256: value.scope.receipt_sha256,
            trust_config_sha256: &value.scope.trust_config_sha256,
            trust_generation: value.scope.trust_generation,
            receipt_generation: 5,
            allowlist_generation: value.scope.generation,
            payload_schema_id: crate::DESTINATION_ALLOWLIST_SCHEMA_V1,
            payload_schema_sha256: Sha256::digest(include_bytes!(
                "../../../docs/schemas/project-owner-publication-destination-allowlist-v1.schema.json"
            ))
            .into(),
            nonce: &value.scope.policy_id,
            envelope_sha256: value.scope.allowlist_sha256,
            payload_sha256: value.scope.unsigned_sha256,
        },
    );
    let result =
        context.admit_or_recover_allowlist(&crate::DestinationAllowlistAdmissionRequest {
            expected: expected.clone(),
            newly_admitted_state: newly_admitted_state.clone(),
            scope: value.scope.clone(),
            promotion,
            revision,
            command,
            reservation: persisted.reservation.clone(),
            outcome: persisted.outcome.clone(),
        })?;
    require_exact(&result, &persisted, &expected, &newly_admitted_state)?;
    Ok(
        crate::destination_allowlist::verified_destination_allowlist(
            value.digest,
            value.value.generation,
            value.value.destinations,
            value.value.issued_at,
            value.value.not_before,
            value.value.expires_at,
            value.value.revocation_epoch,
            value.value.key_id,
            value.value.key_epoch,
            value.value.policy_id,
        ),
    )
}

fn envelope_identities(
    scope: &crate::V5AdmissionScope,
) -> (
    crate::PromotionIdentity,
    crate::RevisionIdentity,
    crate::CommandIdentity,
    crate::PersistedAdmission,
) {
    crate::v5_admission_identity::identities(crate::v5_admission_identity::IdentityInput {
        receipt_sha256: scope.receipt_sha256,
        trust_config_sha256: &scope.trust_config_sha256,
        trust_generation: scope.trust_generation,
        receipt_generation: 5,
        allowlist_generation: scope.destination_allowlist_generation,
        payload_schema_id: &scope.payload_schema_id,
        payload_schema_sha256: scope.payload_schema_sha256,
        nonce: &scope.nonce,
        envelope_sha256: scope.envelope_sha256,
        payload_sha256: scope.payload_sha256,
    })
}

fn require_exact(
    result: &crate::DurableAdmission,
    expected: &crate::PersistedAdmission,
    expected_state: &crate::AuthorityStateSnapshot,
    newly_admitted_state: &crate::AuthorityStateSnapshot,
) -> Result<(), AuthorityError> {
    crate::v5_admission_result::unchanged_generations(
        result,
        expected,
        expected_state,
        newly_admitted_state,
    )
}
