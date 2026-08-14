//! Trusted-context admission for prevalidated receipt `/5` values.

use crate::{
    AuthorityError, PrevalidatedPromotionAuthorityReceiptV5, ReceiptV5AdmissionScope,
    ReceiptV5Validity, ReceiptV5VerificationContext, VerifiedPromotionBootstrapV5,
    receipt_v5::ReceiptV5Bindings,
};
use sha2::{Digest, Sha256};

/// Admit one cryptographically prevalidated receipt through the trusted backend.
///
/// # Errors
/// Returns an admission error when the configured store profile or durable
/// recovery scope differs from the prevalidated immutable receipt closure.
pub fn admit_prevalidated_promotion_authority_receipt_v5(
    prevalidated: PrevalidatedPromotionAuthorityReceiptV5,
    context: &dyn ReceiptV5VerificationContext,
) -> Result<VerifiedPromotionBootstrapV5, AuthorityError> {
    let value = prevalidated.unsigned;
    let scope = ReceiptV5AdmissionScope {
        receipt_sha256: prevalidated.receipt_sha256,
        trust_config_sha256: value.trust_config_sha256.clone(),
        trust_generation: value.trust_generation,
        predecessor_receipt_sha256: value.predecessor_receipt_sha256,
        authority_store_profile: value.authority_store_profile.clone(),
        root_key_id: value.key_id.clone(),
        root_key_epoch: value.key_epoch,
        root_principal_id: value.root_principal_id.clone(),
        root_controlling_account_id: value.root_controlling_account_id.clone(),
        root_lane_id: value.root_lane_id.clone(),
        root_signature_profile_id: value.root_signature_profile_id.clone(),
        root_public_key: prevalidated.root_public_key,
        root_revocation_epoch: value.revocation_epoch,
        subject: value.subject.clone(),
        production_security_review_sha256: value.production_security_review_sha256,
        destination_allowlist_sha256: value.destination_allowlist_sha256,
        destination_allowlist_generation: value.destination_allowlist_generation,
        role_scope_floors: crate::v5_state_validation::floors(
            &value.transition_delegations,
            &value.evidence_delegations,
        ),
        promotion_policy_sha256: value.promotion_policy_sha256,
        promotion_policy_revision: value.promotion_policy_revision.clone(),
        platform_qualified_subject_sha256: value.platform_qualified_subject_sha256,
        platform_matrix_sha256: value.platform_matrix_sha256,
        adr_0029_sha256: value.adr_0029_sha256,
        post_rc0_program_sha256: value.post_rc0_program_sha256,
        transition_delegations: value.transition_delegations.clone(),
        evidence_delegations: value.evidence_delegations.clone(),
    };
    if context.authority_store_profile()? != scope.authority_store_profile {
        return Err(AuthorityError::PromotionBootstrapAdmissionConflict);
    }
    let validity = ReceiptV5Validity {
        issued_at: value.issued_at.clone(),
        not_before: value.not_before.clone(),
        expires_at: value.expires_at.clone(),
    };
    let expected = context.read_authority_state()?;
    let phase = crate::v5_state_validation::receipt(&expected, &scope)?;
    let schema_sha256 = Sha256::digest(include_bytes!(
        "../../../docs/schemas/project-owner-authority-receipt-v5.schema.json"
    ))
    .into();
    let nonce = crate::trust_canonical::hex(&scope.receipt_sha256);
    let (promotion, revision, command, persisted) =
        crate::v5_admission_identity::identities(crate::v5_admission_identity::IdentityInput {
            receipt_sha256: scope.receipt_sha256,
            trust_config_sha256: &scope.trust_config_sha256,
            trust_generation: scope.trust_generation,
            receipt_generation: 5,
            allowlist_generation: scope.destination_allowlist_generation,
            payload_schema_id: crate::RECEIPT_SCHEMA_V5,
            payload_schema_sha256: schema_sha256,
            nonce: &nonce,
            envelope_sha256: scope.receipt_sha256,
            payload_sha256: scope.receipt_sha256,
        });
    let closure = ReceiptAdmissionClosure {
        scope: scope.clone(),
        validity,
        promotion,
        revision,
        command,
        persisted,
    };
    admit_or_recover(context, expected, phase, closure)?;
    Ok(mint_verified(
        prevalidated.receipt_sha256,
        prevalidated.root_public_key,
        value,
        scope,
    ))
}

struct ReceiptAdmissionClosure {
    scope: ReceiptV5AdmissionScope,
    validity: ReceiptV5Validity,
    promotion: crate::PromotionIdentity,
    revision: crate::RevisionIdentity,
    command: crate::CommandIdentity,
    persisted: crate::PersistedAdmission,
}

fn admit_or_recover(
    context: &dyn ReceiptV5VerificationContext,
    expected: crate::AuthorityStateSnapshot,
    phase: crate::v5_state_validation::ReceiptAdmissionPhase,
    closure: ReceiptAdmissionClosure,
) -> Result<(), AuthorityError> {
    let reservation = closure.persisted.reservation.clone();
    let outcome = closure.persisted.outcome.clone();
    match phase {
        crate::v5_state_validation::ReceiptAdmissionPhase::NewlyAdmitted => {
            let newly_admitted_state =
                crate::v5_state_validation::newly_admitted_state(&expected, 5)?;
            let result = context.admit_receipt_v5(&crate::ReceiptV5AdmissionRequest {
                expected,
                newly_admitted_state: newly_admitted_state.clone(),
                scope: closure.scope,
                validity: closure.validity,
                promotion: closure.promotion,
                revision: closure.revision,
                command: closure.command,
                reservation,
                outcome,
            })?;
            crate::v5_admission_result::receipt_new(
                &result,
                &closure.persisted,
                &newly_admitted_state,
            )
        }
        crate::v5_state_validation::ReceiptAdmissionPhase::ExistingSame => {
            let result = context.recover_receipt_v5(&crate::ReceiptV5RecoveryRequest {
                expected: expected.clone(),
                scope: closure.scope,
                validity: closure.validity,
                promotion: closure.promotion,
                revision: closure.revision,
                command: closure.command,
                reservation,
                outcome,
            })?;
            crate::v5_admission_result::receipt_existing(&result, &closure.persisted, &expected)
        }
    }
}

fn mint_verified(
    receipt_sha256: [u8; 32],
    root_public_key: [u8; 32],
    value: crate::PromotionAuthorityReceiptV5,
    scope: ReceiptV5AdmissionScope,
) -> VerifiedPromotionBootstrapV5 {
    crate::receipt_v5::verified_receipt_v5(
        receipt_sha256,
        value.transition_delegations,
        value.evidence_delegations,
        root_public_key,
        crate::VerifiedStageIssuer {
            principal: value.root_principal_id.clone(),
            account: value.root_controlling_account_id.clone(),
            lane: value.root_lane_id.clone(),
            key: value.key_id.clone(),
            signature_profile: value.root_signature_profile_id.clone(),
        },
        value.revocation_epoch,
        ReceiptV5Bindings {
            trust_config_sha256: scope.trust_config_sha256,
            trust_generation: scope.trust_generation,
            subject_sha256: value.platform_qualified_subject_sha256,
            matrix_sha256: value.platform_matrix_sha256,
            policy_sha256: value.promotion_policy_sha256,
            policy_revision: value.promotion_policy_revision,
            destination_allowlist_sha256: value.destination_allowlist_sha256,
            destination_allowlist_generation: value.destination_allowlist_generation,
            production_security_review_sha256: value.production_security_review_sha256,
            subject: value.subject,
        },
    )
}
