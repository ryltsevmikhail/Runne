use runne_api::{
    ProviderCredentialBeginIntentBinding, ProviderCredentialEnrollmentActionV2,
    ProviderCredentialEnrollmentHostError, ProviderCredentialRequestAuthorityPair,
    ProviderCredentialRequestAuthorityVerifier,
};
use runne_provider::{
    BeginCredentialOperation, CredentialEnrollmentAuthorityPair, CredentialOperationAction,
};

use super::super::ProviderCredentialAdmission;
use super::begin_admission_support::{begin, context, lifecycle_snapshot};

#[test]
fn broker_claim_binding_rejects_a_foreign_transport_authority_before_admission() {
    let (_, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let (foreign_issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = foreign_issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let admission = admission(verifier);

    assert_eq!(
        admission.require_base(&authority),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn broker_claim_binding_rejects_a_foreign_intent_proof_before_admission() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let (foreign_issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let proof = foreign_issuer
        .issue_intent_proof([6; 32], [7; 32], [8; 32], [9; 32], 10)
        .unwrap();
    let admission = admission(verifier);

    admission.require_base(&authority).unwrap();
    assert_eq!(
        admission.require_intent(&proof),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn broker_claim_binding_rejects_a_session_substituted_intent_proof() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let proof = issuer
        .issue_intent_proof([6; 32], [7; 32], [8; 32], [9; 32], 10)
        .unwrap();
    let admission = admission(verifier);

    assert_eq!(
        admission.require_begin(&authority, &proof),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn broker_claim_binding_accepts_the_exact_protected_session() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let proof = issuer
        .issue_intent_proof([6; 32], [3; 32], [8; 32], [9; 32], 10)
        .unwrap();
    let admission = admission(verifier);

    admission.require_begin(&authority, &proof).unwrap();
}

#[test]
fn broker_claim_binding_rejects_another_begin_command_in_the_same_session() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let expected = begin(ProviderCredentialEnrollmentActionV2::Pair);
    let substituted = begin(ProviderCredentialEnrollmentActionV2::Revoke);
    let context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&substituted, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            10,
        )
        .unwrap();
    let admission = admission(verifier);

    assert_eq!(
        admission.require_begin_command(&authority, &proof, &expected, &context),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn daemon_begin_allocates_the_operation_id_and_authoritative_next_version() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = begin(ProviderCredentialEnrollmentActionV2::Pair);
    let context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            10,
        )
        .unwrap();
    let snapshot = lifecycle_snapshot();
    let admission = admission(verifier);

    let effect = admission
        .begin_input(&authority, &proof, &command, &context, snapshot)
        .unwrap();

    assert_eq!(effect.allocated_credential_version().unwrap().version(), 9);
}

#[test]
fn daemon_begin_keeps_bridge_seconds_proof_expiry_unchanged() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = begin(ProviderCredentialEnrollmentActionV2::Pair);
    let context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            1_900,
        )
        .unwrap();
    let admission = admission(verifier);

    let input: BeginCredentialOperation = admission
        .begin_input(&authority, &proof, &command, &context, lifecycle_snapshot())
        .unwrap();

    assert_eq!(input.begin_proof_expires_at_high_water(), 1_900);
}

#[test]
fn daemon_migrate_legacy_requires_and_mints_the_store_paired_authorization() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = begin(ProviderCredentialEnrollmentActionV2::MigrateLegacy);
    let context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            10,
        )
        .unwrap();
    let (legacy_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();

    let closed = admission(verifier.clone()).begin_input(
        &authority,
        &proof,
        &command,
        &context,
        lifecycle_snapshot(),
    );
    assert_eq!(
        closed,
        Err(ProviderCredentialEnrollmentHostError::Unsupported)
    );

    let input = ProviderCredentialAdmission::with_legacy_import_authority(
        verifier,
        measurements,
        legacy_authority,
    )
    .begin_input(&authority, &proof, &command, &context, lifecycle_snapshot())
    .unwrap();
    assert_eq!(input.action(), CredentialOperationAction::MigrateLegacy);
    assert!(input.legacy_import_authorization().is_some());
}

fn admission(verifier: ProviderCredentialRequestAuthorityVerifier) -> ProviderCredentialAdmission {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    ProviderCredentialAdmission::new(verifier, measurements)
}
