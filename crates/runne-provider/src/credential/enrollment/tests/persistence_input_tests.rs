use runne_domain::id::{CommandId, IdempotencyKey};

use super::super::{
    BeginCredentialOperation, BeginCredentialVerification, BindCredentialReadback,
    ClaimCredentialOperation, CompleteCredentialOperation, CompleteCredentialVerification,
    CredentialBindingDigest, CredentialFence, CredentialLifecycleRevision,
    CredentialNativeEffectDisposition, CredentialOperationAction, CredentialOperationId,
    CredentialReadbackDisposition, CredentialReadinessDisposition, CredentialReadinessObservation,
    CredentialReadinessRevision, CredentialTicketAttempt, CredentialVerificationKind,
    CredentialVerificationObservation, CredentialVerificationResult, CredentialVerifierRevision,
    FailCredentialOperation, IssueCredentialTicketDigest, ObserveNativeEffect,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn credential_enrollment_persistence_inputs_carry_replay_and_claim_digests() {
    let provider = ProviderId::new("openai").unwrap();
    let version = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let operation_id = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let command_id = CommandId::from_bytes([2; 16]);
    let idempotency_key = IdempotencyKey::new("credential-pair-1").unwrap();
    let revision = CredentialLifecycleRevision::new(1).unwrap();
    let fence = CredentialFence::new(1).unwrap();
    let begin_proof = digest(3);
    let ticket_digest = digest(4);
    let continuation_digest = digest(5);
    let claim_digest = digest(6);

    let begin = BeginCredentialOperation::new(
        command_id,
        idempotency_key,
        operation_id,
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(version.clone()),
        revision,
        fence,
        begin_proof,
    )
    .unwrap();
    assert_eq!(begin.command_id(), command_id);
    assert_eq!(begin.idempotency_key().as_str(), "credential-pair-1");
    assert_eq!(begin.begin_proof_digest(), begin_proof);
    assert_eq!(begin.allocated_credential_version(), Some(&version));
    assert!(
        BeginCredentialOperation::new(
            command_id,
            IdempotencyKey::new("credential-migrate-1").unwrap(),
            operation_id,
            provider.clone(),
            CredentialOperationAction::MigrateLegacy,
            Some(version.clone()),
            revision,
            fence,
            begin_proof,
        )
        .is_ok()
    );

    let ticket = IssueCredentialTicketDigest::new(
        operation_id,
        CredentialTicketAttempt::new(1).unwrap(),
        ticket_digest,
        continuation_digest,
        10,
        20,
    )
    .unwrap();
    assert_eq!(ticket.continuation_binding_digest(), continuation_digest);

    let claim = ClaimCredentialOperation::new(
        operation_id,
        ticket.ticket_attempt(),
        ticket.ticket_digest(),
        ticket.continuation_binding_digest(),
        claim_digest,
        provider,
        CredentialOperationAction::Pair,
        Some(version),
        revision,
        fence,
        1,
        1,
        10,
        20,
    )
    .unwrap();
    assert_eq!(claim.continuation_binding_digest(), continuation_digest);
    assert_eq!(claim.process_release_binding_digest(), claim_digest);
}

#[test]
fn credential_enrollment_persistence_inputs_are_safe_and_exact() {
    let provider = ProviderId::new("openai").unwrap();
    let operation_id = CredentialOperationId::from_bytes([7; 16]).unwrap();
    let revision = CredentialLifecycleRevision::new(1).unwrap();
    let fence = CredentialFence::new(1).unwrap();
    let absence = digest(8);
    let release_tuple = digest(9);

    let effect = ObserveNativeEffect::new(
        operation_id,
        CredentialNativeEffectDisposition::PossibleEffect,
    );
    assert_eq!(
        effect.disposition(),
        CredentialNativeEffectDisposition::PossibleEffect
    );
    let readback = BindCredentialReadback::new(
        operation_id,
        CredentialReadbackDisposition::ExactAbsence,
        absence,
    )
    .unwrap();
    assert_eq!(
        readback.disposition(),
        CredentialReadbackDisposition::ExactAbsence
    );
    assert_eq!(readback.observation_digest(), absence);
    assert_eq!(
        FailCredentialOperation::new(operation_id, absence).absence_digest(),
        absence
    );

    let verification_id = CredentialOperationId::from_bytes([19; 16]).unwrap();
    let begin = BeginCredentialVerification::new(
        verification_id,
        Some(operation_id),
        provider.clone(),
        CredentialVerificationKind::Local,
        revision,
        fence,
        digest(10),
        CredentialVerifierRevision::new(1).unwrap(),
        30,
        40,
    )
    .unwrap();
    assert_eq!(begin.kind(), CredentialVerificationKind::Local);
    assert_eq!(begin.intent_proof_digest(), digest(10));
    let observation = CredentialVerificationObservation::new(
        verification_id,
        CredentialVerificationResult::Verified,
        35,
    )
    .unwrap();
    let complete = CompleteCredentialVerification::new(observation, revision, fence);
    assert_eq!(
        complete.observation().result(),
        CredentialVerificationResult::Verified
    );

    let readiness = CredentialReadinessObservation::new(
        CredentialOperationId::from_bytes([20; 16]).unwrap(),
        Some(operation_id),
        provider,
        revision,
        CredentialReadinessRevision::new(1).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(digest(11)),
        release_tuple,
        50,
    )
    .unwrap();
    let completion = CompleteCredentialOperation::new(operation_id, readback, revision, fence)
        .unwrap()
        .with_readiness_observation(readiness);
    assert!(completion.readiness_observation().is_some());
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
