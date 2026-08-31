use super::super::*;
use crate::{CredentialInstallationOwnerId, CredentialVersionRef, ProviderId};
use runne_domain::id::{CommandId, IdempotencyKey};

#[test]
fn credential_enrollment_review_canonical_inputs_validate_closed_boundaries() {
    let provider = ProviderId::new("openai").unwrap();
    let version = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let operation_id = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let revision = CredentialLifecycleRevision::new(1).unwrap();
    let fence = CredentialFence::new(1).unwrap();
    let digest = CredentialBindingDigest::from_measured([2; 32]).unwrap();

    assert!(
        BeginCredentialOperation::new(
            command(1),
            key("pair"),
            operation_id,
            owner(),
            provider.clone(),
            CredentialOperationAction::Pair,
            Some(version.clone()),
            None,
            revision,
            fence,
            digest,
            1,
        )
        .is_ok()
    );
    assert!(
        BeginCredentialOperation::new(
            command(2),
            key("cleanup"),
            operation_id,
            owner(),
            provider.clone(),
            CredentialOperationAction::RetiredVersionCleanup,
            Some(version.clone()),
            None,
            revision,
            fence,
            digest,
            1,
        )
        .is_err()
    );
    assert!(
        ClosePreparedCredentialOperation::new(operation_id, CredentialOperationState::Cancelled)
            .is_ok()
    );
    assert!(
        ClosePreparedCredentialOperation::new(operation_id, CredentialOperationState::Completed)
            .is_err()
    );
    assert!(
        BindCredentialReadback::new(
            operation_id,
            CredentialReadbackDisposition::ExactVersion,
            digest,
        )
        .is_ok()
    );
    assert!(
        HardFenceProvider::new(provider.clone(), fence, CredentialFence::new(2).unwrap()).is_ok()
    );
    assert!(HardFenceProvider::new(provider, CredentialFence::new(2).unwrap(), fence).is_err());
}

#[test]
fn credential_enrollment_review_canonical_snapshots_and_verification_are_immutable() {
    let provider = ProviderId::new("openai").unwrap();
    let version = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let operation_id = CredentialOperationId::from_bytes([3; 16]).unwrap();
    let revision = CredentialLifecycleRevision::new(1).unwrap();
    let fence = CredentialFence::new(1).unwrap();
    let digest = CredentialBindingDigest::from_measured([4; 32]).unwrap();
    let readback = BindCredentialReadback::new(
        operation_id,
        CredentialReadbackDisposition::ExactVersion,
        digest,
    )
    .unwrap();
    let observe = ObserveNativeEffect::new(
        operation_id,
        CredentialNativeEffectDisposition::PossibleEffect,
    );
    assert_eq!(observe.operation_id(), operation_id);
    let complete =
        CompleteCredentialOperation::new(operation_id, readback, revision, fence).unwrap();
    assert_eq!(complete.operation_id(), operation_id);
    assert_eq!(
        FailCredentialOperation::new(operation_id, digest).operation_id(),
        operation_id
    );
    assert!(
        TombstoneCredentialOperation::new(operation_id, CredentialOperationState::Completed)
            .is_ok()
    );

    let snapshot = CredentialOperationSnapshot::new(
        operation_id,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialOperationState::Claimed,
        Some(version.clone()),
        None,
        metadata(3, revision, fence, digest).with_claim(digest, digest),
    )
    .unwrap();
    assert_eq!(snapshot.operation_id(), operation_id);
    assert!(CredentialRecoveryWork::new(snapshot.clone()).is_ok());
    let lifecycle = CredentialLifecycleSnapshot::new(
        provider.clone(),
        Some(version),
        revision,
        fence,
        CredentialReadinessRevision::new(1).unwrap(),
        2,
    )
    .unwrap();
    assert_eq!(lifecycle.provider(), &provider);

    let begin = BeginCredentialVerification::new(
        CredentialOperationId::from_bytes([8; 16]).unwrap(),
        Some(operation_id),
        provider.clone(),
        CredentialVerificationKind::Local,
        revision,
        fence,
        CredentialReadinessRevision::new(1).unwrap(),
        CredentialBindingDigest::from_measured([3; 32]).unwrap(),
        digest,
        CredentialVerifierRevision::new(1).unwrap(),
        1,
        100,
    )
    .unwrap();
    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let lease = store.issue_credential_verification_lease(
        begin,
        CredentialVersionRef::new(provider.clone(), 1).unwrap(),
    );
    let capability = measurements
        .issue_credential_verification_capability(lease, digest)
        .unwrap();
    let observation = CredentialVerificationObservation::new(
        CredentialOperationId::from_bytes([8; 16]).unwrap(),
        CredentialVerificationResult::Verified,
        10,
    )
    .unwrap();
    let completed = CompleteCredentialVerification::new(observation, revision, fence);
    assert_eq!(capability.operation_id(), Some(operation_id));
    assert_eq!(
        completed.observation_id(),
        CredentialOperationId::from_bytes([8; 16]).unwrap()
    );
}

#[test]
fn credential_enrollment_review_ticket_issue_and_operation_commands_are_safe() {
    let operation_id = CredentialOperationId::from_bytes([5; 16]).unwrap();
    let ticket = CredentialBindingDigest::from_measured([6; 32]).unwrap();
    let continuation = CredentialBindingDigest::from_measured([7; 32]).unwrap();
    let issued = IssueCredentialTicketDigest::new(operation_id, ticket, continuation, 10).unwrap();
    assert_eq!(issued.operation_id(), operation_id);
    assert!(IssueCredentialTicketDigest::new(operation_id, ticket, continuation, 0).is_err());
}

fn command(value: u8) -> CommandId {
    CommandId::from_bytes([value; 16])
}

fn key(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).unwrap()
}

fn metadata(
    value: u8,
    revision: CredentialLifecycleRevision,
    fence: CredentialFence,
    digest: CredentialBindingDigest,
) -> CredentialOperationMetadata {
    CredentialOperationMetadata::new(
        command(value),
        key("snapshot"),
        owner(),
        revision,
        fence,
        digest,
        1,
        1,
    )
    .unwrap()
}

fn owner() -> CredentialInstallationOwnerId {
    CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap()
}
