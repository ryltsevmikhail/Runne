use super::super::*;
use crate::{CredentialVersionRef, ProviderId};

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
            operation_id,
            provider.clone(),
            CredentialOperationAction::Pair,
            version.clone(),
            revision,
            fence
        )
        .is_ok()
    );
    assert!(
        BeginCredentialOperation::new(
            operation_id,
            provider.clone(),
            CredentialOperationAction::RetiredVersionCleanup,
            version.clone(),
            revision,
            fence
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
            CredentialTransitionEvidence::ExactVersionReadback(digest)
        )
        .is_ok()
    );
    assert!(BindCredentialReadback::new(operation_id, CredentialTransitionEvidence::None).is_err());
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
    let evidence = CredentialTransitionEvidence::ExactVersionReadback(digest);

    let observe = ObserveNativeEffect::new(operation_id, digest);
    assert_eq!(observe.operation_id(), operation_id);
    let complete =
        CompleteCredentialOperation::new(operation_id, evidence, revision, fence).unwrap();
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
        version.clone(),
        revision,
        fence,
    )
    .unwrap();
    assert_eq!(snapshot.operation_id(), operation_id);
    assert!(CredentialRecoveryWork::new(snapshot.clone()).is_ok());
    let lifecycle =
        CredentialLifecycleSnapshot::new(provider.clone(), Some(version), revision, fence).unwrap();
    assert_eq!(lifecycle.provider(), &provider);

    let begin = BeginCredentialVerification::new(operation_id, provider, revision, fence);
    let lease = CredentialVerificationLease::new(begin, 100).unwrap();
    let capability = CredentialVerificationCapability::new(lease, digest);
    let observation = CredentialVerificationObservation::new(operation_id, evidence).unwrap();
    let completed = CompleteCredentialVerification::new(observation, revision, fence);
    assert_eq!(capability.operation_id(), operation_id);
    assert_eq!(completed.operation_id(), operation_id);
}

#[test]
fn credential_enrollment_review_ticket_issue_and_operation_commands_are_safe() {
    let operation_id = CredentialOperationId::from_bytes([5; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    let ticket = RawCredentialTicket::generate().unwrap();
    let issued = IssueCredentialTicketDigest::new(operation_id, attempt, &ticket, 10, 20).unwrap();
    assert_eq!(issued.operation_id(), operation_id);
    assert!(IssueCredentialTicketDigest::new(operation_id, attempt, &ticket, 20, 10).is_err());
}
