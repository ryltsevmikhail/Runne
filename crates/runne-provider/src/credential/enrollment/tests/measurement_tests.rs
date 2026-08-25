use super::super::{
    BrokerChannelBinding, CandidateSourceIdentity, ClaimCredentialOperation,
    ContinuationBindingDigest, ContractBundleDigest, CredentialClaimBinding, CredentialFence,
    CredentialLifecycleRevision, CredentialMeasurementSnapshot, CredentialOperationAction,
    CredentialOperationId, CredentialProcessBinding, CredentialTicketAttempt, DaemonAuthorityId,
    DesktopExecutableIdentity, ProtectedSessionId, ReaderExecutableIdentity, ReleaseManifestDigest,
    WriterExecutableIdentity, WriterLaunchId, WriterProcessHandleIdentity,
    WriterProcessStartIdentity,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn credential_enrollment_review_measurement_snapshot_rejects_cross_source_aliases() {
    assert!(measurement_snapshot([9; 32]).is_err());
}

#[test]
fn credential_enrollment_review_claim_binding_uses_validated_measurement_snapshot() {
    let measurements = distinct_measurements();
    let process = CredentialProcessBinding::new(
        WriterProcessStartIdentity::from_measured([10; 32]).unwrap(),
        WriterProcessHandleIdentity::from_measured([11; 32]).unwrap(),
    );
    assert_eq!(measurements.process_binding(), process);

    let provider = ProviderId::new("openai").unwrap();
    let claim = ClaimCredentialOperation::new(
        CredentialOperationId::from_bytes([20; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        digest(21),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialVersionRef::new(provider, 1).unwrap(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        1,
        1,
        10,
        20,
    )
    .unwrap();
    let binding = CredentialClaimBinding::new(measurements, claim).unwrap();
    assert_eq!(binding.operation_id().bytes(), [20; 16]);
    assert_ne!(binding.digest().as_bytes(), [0; 32]);
}

fn measurement_snapshot(
    alias: [u8; 32],
) -> Result<CredentialMeasurementSnapshot, super::super::CredentialEnrollmentError> {
    CredentialMeasurementSnapshot::new(
        CandidateSourceIdentity::from_measured(alias)?,
        ReleaseManifestDigest::from_measured(alias)?,
        DesktopExecutableIdentity::from_measured(alias)?,
        WriterExecutableIdentity::from_measured(alias)?,
        ReaderExecutableIdentity::from_measured(alias)?,
        ContractBundleDigest::from_measured(alias)?,
        DaemonAuthorityId::from_measured(alias)?,
        ProtectedSessionId::from_measured(alias)?,
        WriterLaunchId::from_measured(alias)?,
        WriterProcessStartIdentity::from_measured(alias)?,
        WriterProcessHandleIdentity::from_measured(alias)?,
        BrokerChannelBinding::from_measured(alias)?,
        ContinuationBindingDigest::from_measured(alias)?,
    )
}

fn distinct_measurements() -> CredentialMeasurementSnapshot {
    CredentialMeasurementSnapshot::new(
        CandidateSourceIdentity::from_measured([1; 32]).unwrap(),
        ReleaseManifestDigest::from_measured([2; 32]).unwrap(),
        DesktopExecutableIdentity::from_measured([3; 32]).unwrap(),
        WriterExecutableIdentity::from_measured([4; 32]).unwrap(),
        ReaderExecutableIdentity::from_measured([5; 32]).unwrap(),
        ContractBundleDigest::from_measured([6; 32]).unwrap(),
        DaemonAuthorityId::from_measured([7; 32]).unwrap(),
        ProtectedSessionId::from_measured([8; 32]).unwrap(),
        WriterLaunchId::from_measured([9; 32]).unwrap(),
        WriterProcessStartIdentity::from_measured([10; 32]).unwrap(),
        WriterProcessHandleIdentity::from_measured([11; 32]).unwrap(),
        BrokerChannelBinding::from_measured([12; 32]).unwrap(),
        ContinuationBindingDigest::from_measured([13; 32]).unwrap(),
    )
    .unwrap()
}

fn digest(value: u8) -> super::super::CredentialBindingDigest {
    super::super::CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
