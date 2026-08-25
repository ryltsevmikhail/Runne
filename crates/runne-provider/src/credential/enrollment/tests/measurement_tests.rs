use super::super::{
    ClaimCredentialOperation, CredentialClaimBinding, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentMeasurementAuthority, CredentialFence, CredentialLifecycleRevision,
    CredentialMeasurementSnapshot, CredentialOperationAction, CredentialOperationId,
    CredentialProcessBinding, CredentialTicketAttempt,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn credential_enrollment_review_measurement_snapshot_rejects_cross_source_aliases() {
    assert!(measurement_snapshot([9; 32]).is_err());
}

#[test]
fn credential_enrollment_review_claim_binding_uses_validated_measurement_snapshot() {
    let (_, authority) = CredentialEnrollmentAuthorityPair::new().split();
    let measurements = distinct_measurements(&authority);
    let process = CredentialProcessBinding::new(
        authority.writer_process_start_identity([10; 32]).unwrap(),
        authority.writer_process_handle_identity([11; 32]).unwrap(),
    );
    assert_eq!(measurements.process_binding(), process);

    let provider = ProviderId::new("openai").unwrap();
    let claim = ClaimCredentialOperation::new(
        CredentialOperationId::from_bytes([20; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        digest(21),
        digest(13),
        canonical_claim_digest(),
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        1,
        1,
        10,
        20,
    )
    .unwrap();
    let binding = CredentialClaimBinding::new(measurements, &claim).unwrap();
    assert_eq!(binding.operation_id().bytes(), [20; 16]);
    assert_ne!(binding.digest().as_bytes(), [0; 32]);
}

fn canonical_claim_digest() -> super::super::CredentialBindingDigest {
    super::super::CredentialBindingDigest::from_measured([
        0x75, 0xc1, 0x03, 0xa9, 0x0d, 0x81, 0xee, 0xb8, 0x36, 0xdb, 0x12, 0xf4, 0x9e, 0xb4, 0xff,
        0x11, 0x2e, 0x7b, 0xd3, 0xfd, 0xe6, 0x52, 0xef, 0x31, 0x6f, 0x06, 0x62, 0x35, 0x78, 0xaa,
        0xae, 0x1f,
    ])
    .unwrap()
}

fn measurement_snapshot(
    alias: [u8; 32],
) -> Result<CredentialMeasurementSnapshot, super::super::CredentialEnrollmentError> {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    CredentialMeasurementSnapshot::new(
        measurements.candidate_source_identity(alias)?,
        measurements.release_manifest_digest(alias)?,
        measurements.desktop_executable_identity(alias)?,
        measurements.writer_executable_identity(alias)?,
        measurements.reader_executable_identity(alias)?,
        measurements.contract_bundle_digest(alias)?,
        measurements.daemon_authority_id(alias)?,
        measurements.protected_session_id(alias)?,
        measurements.writer_launch_id(alias)?,
        measurements.writer_process_start_identity(alias)?,
        measurements.writer_process_handle_identity(alias)?,
        measurements.broker_channel_binding(alias)?,
        measurements.continuation_binding_digest(alias)?,
    )
}

fn distinct_measurements(
    measurements: &CredentialEnrollmentMeasurementAuthority,
) -> CredentialMeasurementSnapshot {
    CredentialMeasurementSnapshot::new(
        measurements.candidate_source_identity([1; 32]).unwrap(),
        measurements.release_manifest_digest([2; 32]).unwrap(),
        measurements.desktop_executable_identity([3; 32]).unwrap(),
        measurements.writer_executable_identity([4; 32]).unwrap(),
        measurements.reader_executable_identity([5; 32]).unwrap(),
        measurements.contract_bundle_digest([6; 32]).unwrap(),
        measurements.daemon_authority_id([7; 32]).unwrap(),
        measurements.protected_session_id([8; 32]).unwrap(),
        measurements.writer_launch_id([9; 32]).unwrap(),
        measurements
            .writer_process_start_identity([10; 32])
            .unwrap(),
        measurements
            .writer_process_handle_identity([11; 32])
            .unwrap(),
        measurements.broker_channel_binding([12; 32]).unwrap(),
        measurements.continuation_binding_digest([13; 32]).unwrap(),
    )
    .unwrap()
}

fn digest(value: u8) -> super::super::CredentialBindingDigest {
    super::super::CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
