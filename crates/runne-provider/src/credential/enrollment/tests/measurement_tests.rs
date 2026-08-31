use super::super::{
    ClaimCredentialOperation, CredentialClaimBinding, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentMeasurementAuthority, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleRevision, CredentialMeasurementSnapshot, CredentialOperationAction,
    CredentialOperationId, CredentialOperationMetadata, CredentialOperationSnapshot,
    CredentialOperationState, CredentialProcessBinding, CredentialTicketAttempt,
    IssuedCredentialTicketAttempt,
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
        receipt(provider.clone()),
        digest(21),
        digest(13),
        canonical_claim_digest(),
        1,
        1,
    )
    .unwrap();
    let binding = CredentialClaimBinding::new(measurements, &claim).unwrap();
    assert_eq!(binding.operation_id().as_bytes(), [20; 16]);
    assert_ne!(binding.digest().as_bytes(), [0; 32]);
}

fn receipt(provider: ProviderId) -> IssuedCredentialTicketAttempt {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let operation = CredentialOperationId::from_bytes([20; 16]).unwrap();
    let snapshot = CredentialOperationSnapshot::new(
        operation,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialOperationState::Prepared,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        None,
        CredentialOperationMetadata::new(
            runne_domain::id::CommandId::from_bytes([20; 16]),
            runne_domain::id::IdempotencyKey::new("measurement-claim").unwrap(),
            CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            digest(22),
            10,
            10,
        )
        .unwrap(),
    )
    .unwrap();
    store
        .hydrate_issued_credential_ticket_attempt(
            snapshot,
            CredentialTicketAttempt::new(1).unwrap(),
            10,
            20,
        )
        .unwrap()
}

fn canonical_claim_digest() -> super::super::CredentialBindingDigest {
    super::super::CredentialBindingDigest::from_measured([
        0xd8, 0x6b, 0x05, 0xe6, 0x02, 0x20, 0x7f, 0x65, 0x60, 0xfd, 0x8b, 0x66, 0xe5, 0x7a, 0xa2,
        0x02, 0xe9, 0xa7, 0x65, 0x50, 0x74, 0x34, 0xac, 0xf3, 0x42, 0x44, 0xed, 0xda, 0xbd, 0x43,
        0x2f, 0xc7,
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
        measurements.desktop_supervisor_generation(1)?,
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
        measurements.desktop_supervisor_generation(1).unwrap(),
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
