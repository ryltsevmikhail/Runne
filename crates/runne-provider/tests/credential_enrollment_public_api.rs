use runne_provider::{
    BeginCredentialOperation, BeginCredentialVerification, BindCredentialReadback,
    BrokerChannelBinding, CandidateSourceIdentity, ClaimCredentialOperation,
    ClosePreparedCredentialOperation, CompleteCredentialOperation, CompleteCredentialVerification,
    ContinuationBindingDigest, ContractBundleDigest, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialBrokerTarget, CredentialClaimBinding, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentError, CredentialEnrollmentMeasurementAuthority, CredentialFence,
    CredentialLifecycleRevision, CredentialLifecycleSnapshot, CredentialMeasurementSnapshot,
    CredentialOperationAction, CredentialOperationId, CredentialOperationSnapshot,
    CredentialOperationState, CredentialProcessBinding, CredentialRecoveryWork,
    CredentialReleaseMigrationBinding, CredentialTicketAttempt, CredentialTransitionEvidence,
    CredentialVerificationCapability, CredentialVerificationContext, CredentialVerificationLease,
    CredentialVerificationObservation, CredentialVersionRef, DaemonAuthorityId,
    DesktopExecutableIdentity, DesktopSupervisorGeneration, FailCredentialOperation,
    HardFenceProvider, IssueCredentialTicketDigest, ObserveNativeEffect, ProtectedSessionId,
    ProviderId, RawCredentialTicket, ReaderExecutableIdentity, ReleaseManifestDigest,
    TombstoneCredentialOperation, TransitionCommand, WriterExecutableIdentity,
    WriterIdentityMigrationPhase, WriterLaunchId, WriterProcessHandleIdentity,
    WriterProcessStartIdentity,
};

#[test]
fn credential_enrollment_public_api_is_consumer_visible() {
    macro_rules! visible { ($($ty:ty),+ $(,)?) => { $(let _ = std::any::type_name::<$ty>();)+ }; }
    visible!(
        BeginCredentialOperation,
        BeginCredentialVerification,
        BindCredentialReadback,
        BrokerChannelBinding,
        CandidateSourceIdentity,
        ClaimCredentialOperation,
        ClosePreparedCredentialOperation,
        CompleteCredentialOperation,
        CompleteCredentialVerification,
        ContinuationBindingDigest,
        ContractBundleDigest,
        CredentialBindingDigest,
        CredentialBrokerCommand,
        CredentialBrokerFrame,
        CredentialBrokerFrameCodec,
        CredentialClaimBinding,
        CredentialFence,
        CredentialLifecycleRevision,
        CredentialLifecycleSnapshot,
        CredentialMeasurementSnapshot,
        CredentialOperationAction,
        CredentialOperationId,
        CredentialOperationSnapshot,
        CredentialOperationState,
        CredentialProcessBinding,
        CredentialRecoveryWork,
        CredentialReleaseMigrationBinding,
        CredentialTicketAttempt,
        CredentialTransitionEvidence,
        CredentialVerificationCapability,
        CredentialVerificationContext,
        CredentialVerificationLease,
        CredentialVerificationObservation,
        DaemonAuthorityId,
        DesktopExecutableIdentity,
        DesktopSupervisorGeneration,
        FailCredentialOperation,
        HardFenceProvider,
        IssueCredentialTicketDigest,
        ObserveNativeEffect,
        ProtectedSessionId,
        ProviderId,
        RawCredentialTicket,
        ReaderExecutableIdentity,
        ReleaseManifestDigest,
        TombstoneCredentialOperation,
        TransitionCommand,
        WriterExecutableIdentity,
        WriterIdentityMigrationPhase,
        WriterLaunchId,
        WriterProcessHandleIdentity,
        WriterProcessStartIdentity,
    );
}

#[test]
fn credential_enrollment_public_authorities_bind_commands_and_measurements_to_one_pair() {
    let operation_id = CredentialOperationId::from_bytes([11; 16]).unwrap();
    assert_eq!(operation_id.as_bytes(), [11; 16]);
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    let ticket = RawCredentialTicket::generate().unwrap();
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket,
        binding: CredentialBindingDigest::from_measured([12; 32]).unwrap(),
        command: CredentialBrokerCommand::new(
            operation_id,
            attempt,
            ProviderId::new("openai").unwrap(),
            CredentialOperationAction::Pair,
            CredentialBrokerTarget::Version(
                CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 1).unwrap(),
            ),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            None,
        )
        .unwrap(),
    };
    let bytes = CredentialBrokerFrameCodec::encode(frame).unwrap();
    assert_eq!(
        CredentialBrokerFrameCodec::encode(CredentialBrokerFrameCodec::decode(&bytes).unwrap())
            .unwrap(),
        bytes
    );

    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let command = store
        .issue_transition_command(
            CredentialOperationAction::Pair,
            CredentialOperationState::Prepared,
            CredentialOperationState::Claimed,
            CredentialTransitionEvidence::None,
        )
        .unwrap();
    assert!(store.validate_transition_command(&command).is_ok());
    let (foreign_store, foreign_measurements) = CredentialEnrollmentAuthorityPair::new().split();
    assert!(foreign_store.validate_transition_command(&command).is_err());

    let expected = store.expected_install_measurement([12; 32]).unwrap();
    let observed = measurements.observed_install_measurement([12; 32]).unwrap();
    assert!(
        store
            .matches_expected_install(&expected, &observed)
            .unwrap()
    );
    let foreign_observed = foreign_measurements
        .observed_install_measurement([12; 32])
        .unwrap();
    assert!(
        store
            .matches_expected_install(&expected, &foreign_observed)
            .is_err()
    );
    let foreign_expected = foreign_store
        .expected_install_measurement([12; 32])
        .unwrap();
    assert!(
        store
            .matches_expected_install(&foreign_expected, &observed)
            .is_err()
    );
}

#[test]
fn credential_measurement_snapshot_rejects_a_foreign_source_authority() {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let (_, foreign_measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let local_source = measurements.candidate_source_identity([1; 32]).unwrap();
    let foreign_source = foreign_measurements
        .candidate_source_identity([1; 32])
        .unwrap();

    assert_ne!(local_source, foreign_source);
    assert_eq!(format!("{local_source:?}"), format!("{foreign_source:?}"));
    assert!(measurement_snapshot(&measurements, &foreign_measurements).is_err());
}

#[test]
fn credential_store_authority_validates_only_its_measurement_snapshot() {
    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let (_, foreign_measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let snapshot = measurement_snapshot(&measurements, &measurements).unwrap();
    let foreign_snapshot =
        measurement_snapshot(&foreign_measurements, &foreign_measurements).unwrap();

    assert!(store.validate_measurement_snapshot(&snapshot).is_ok());
    assert!(
        store
            .validate_measurement_snapshot(&foreign_snapshot)
            .is_err()
    );
}

fn measurement_snapshot(
    measurements: &CredentialEnrollmentMeasurementAuthority,
    candidate_source: &CredentialEnrollmentMeasurementAuthority,
) -> Result<CredentialMeasurementSnapshot, CredentialEnrollmentError> {
    CredentialMeasurementSnapshot::new(
        candidate_source.candidate_source_identity([1; 32])?,
        measurements.release_manifest_digest([2; 32])?,
        measurements.desktop_executable_identity([3; 32])?,
        measurements.writer_executable_identity([4; 32])?,
        measurements.reader_executable_identity([5; 32])?,
        measurements.contract_bundle_digest([6; 32])?,
        measurements.daemon_authority_id([7; 32])?,
        measurements.protected_session_id([8; 32])?,
        measurements.desktop_supervisor_generation(1)?,
        measurements.writer_launch_id([9; 32])?,
        measurements.writer_process_start_identity([10; 32])?,
        measurements.writer_process_handle_identity([11; 32])?,
        measurements.broker_channel_binding([12; 32])?,
        measurements.continuation_binding_digest([13; 32])?,
    )
}
