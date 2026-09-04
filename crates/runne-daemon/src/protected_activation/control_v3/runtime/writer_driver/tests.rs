use super::*;
use crate::protected_activation::{
    ProtectedActivationChannel, enrollment_v3_tests::owned_and_sessions,
};
use runne_provider::{
    CredentialBindingDigest, CredentialEnrollmentAuthorityPair, CredentialMeasurementSnapshot,
};

#[test]
fn deferred_control_prevents_consuming_claim_measurements() {
    let (owned, keys, sessions) = owned_and_sessions();
    let (_, authority) = CredentialEnrollmentAuthorityPair::new().split();
    let continuation = CredentialBindingDigest::from_measured([23; 32]).unwrap();
    let measurements = CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([10; 32]).unwrap(),
        authority.release_manifest_digest([11; 32]).unwrap(),
        authority.desktop_executable_identity([12; 32]).unwrap(),
        authority.writer_executable_identity([13; 32]).unwrap(),
        authority.reader_executable_identity([14; 32]).unwrap(),
        authority.contract_bundle_digest([15; 32]).unwrap(),
        authority.daemon_authority_id([16; 32]).unwrap(),
        authority.protected_session_id([17; 32]).unwrap(),
        authority.desktop_supervisor_generation(1).unwrap(),
        authority.writer_launch_id([18; 32]).unwrap(),
        authority.writer_process_start_identity([19; 32]).unwrap(),
        authority.writer_process_handle_identity([20; 32]).unwrap(),
        authority.broker_channel_binding([21; 32]).unwrap(),
        authority
            .continuation_binding_digest(continuation.as_bytes())
            .unwrap(),
    )
    .unwrap();
    let live = super::super::super::live_session::LiveEnrollmentSession::capture(&sessions, &owned)
        .unwrap();
    let deferred = vec![0, 0, 0, 1, 7];
    let mut runtime = V3EnrollmentRuntime {
        deferred_control: Some(zeroize::Zeroizing::new(deferred.clone())),
        #[cfg(target_arch = "aarch64")]
        round: None,
        live: Some(live),
        broker: None,
        session: None,
        terminal: false,
        claim_measurements: Some((measurements, continuation)),
        channel: None,
        credential_service: None,
        credential_service_configuration: None,
    };
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut channel = ProtectedActivationChannel::new(stream).unwrap();
    assert!(
        runtime
            .drive_claimed_writer(&mut channel, &sessions, &keys, &owned)
            .is_err()
    );
    assert!(
        runtime.claim_measurements.is_some(),
        "deferred control must fence claim admission"
    );
    assert_eq!(runtime.deferred_control.unwrap().as_slice(), deferred);
    assert!(runtime.channel.is_none());
}
