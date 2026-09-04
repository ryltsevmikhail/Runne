use super::super::{
    ProtectedProcessActivation, read_frame, test_only_ready_v3_enrollment_supervisor, write_frame,
};
use super::*;
use runne_api::{LaunchSecret, ProtectedCredentialRoundBrokerFacts, ProtectedCredentialRoundCodec};
use std::{os::unix::net::UnixStream, time::Duration};
mod interleaved;

fn snapshot(
    handle: u8,
    state: runne_api::ProviderCredentialOperationStateV2,
) -> runne_api::ProviderCredentialOperationSnapshotV2 {
    runne_api::ProviderCredentialOperationSnapshotV2::new(
        runne_api::ProviderCredentialOperationHandleV2::from_bytes([handle; 48]).unwrap(),
        None,
        runne_api::ProviderCredentialProviderV2::OpenAi,
        runne_api::ProviderCredentialOperationKindV2::Pair,
        state,
        1,
        1,
        false,
        None,
    )
    .unwrap()
}

#[test]
fn desktop_round_requires_terminal_and_session_renewal_before_io() {
    let mut supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
    let process = supervisor.process.as_mut().unwrap();
    process.enrollment_broker_facts = Some(EnrollmentBrokerFacts::new([31; 32], [32; 32]));
    assert!(supervisor.begin_next_protected_credential_round().is_err());
    supervisor
        .process
        .as_mut()
        .unwrap()
        .record_enrollment_terminal()
        .unwrap();
    assert!(supervisor.begin_next_protected_credential_round().is_err());
    assert!(
        supervisor
            .process
            .as_ref()
            .unwrap()
            .enrollment_broker_facts
            .is_some()
    );
}

#[test]
fn unrelated_terminal_does_not_authorize_next_round() {
    use super::super::{PreparedProtectedCredentialEnrollment, v3_process};
    use runne_api::{
        ProtectedCredentialEnrollmentLifecycleCodec, ProviderCredentialOperationStateV2 as State,
    };
    let (channel, mut peer) = UnixStream::pair().unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (mut process, keys) = v3_process(channel);
    process.enrollment_broker_facts = Some(EnrollmentBrokerFacts::new([31; 32], [32; 32]));
    let mut enrollment = PreparedProtectedCredentialEnrollment {
        codec: ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys),
        snapshot: snapshot(1, State::Prepared),
        relay: Some([7; 388]),
        relay_taken: true,
        terminal: false,
    };
    let daemon = std::thread::spawn(move || {
        let codec = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
        let _ack = read_frame(&mut peer).unwrap();
        write_frame(
            &mut peer,
            &codec
                .encode_daemon_snapshot(&snapshot(2, State::Completed), 3)
                .unwrap(),
        )
        .unwrap();
    });
    assert!(
        process
            .finish_protected_credential_enrollment(&mut enrollment, &[7; 388])
            .is_err()
    );
    assert!(!enrollment.terminal());
    assert!(
        process
            .enrollment_broker_facts
            .unwrap()
            .terminal_session
            .is_none()
    );
    daemon.join().unwrap();
}

#[test]
fn desktop_round_accepts_exact_offer_before_returning_broker_facts() {
    let supervisor = test_only_ready_v3_enrollment_supervisor().into_supervisor();
    let ProtectedProcessActivation::V3 { owned, .. } =
        &supervisor.process.as_ref().unwrap().activation
    else {
        panic!()
    };
    let owned = owned.clone();
    let daemon_owned = owned.clone();
    let (mut channel, mut peer) = UnixStream::pair().unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let daemon = std::thread::spawn(move || {
        let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
        let mut codec = ProtectedCredentialRoundCodec::new(&keys, &daemon_owned);
        codec
            .decode_request(&read_frame(&mut peer).unwrap())
            .unwrap();
        let offer = codec
            .encode_offer(ProtectedCredentialRoundBrokerFacts::new([31; 32], [32; 32]).unwrap())
            .unwrap();
        write_frame(&mut peer, &offer).unwrap();
        codec
            .decode_accept(&read_frame(&mut peer).unwrap())
            .unwrap();
    });
    let keys = LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys();
    let facts = exchange(&mut channel, &keys, &owned).unwrap();
    assert_eq!(facts.binding(), [31; 32]);
    assert_eq!(facts.publication_public_key(), [32; 32]);
    daemon.join().unwrap();
}
