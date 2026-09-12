use super::*;
use runne_api::ProtectedCredentialStatusNativeClaimsV2;

fn daemon_status(mut channel: UnixStream, owned: ProtectedOwnedLaunchV2, foreign: bool) {
    let (_, _, keys) = v2_launch_fixture();
    let request =
        ProtectedCredentialStatusRequestV2::decode_frame(&read_frame(&mut channel).unwrap())
            .unwrap();
    let verified = request.verify_exact_view(&owned, 0, &keys).unwrap();
    let claims =
        ProtectedCredentialStatusNativeClaimsV2::new([22; 32], [7; 32], [8; 32], [9; 32], 1, 1)
            .unwrap();
    let mut ack = ProtectedCredentialStatusAckV2::new(&verified, claims).unwrap();
    let signer = if foreign {
        v2_launch_fixture_with_secret([66; 32]).2
    } else {
        keys
    };
    ack.sign(&signer);
    write_frame(&mut channel, &Zeroizing::new(ack.encode_frame().unwrap())).unwrap();
}

#[test]
fn status_prelude_keeps_v2_and_does_not_create_a_broker_or_profile() {
    let (desktop, daemon) = UnixStream::pair().unwrap();
    desktop
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (mut process, owned) = v2_process(desktop);
    let server = std::thread::spawn(move || daemon_status(daemon, owned, false));
    // Root transfers may have already consumed sequence values.
    process.root_control_sequence = 5;
    let result = process.prepare_credential_status(
        &EnrollmentTransitionClaims::new([7; 32], [8; 32], [9; 32], 1),
        1,
    );
    let unchanged = matches!(process.activation, ProtectedProcessActivation::V2 { .. })
        && process.runtime_profile.is_none()
        && process.enrollment_broker_facts.is_none();
    let _ = process.child.kill();
    let _ = process.child.wait();
    server.join().unwrap();
    result.unwrap();
    assert!(unchanged);
    assert_eq!(process.root_control_sequence, 6);
}

#[test]
fn foreign_status_ack_fences_the_ambiguous_channel() {
    let (desktop, daemon) = UnixStream::pair().unwrap();
    desktop
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (mut process, owned) = v2_process(desktop);
    let server = std::thread::spawn(move || daemon_status(daemon, owned, true));
    let result = process.prepare_credential_status(
        &EnrollmentTransitionClaims::new([7; 32], [8; 32], [9; 32], 1),
        1,
    );
    server.join().unwrap();
    assert!(result.is_err());
    assert_eq!(process.status(), Ok(BundledRuntimeProcessStatus::Exited));
    assert!(process.graceful_requested);
}

#[test]
fn stale_installed_generation_ack_is_rejected() {
    let (desktop, daemon) = UnixStream::pair().unwrap();
    desktop
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (mut process, owned) = v2_process(desktop);
    let server = std::thread::spawn(move || daemon_status(daemon, owned, false));
    let result = process.prepare_credential_status(
        &EnrollmentTransitionClaims::new([7; 32], [8; 32], [9; 32], 1),
        2,
    );
    server.join().unwrap();
    assert!(result.is_err());
    assert_eq!(process.status(), Ok(BundledRuntimeProcessStatus::Exited));
}
