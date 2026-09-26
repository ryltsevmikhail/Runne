use super::*;
use std::os::unix::net::UnixStream;
use std::process::Command;

#[test]
fn post_transition_v3_status_uses_the_generation_in_its_signed_enrollment_binding() {
    // Match the real V2→V3 transition: the signed enrollment binding retains
    // the confirmed pre-transition desktop generation, while Ready-V3 advances
    // the daemon launch generation (see the transition wire contract).
    let (launch, original, _, keys) = super::super::v3_fixture();
    let core = runne_api::ProtectedReadyV1::new(
        launch.launch_authority_id(),
        launch.desktop_host_instance_id(),
        original.executable().clone(),
        original.profile().clone(),
        original.stable().clone(),
        *original.daemon_instance_id(),
        5,
        *original.session_id(),
        original.endpoint(),
        *original.certificate_sha256(),
        original.certificate_der().to_vec(),
        original.capabilities().to_vec(),
    )
    .unwrap();
    let mut ready = runne_api::ProtectedCredentialEnrollmentReadyV3::new(
        core,
        original.provider_binding().clone(),
        original.enrollment_binding().clone(),
        original.provider_readiness(),
    )
    .unwrap();
    ready.sign(&launch, &keys).unwrap();
    let desktop_launch = super::super::DesktopLaunchRequest::V3(launch);
    let decoded = desktop_launch
        .decode_ready(&ready.encode_frame().unwrap(), &keys)
        .unwrap();
    let activation = decoded.into_process_activation(desktop_launch).unwrap();
    let owned = ready.owned_launch();
    let (channel, daemon) = UnixStream::pair().unwrap();
    drop(daemon);
    let child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
    let mut process = super::super::ProtectedBundledRuntimeProcess {
        child,
        linux_launch_image: None,
        channel,
        keys,
        activation,
        runtime_profile: None,
        renewal_sequence: 0,
        root_control_sequence: 0,
        graceful_requested: false,
        graceful_acknowledged: false,
        enrollment_broker_facts: None,
        #[cfg(feature = "test-support")]
        captured_stdout: None,
        #[cfg(feature = "test-support")]
        captured_stderr: None,
    };

    let peer_generation = process
        .credential_status_peer_generation(owned.launch_generation())
        .unwrap();
    assert_eq!(owned.launch_generation(), 5);
    assert_eq!(
        owned.enrollment_binding().desktop_supervisor_generation(),
        1
    );
    assert_eq!(peer_generation, 1);
    assert!(process.credential_status_peer_generation(4).is_err());
    assert!(process.credential_status_peer_generation(6).is_err());
    let binding = owned.enrollment_binding();
    let claims = EnrollmentTransitionClaims::new(
        *binding.release_tuple_digest(),
        *binding.qualification_binding_digest(),
        *binding.desktop_peer_binding_digest(),
        peer_generation,
    );
    assert!(process.prepare_credential_status(&claims, 7).is_ok());

    let stale_generation_claims = EnrollmentTransitionClaims::new(
        *binding.release_tuple_digest(),
        *binding.qualification_binding_digest(),
        *binding.desktop_peer_binding_digest(),
        owned.launch_generation(),
    );
    assert!(
        process
            .prepare_credential_status(&stale_generation_claims, 7)
            .is_err()
    );
    let _ = process.child.kill();
    let _ = process.child.wait();
}
