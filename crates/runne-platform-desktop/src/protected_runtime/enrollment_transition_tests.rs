fn v2_launch_fixture() -> (
    ProtectedLaunchRequestV2,
    ProtectedReadyV2,
    ProtectedActivationKeys,
) {
    let profile = expected_profile().expect("expected protected profile");
    let request = ProtectedLaunchRequestV1::new(
        id(1),
        id(2),
        LaunchSecret::from_bytes([3; 32]).expect("launch secret"),
        10,
        20,
        "principal",
        profile.clone(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).expect("executable"),
        PathBuf::from("/tmp/runtime"),
        ActivationDispositionV1::FirstActivation,
    )
    .expect("V1 request");
    let keys = request.derive_keys();
    let stable = StableRuntimeBindingV1::new(
        id(10),
        "principal",
        id(11),
        profile.profile_id(),
        *profile.profile_hash(),
        *profile.capability_digest(),
    )
    .expect("stable binding");
    let mut v1_ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        request.executable().clone(),
        profile,
        stable,
        id(12),
        1,
        id(13),
        "https://127.0.0.1:43123",
        Sha256::digest([15; 32]).into(),
        vec![15; 32],
        PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect(),
    )
    .expect("V1 ready");
    v1_ready.sign(&keys);
    let ready = v2_ready(v1_ready, &keys);
    let request =
        ProtectedLaunchRequestV2::new(request, ProviderActivationBindingV1::openai_responses_text_v1())
            .expect("V2 request");
    (request, ready, keys)
}

fn v2_process(channel: UnixStream) -> (ProtectedBundledRuntimeProcess, ProtectedOwnedLaunchV2) {
    let (request, ready, keys) = v2_launch_fixture();
    let owned = ready.owned_launch();
    let launch = DesktopLaunchRequest::V2(request);
    let decoded = launch
        .decode_ready(&ready.encode_frame().expect("V2 ready frame"), &keys)
        .expect("exact V2 ready");
    let activation = decoded
        .into_process_activation(launch)
        .expect("V2 activation");
    let child = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 60"])
        .spawn()
        .expect("owned test child");
    (
        ProtectedBundledRuntimeProcess {
            child,
            channel,
            keys,
            activation,
            runtime_profile: None,
            renewal_sequence: 0,
            #[cfg(feature = "protected-channel-integration")]
            root_control_sequence: 0,
            graceful_requested: false,
            #[cfg(feature = "test-support")]
            captured_stdout: None,
            #[cfg(feature = "test-support")]
            captured_stderr: None,
        },
        owned,
    )
}

fn daemon_prelude(
    prepare: &ProtectedCredentialEnrollmentPrepareV2,
    keys: &ProtectedActivationKeys,
) -> (Vec<u8>, runne_api::DaemonEnrollmentLaunchPreludeV1) {
    let now = crate::MacOsContinuousClock::now_millis().expect("continuous clock");
    let prelude = runne_api::DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        id(1),
        id(2),
        [22; 32],
        [11; 32],
        [12; 32],
        [6; 32],
        [9; 32],
        1,
        now,
        now + 20_000,
    )
    .expect("enrollment prelude");
    let mut signed =
        ProtectedCredentialEnrollmentPreludeV2::new(prepare, [25; 32], prelude.clone())
            .expect("prelude frame");
    signed.sign(keys);
    (
        signed.encode_frame().expect("prelude frame bytes"),
        prelude,
    )
}

/// Runs the daemon half of the transition exactly as the real control loop
/// would: verify the prepare MAC, issue the signed prelude, admit the exact
/// V3 request through its broker commitment, and answer with signed readiness.
fn daemon_exchange(
    mut daemon: UnixStream,
    owned: &ProtectedOwnedLaunchV2,
    foreign_prelude_keys: bool,
) {
    let (_, _, keys) = v2_launch_fixture();
    let frame = read_frame(&mut daemon).expect("prepare frame");
    let prepare = ProtectedCredentialEnrollmentPrepareV2::decode_frame(&frame).expect("exact prepare");
    prepare
        .verify_exact_view(owned, 0, &keys)
        .expect("prepare MAC");
    let signer = if foreign_prelude_keys {
        let (_request, _ready, foreign) = v2_launch_fixture_with_secret([0x66; 32]);
        foreign
    } else {
        keys
    };
    let (prelude_frame, prelude) = daemon_prelude(&prepare, &signer);
    write_frame(&mut daemon, &Zeroizing::new(prelude_frame)).expect("prelude response");
    let Ok(frame) = read_frame(&mut daemon) else {
        // A client that rejected the prelude fenced the channel first.
        return;
    };
    let v3 = ProtectedCredentialEnrollmentLaunchRequestV3::decode_frame(&frame).expect("exact V3");
    let v3_keys = v3.derive_keys();
    let commitment = CredentialBrokerTransferAuthenticator::from_protected_activation(&v3_keys)
        .enrollment_launch_commitment(&prelude);
    assert_eq!(*v3.enrollment_binding().broker_transfer_commitment(), commitment);

    let ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        v3.executable().clone(),
        v3.profile().clone(),
        owned.compatibility_owned_launch().stable().clone(),
        id(12),
        5,
        id(13),
        "https://127.0.0.1:43123",
        Sha256::digest([15; 32]).into(),
        vec![15; 32],
        PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect(),
    )
    .expect("V1 ready core");
    let mut ready = ProtectedCredentialEnrollmentReadyV3::new(
        ready,
        v3.provider_binding().clone(),
        v3.enrollment_binding().clone(),
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .expect("V3 ready");
    ready.sign(&v3, &v3_keys).expect("sign V3 ready");
    write_frame(&mut daemon, &Zeroizing::new(ready.encode_frame().expect("V3 ready frame")))
        .expect("ready response");
}

fn v2_launch_fixture_with_secret(
    secret: [u8; 32],
) -> (ProtectedLaunchRequestV1, ProtectedReadyV2, ProtectedActivationKeys) {
    let profile = expected_profile().expect("expected protected profile");
    let request = ProtectedLaunchRequestV1::new(
        id(1),
        id(2),
        LaunchSecret::from_bytes(secret).expect("launch secret"),
        10,
        20,
        "principal",
        profile.clone(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).expect("executable"),
        PathBuf::from("/tmp/runtime"),
        ActivationDispositionV1::FirstActivation,
    )
    .expect("V1 request");
    let keys = request.derive_keys();
    let stable = StableRuntimeBindingV1::new(
        id(10),
        "principal",
        id(11),
        profile.profile_id(),
        *profile.profile_hash(),
        *profile.capability_digest(),
    )
    .expect("stable binding");
    let mut v1_ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        request.executable().clone(),
        profile,
        stable,
        id(12),
        1,
        id(13),
        "https://127.0.0.1:43123",
        Sha256::digest([15; 32]).into(),
        vec![15; 32],
        PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect(),
    )
    .expect("V1 ready");
    v1_ready.sign(&keys);
    let ready = v2_ready(v1_ready, &keys);
    (request, ready, keys)
}

const fn v3_state(process: &ProtectedBundledRuntimeProcess) -> Option<u64> {
    match &process.activation {
        ProtectedProcessActivation::V3 { owned, .. } => Some(owned.launch_generation()),
        _ => None,
    }
}

#[test]
fn enrollment_transition_upgrades_the_process_to_the_exact_v3_state() {
    let (desktop, daemon) = UnixStream::pair().expect("test channel");
    let (mut process, owned) = v2_process(desktop);
    let server = std::thread::spawn(move || daemon_exchange(daemon, &owned, false));

    let claims = EnrollmentTransitionClaims::new([7; 32], [8; 32], [9; 32], 1);
    let profile = process
        .begin_credential_enrollment_transition(&claims)
        .expect("exact transition");
    server.join().expect("daemon exchange");

    assert_eq!(v3_state(&process), Some(5));
    assert_eq!(
        profile.enrollment_owned_launch().map(runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3::launch_generation),
        Some(5)
    );
}

#[test]
fn foreign_prelude_fails_closed_and_fences_the_child() {
    let (desktop, daemon) = UnixStream::pair().expect("test channel");
    let (mut process, owned) = v2_process(desktop);
    let server = std::thread::spawn(move || daemon_exchange(daemon, &owned, true));

    let claims = EnrollmentTransitionClaims::new([7; 32], [8; 32], [9; 32], 1);
    assert!(process.begin_credential_enrollment_transition(&claims).is_err());
    server.join().expect("daemon exchange");

    assert_eq!(v3_state(&process), None);
    assert_eq!(
        process.status(),
        Ok(BundledRuntimeProcessStatus::Exited),
        "the ambiguous transition child must be fenced"
    );
}
