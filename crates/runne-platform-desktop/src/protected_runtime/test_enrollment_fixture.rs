/// Opaque test-only owner of a real Ready-V3 supervisor state.
#[doc(hidden)]
pub struct TestOnlyReadyV3EnrollmentSupervisor(ProtectedBundledRuntimeSupervisor);

impl TestOnlyReadyV3EnrollmentSupervisor {
    #[must_use]
    pub fn owned_process_id(&self) -> Option<u32> {
        self.0.process.as_ref().map(|process| process.child.id())
    }

    #[must_use]
    pub fn into_supervisor(self) -> ProtectedBundledRuntimeSupervisor {
        self.0
    }
}

/// Builds a real supervisor/process V3 state without a daemon protocol peer.
/// It is available only through the explicit `test-support` feature.
#[doc(hidden)]
#[must_use]
pub fn test_only_ready_v3_enrollment_supervisor() -> TestOnlyReadyV3EnrollmentSupervisor {
    let profile = expected_profile().expect("protected profile");
    let request = ProtectedLaunchRequestV1::new(
        test_id(1),
        test_id(2),
        LaunchSecret::from_bytes([3; 32]).expect("launch secret"),
        10,
        20,
        "principal",
        profile.clone(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).expect("executable"),
        std::path::PathBuf::from("/tmp/runtime"),
        ActivationDispositionV1::FirstActivation,
    )
    .expect("request");
    let keys = request.derive_keys();
    let broker = runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let prelude = runne_api::DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        request.launch_authority_id(), request.desktop_host_instance_id(), [10; 32], [11; 32],
        [12; 32], [6; 32], [9; 32], 1, 10, 20,
    ).expect("prelude");
    let binding = runne_api::ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [6; 32], [7; 32], [8; 32], [9; 32], 1,
        broker.enrollment_launch_commitment(&prelude),
    ).expect("binding");
    let launch = runne_api::ProtectedCredentialEnrollmentLaunchRequestV3::new(
        request.clone(), ProviderActivationBindingV1::openai_responses_text_v1(), binding.clone(),
    ).expect("launch");
    let stable = StableRuntimeBindingV1::new(
        test_id(10), "principal", test_id(11), profile.profile_id(), *profile.profile_hash(),
        *profile.capability_digest(),
    ).expect("stable");
    let mut ready_v1 = ProtectedReadyV1::new(
        test_id(1), test_id(2), request.executable().clone(), profile, stable, test_id(12), 1,
        test_id(13), "https://127.0.0.1:43123", sha2::Sha256::digest([15; 32]).into(),
        vec![15; 32], PROTECTED_RUNTIME_CAPABILITIES.iter().map(|value| (*value).to_owned()).collect(),
    ).expect("ready");
    ready_v1.sign(&keys);
    let mut ready = runne_api::ProtectedCredentialEnrollmentReadyV3::new(
        ready_v1, ProviderActivationBindingV1::openai_responses_text_v1(), binding,
        ProviderActivationReadinessV1::CredentialMissing,
    ).expect("V3 ready");
    ready.sign(&launch, &keys).expect("sign ready");
    let desktop = DesktopLaunchRequest::V3(launch);
    let decoded = desktop.decode_ready(&ready.encode_frame().expect("ready frame"), &keys)
        .expect("decode ready");
    let activation = decoded.into_process_activation(desktop).expect("activation");
    let child = std::process::Command::new("/bin/sleep").arg("30").spawn().expect("child");
    let (channel, peer) = std::os::unix::net::UnixStream::pair().expect("channel");
    drop(peer);
    let process = ProtectedBundledRuntimeProcess {
        child, channel, keys, activation, runtime_profile: None, renewal_sequence: 0,
        root_control_sequence: 0, graceful_requested: false, enrollment_broker_facts: None,
        captured_stdout: None, captured_stderr: None,
    };
    let root = std::env::temp_dir().join(format!("runne-v3-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).expect("runtime root");
    let spec = ProtectedBundledRuntimeLaunchSpec::new(std::path::Path::new("/bin/sleep"), &root)
        .expect("launch spec");
    let supervisor = ProtectedBundledRuntimeSupervisor {
        launcher: DevelopmentBundledRuntimeLauncher::new(), spec, process: Some(process),
        pending_profile: None, backoff: BundledRuntimeBackoff::new(), restart_at: None,
        state: BundledRuntimeLifecycleState::Ready,
    };
    let _ = std::fs::remove_dir(root);
    TestOnlyReadyV3EnrollmentSupervisor(supervisor)
}

/// Builds the same concrete supervisor type in its genuine pre-V3 Absent state.
#[doc(hidden)]
#[must_use]
pub fn test_only_absent_enrollment_supervisor() -> TestOnlyReadyV3EnrollmentSupervisor {
    let root = std::env::temp_dir().join(format!("runne-absent-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).expect("runtime root");
    let spec = ProtectedBundledRuntimeLaunchSpec::new(std::path::Path::new("/bin/sleep"), &root)
        .expect("launch spec");
    let supervisor = ProtectedBundledRuntimeSupervisor::new(
        DevelopmentBundledRuntimeLauncher::new(),
        spec,
    );
    let _ = std::fs::remove_dir(root);
    TestOnlyReadyV3EnrollmentSupervisor(supervisor)
}

const fn test_id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}
