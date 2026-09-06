/// Opaque test-only owner of a real Ready-V3 supervisor state.
#[doc(hidden)]
pub struct TestOnlyReadyV3EnrollmentSupervisor(ProtectedBundledRuntimeSupervisor, u64);

/// Test-only connected endpoints for one real supervisor and V3 daemon loop.
#[doc(hidden)]
pub struct TestOnlyConnectedReadyV3EnrollmentSupervisor {
    supervisor: ProtectedBundledRuntimeSupervisor,
    daemon_channel: std::os::unix::net::UnixStream,
    keys: runne_api::ProtectedActivationKeys,
    owned: runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    installed: crate::VerifiedInstalledEnrollmentMeasurementFacts,
}

impl TestOnlyConnectedReadyV3EnrollmentSupervisor {
    #[doc(hidden)]
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ProtectedBundledRuntimeSupervisor,
        std::os::unix::net::UnixStream,
        runne_api::ProtectedActivationKeys,
        runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        crate::VerifiedInstalledEnrollmentMeasurementFacts,
    ) {
        (
            self.supervisor,
            self.daemon_channel,
            self.keys,
            self.owned,
            self.installed,
        )
    }
}

impl TestOnlyReadyV3EnrollmentSupervisor {
    #[must_use]
    pub const fn credential_service_parent_expiry(&self) -> u64 { self.1 }

    #[must_use]
    pub fn owned_launch(&self) -> Option<runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3> {
        match &self.0.process.as_ref()?.activation {
            ProtectedProcessActivation::V3 { owned, .. } => Some(owned.clone()),
            _ => None,
        }
    }
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
    let (supervisor, peer, _, _, _) = ready_v3_parts(test_id(13), false);
    drop(peer);
    TestOnlyReadyV3EnrollmentSupervisor(
        supervisor,
        credential_service_session::bounded_session_expiry_unix_millis(
            credential_service_session::unix_millis().expect("clock"),
        )
        .expect("expiry"),
    )
}

/// Builds a real Ready-V3 supervisor whose channel remains connected to a
/// daemon-side endpoint. No native service or credential mutation is involved.
#[doc(hidden)]
#[must_use]
pub fn test_only_connected_ready_v3_enrollment_supervisor(
) -> TestOnlyConnectedReadyV3EnrollmentSupervisor {
    let (supervisor, daemon_channel, keys, owned, installed) =
        ready_v3_parts(*uuid::Uuid::now_v7().as_bytes(), true);
    TestOnlyConnectedReadyV3EnrollmentSupervisor {
        supervisor,
        daemon_channel,
        keys,
        owned,
        installed,
    }
}

fn ready_v3_parts(
    session_id: [u8; 16],
    with_broker_facts: bool,
) -> (
    ProtectedBundledRuntimeSupervisor,
    std::os::unix::net::UnixStream,
    runne_api::ProtectedActivationKeys,
    runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    crate::VerifiedInstalledEnrollmentMeasurementFacts,
) {
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
        session_id, "https://127.0.0.1:43123", sha2::Sha256::digest([15; 32]).into(),
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
    let owned = ready.owned_launch();
    let activation = decoded.into_process_activation(desktop).expect("activation");
    let child = std::process::Command::new("/bin/sleep").arg("30").spawn().expect("child");
    let (channel, peer) = std::os::unix::net::UnixStream::pair().expect("channel");
    channel.set_read_timeout(Some(std::time::Duration::from_secs(2))).expect("timeout");
    let process = ProtectedBundledRuntimeProcess {
        child, channel, keys: keys.clone(), activation, runtime_profile: None, renewal_sequence: 0,
        #[cfg(feature = "protected-channel-integration")]
        root_control_sequence: 0,
        graceful_requested: false, graceful_acknowledged: false,
        enrollment_broker_facts: with_broker_facts
            .then(|| EnrollmentBrokerFacts::new([31; 32], [32; 32])),
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
        credential_service_rejoin: None,
    };
    let _ = std::fs::remove_dir(root);
    let installed = crate::updater_metadata::VerifiedInstalledEnrollmentMeasurementFacts::for_connected_relay_test(
        *owned.enrollment_binding().release_tuple_digest(),
    );
    (supervisor, peer, keys, owned, installed)
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
    TestOnlyReadyV3EnrollmentSupervisor(supervisor,
        credential_service_session::bounded_session_expiry_unix_millis(
            credential_service_session::unix_millis().expect("clock"),
        ).expect("expiry"))
}

const fn test_id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}
