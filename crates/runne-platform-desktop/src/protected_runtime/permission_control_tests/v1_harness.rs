use super::*;

pub(super) fn connected_ready_v1_supervisor() -> (
    ProtectedBundledRuntimeSupervisor,
    UnixStream,
    runne_api::ProtectedActivationKeys,
    runne_api::ProtectedOwnedLaunchV1,
) {
    let (channel, daemon) = UnixStream::pair().unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    daemon
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let profile = expected_profile().unwrap();
    let request = runne_api::ProtectedLaunchRequestV1::new(
        id(1),
        id(2),
        runne_api::LaunchSecret::from_bytes([3; 32]).unwrap(),
        10,
        20,
        "permission-v1-test",
        profile.clone(),
        runne_api::ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
        std::path::PathBuf::from("/tmp/runtime"),
        runne_api::ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let keys = request.derive_keys();
    let stable = runne_api::StableRuntimeBindingV1::new(
        id(10),
        "permission-v1-test",
        id(11),
        profile.profile_id(),
        *profile.profile_hash(),
        *profile.capability_digest(),
    )
    .unwrap();
    let mut ready = runne_api::ProtectedReadyV1::new(
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
            .map(|value| (*value).to_owned())
            .collect(),
    )
    .unwrap();
    ready.sign(&keys);
    let owned = ready.owned_launch();
    let launch = DesktopLaunchRequest::V1(request);
    let decoded = launch
        .decode_ready(&ready.encode_frame().unwrap(), &keys)
        .unwrap();
    let activation = decoded.into_process_activation(launch).unwrap();
    assert!(matches!(activation, ProtectedProcessActivation::V1 { .. }));
    let child = Command::new("/bin/sh")
        .args(["-c", "sleep 60"])
        .spawn()
        .unwrap();
    let process = ProtectedBundledRuntimeProcess {
        child,
        #[cfg(target_os = "linux")]
        linux_launch_image: None,
        channel,
        keys: keys.clone(),
        activation,
        runtime_profile: None,
        renewal_sequence: 0,
        #[cfg(feature = "protected-channel-integration")]
        root_control_sequence: 0,
        graceful_requested: false,
        graceful_acknowledged: false,
        enrollment_broker_facts: None,
        #[cfg(feature = "test-support")]
        captured_stdout: None,
        #[cfg(feature = "test-support")]
        captured_stderr: None,
    };
    let root = std::env::temp_dir().join(format!("runne-mode-control-v1-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(std::path::Path::new("/bin/sleep"), &root).unwrap();
    let _ = std::fs::remove_dir(root);
    let supervisor = ProtectedBundledRuntimeSupervisor {
        launcher: DevelopmentBundledRuntimeLauncher::new(),
        spec,
        process: Some(process),
        pending_profile: None,
        backoff: BundledRuntimeBackoff::new(),
        restart_at: None,
        state: BundledRuntimeLifecycleState::Ready,
        permission_control_sequence: None,
    };
    (supervisor, daemon, keys, owned)
}

pub(super) fn pending_context_v1(
    owned: &runne_api::ProtectedOwnedLaunchV1,
    epoch: u64,
) -> PermissionModeNativePendingV2 {
    let principal = ApiPrincipalId::new(owned.stable().principal_id().to_owned()).unwrap();
    let now = unix_millis().unwrap();
    PermissionModeNativePendingV2 {
        workspace_id: uuid::Uuid::now_v7().to_string(),
        principal_id: principal.as_str().to_owned(),
        context: runne_api::PermissionModeNativePendingContextV2 {
            runtime_authority: hex::encode(owned.stable().authority_id()),
            store_lineage_id: *owned.stable().lineage_id(),
            stable_subject_digest: permission_control_stable_subject_digest_v1(&principal).unwrap(),
            protected_launch_authority_id: *owned.launch_authority_id(),
            desktop_authority_id: *owned.desktop_host_instance_id(),
            daemon_instance_id: *owned.daemon_instance_id(),
            protected_session_id: *owned.session_id(),
            launch_generation: owned.launch_generation(),
            native_key_epoch: epoch,
            command_id: uuid::Uuid::now_v7().to_string(),
            idempotency_key: format!("mode-{}", uuid::Uuid::now_v7()),
            public_request_digest: [4; 32],
            predecessor_transcript_digest: [0; 32],
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 20_000,
        },
    }
}

pub(super) fn server_issue_challenge(
    daemon: &mut UnixStream,
    auth: &PermissionControlAuthenticatorV1,
    pending: &PermissionModeNativePendingV2,
    previous_sequence: u64,
) -> PermissionControlContextV1 {
    let wire = read_frame(daemon).unwrap();
    let request = permission_wire_inner_frame(&wire).unwrap();
    let context = pending.context.control_context().unwrap();
    let authenticated = auth
        .authenticate_frame(
            &request,
            &context,
            Purpose::ModeControl,
            Phase::Request,
            Direction::DesktopToDaemon,
            previous_sequence,
            unix_millis().unwrap(),
        )
        .unwrap();
    assert!(matches!(authenticated.payload(), Payload::ModeRequest(_)));
    let mut challenge_context = context;
    challenge_context.predecessor_transcript_digest = Sha256::digest(&request[..]).into();
    let challenge = mode_challenge(pending, &challenge_context);
    let sequence = previous_sequence + 1;
    let response = auth
        .issue_frame(
            challenge_context,
            sequence,
            Direction::DaemonToDesktop,
            Payload::ModeChallenge(challenge),
        )
        .unwrap();
    let response = permission_wire_outer_frame(&response).unwrap();
    let mut context = pending.context.control_context().unwrap();
    context.predecessor_transcript_digest =
        Sha256::digest(&permission_wire_inner_frame(&response).unwrap()[..]).into();
    write_frame(daemon, &response).unwrap();
    context
}

pub(super) fn server_cancel(
    daemon: &mut UnixStream,
    auth: &PermissionControlAuthenticatorV1,
    mut context: PermissionControlContextV1,
    previous_sequence: u64,
) {
    let wire = read_frame(daemon).unwrap();
    let cancel = permission_wire_inner_frame(&wire).unwrap();
    let authenticated = auth
        .authenticate_frame(
            &cancel,
            &context,
            Purpose::ModeControl,
            Phase::Cancel,
            Direction::DesktopToDaemon,
            previous_sequence,
            unix_millis().unwrap(),
        )
        .unwrap();
    assert!(matches!(authenticated.payload(), Payload::Cancel));
    context.predecessor_transcript_digest = Sha256::digest(&cancel[..]).into();
    let response = auth
        .issue_frame(
            context.clone(),
            previous_sequence + 1,
            Direction::DaemonToDesktop,
            Payload::Result(PermissionControlResultV1 {
                code: PermissionControlResultCodeV1::Cancelled,
                command_id: context.command_id,
                public_request_digest: context.public_request_digest,
                receipt_digest: None,
                authorization_revision: None,
                managed_policy_revision: None,
            }),
        )
        .unwrap();
    write_frame(daemon, &permission_wire_outer_frame(&response).unwrap()).unwrap();
}
