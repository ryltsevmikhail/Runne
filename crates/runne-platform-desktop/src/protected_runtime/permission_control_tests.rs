use super::*;
use std::{os::unix::net::UnixStream, time::Duration};

#[path = "permission_consent_recovery_tests.rs"]
mod permission_consent_recovery_tests;

fn connected_ready_v3_supervisor() -> (
    ProtectedBundledRuntimeSupervisor,
    UnixStream,
    runne_api::ProtectedActivationKeys,
    runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
) {
    let (channel, daemon) = UnixStream::pair().unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    daemon
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (process, keys) = v3_process(channel);
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!("V3 test fixture");
    };
    let owned = owned.clone();
    let root = std::env::temp_dir().join(format!("runne-mode-control-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let spec =
        ProtectedBundledRuntimeLaunchSpec::new(std::path::Path::new("/bin/sleep"), &root).unwrap();
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
    let _ = std::fs::remove_dir(root);
    (supervisor, daemon, keys, owned)
}

fn pending_context(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    epoch: u64,
) -> PermissionModeNativePendingV2 {
    let principal = ApiPrincipalId::new(owned.stable().principal_id().to_owned()).unwrap();
    let now = unix_millis().unwrap();
    let workspace = *uuid::Uuid::now_v7().as_bytes();
    PermissionModeNativePendingV2 {
        workspace_id: uuid::Uuid::from_bytes(workspace).to_string(),
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
            idempotency_key: "mode-change-1".to_owned(),
            public_request_digest: [4; 32],
            predecessor_transcript_digest: [0; 32],
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 20_000,
        },
    }
}

fn mode_challenge(
    pending: &PermissionModeNativePendingV2,
    context: &PermissionControlContextV1,
) -> PermissionControlModeChallengeV1 {
    PermissionControlModeChallengeV1 {
        principal: pending.principal_id.clone(),
        workspace_id: *uuid::Uuid::parse_str(&pending.workspace_id)
            .unwrap()
            .as_bytes(),
        workspace_label: "workspace".to_owned(),
        expected_authorization_revision: 0,
        requested_mode: runne_api::PermissionModeSelectionV1::RiskBased,
        preset_version: 1,
        mode_expires_at_unix_ms: None,
        managed_policy_revision: 0,
        managed_policy_digest: [5; 32],
        issued_challenge_binding_digest: [6; 32],
        ceremony_expires_at_unix_ms: context.expires_at_unix_ms,
        native_warning_version: 1,
        challenge_id: *uuid::Uuid::now_v7().as_bytes(),
        nonce: [7; 32],
    }
}

#[test]
fn verified_v3_owner_exchanges_exact_mode_request_and_challenge() {
    let (mut supervisor, mut daemon, keys, owned) = connected_ready_v3_supervisor();
    let epoch = keys
        .permission_control_native_authenticator()
        .native_key_epoch();
    let pending = pending_context(&owned, epoch);
    let context = pending.context.control_context().unwrap();
    let auth =
        PermissionControlAuthenticatorV1::from_protected_activation(&keys, Purpose::ModeControl);
    let server_pending = pending.clone();
    let server = std::thread::spawn(move || {
        let wire_request = read_frame(&mut daemon).unwrap();
        let request = permission_wire_inner_frame(&wire_request).unwrap();
        let authenticated = auth
            .authenticate_frame(
                &request,
                &context,
                Purpose::ModeControl,
                Phase::Request,
                Direction::DesktopToDaemon,
                0,
                unix_millis().unwrap(),
            )
            .unwrap();
        assert!(matches!(authenticated.payload(), Payload::ModeRequest(_)));
        let mut corrupt = request.to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            auth.mode_request_routing_hint(&corrupt, 0, unix_millis().unwrap())
                .is_err()
        );
        let mut challenge_context = context.clone();
        challenge_context.predecessor_transcript_digest = Sha256::digest(&request[..]).into();
        let challenge = mode_challenge(&server_pending, &context);
        let reply = auth
            .issue_frame(
                challenge_context,
                1,
                Direction::DaemonToDesktop,
                Payload::ModeChallenge(challenge.clone()),
            )
            .unwrap();
        let wire_reply = permission_wire_outer_frame(&reply).unwrap();
        write_frame(&mut daemon, &wire_reply).unwrap();
        let wire_cancel = read_frame(&mut daemon).unwrap();
        let cancel = permission_wire_inner_frame(&wire_cancel).unwrap();
        let mut cancel_context = context.clone();
        cancel_context.predecessor_transcript_digest = Sha256::digest(&reply).into();
        let authenticated = auth
            .authenticate_frame(
                &cancel,
                &cancel_context,
                Purpose::ModeControl,
                Phase::Cancel,
                Direction::DesktopToDaemon,
                1,
                unix_millis().unwrap(),
            )
            .unwrap();
        assert!(matches!(authenticated.payload(), Payload::Cancel));
        cancel_context.predecessor_transcript_digest = Sha256::digest(&cancel).into();
        let result = runne_api::PermissionControlResultV1 {
            code: runne_api::PermissionControlResultCodeV1::Cancelled,
            command_id: cancel_context.command_id,
            public_request_digest: cancel_context.public_request_digest,
            receipt_digest: None,
            authorization_revision: None,
            managed_policy_revision: None,
        };
        let reply = auth
            .issue_frame(
                cancel_context,
                2,
                Direction::DaemonToDesktop,
                Payload::Result(result.clone()),
            )
            .unwrap();
        let wire_reply = permission_wire_outer_frame(&reply).unwrap();
        write_frame(&mut daemon, &wire_reply).unwrap();
        (challenge, result)
    });
    let challenge = supervisor
        .request_permission_mode_challenge(&pending)
        .unwrap();
    let result = supervisor.cancel_permission_mode().unwrap();
    let (expected_challenge, expected_result) = server.join().unwrap();
    assert!(challenge == expected_challenge);
    assert!(result == expected_result);
}

#[test]
fn request_rejects_pending_context_from_another_session_before_write() {
    let (mut supervisor, mut daemon, keys, owned) = connected_ready_v3_supervisor();
    let epoch = keys
        .permission_control_native_authenticator()
        .native_key_epoch();
    let mut pending = pending_context(&owned, epoch);
    pending.context.protected_session_id = *uuid::Uuid::now_v7().as_bytes();
    assert!(matches!(
        supervisor.request_permission_mode_challenge(&pending),
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    ));
    assert!(read_frame(&mut daemon).is_err());
    let inner = [0, 0, 0, 4];
    let wire = permission_wire_outer_frame(&inner).unwrap();
    assert_eq!(&permission_wire_inner_frame(&wire).unwrap()[..], &inner);
    assert!(permission_wire_inner_frame(&wire[..3]).is_err());
    assert!(permission_wire_inner_frame(&[0, 0, 0, 5, 0, 0, 0, 4]).is_err());
    assert!(permission_wire_inner_frame(&[0, 0, 0, 4, 0, 0, 0, 5]).is_err());
    let mut double = vec![0; wire.len() + 4];
    double[..4].copy_from_slice(&u32::try_from(wire.len()).unwrap().to_be_bytes());
    double[4..].copy_from_slice(&wire);
    assert!(permission_wire_inner_frame(&double).is_err());
    let oversized = vec![0; MAX_FRAME_PAYLOAD_BYTES + 5];
    assert!(permission_wire_inner_frame(&oversized).is_err());
}

#[test]
fn consent_result_uses_outer_wire_but_authenticates_inner_frames() {
    let (mut supervisor, mut daemon, keys, owned) = connected_ready_v3_supervisor();
    let pending = pending_context(
        &owned,
        keys.permission_control_native_authenticator()
            .native_key_epoch(),
    );
    let mut context = pending.context.control_context().unwrap();
    let control_owner = supervisor
        .process
        .as_ref()
        .unwrap()
        .permission_control_owner()
        .unwrap();
    let auth =
        PermissionControlAuthenticatorV1::from_protected_activation(&keys, Purpose::ModeControl);
    let challenge = mode_challenge(&pending, &context);
    context.predecessor_transcript_digest = [11; 32];
    let exchange = PermissionModeExchangeV1 {
        owner: control_owner,
        context: context.clone(),
        challenge: challenge.clone(),
    };
    let consent = runne_api::PermissionControlModeConsentV1 {
        challenge_id: challenge.challenge_id,
        public_request_digest: context.public_request_digest,
        issued_challenge_binding_digest: challenge.issued_challenge_binding_digest,
        native_warning_version: challenge.native_warning_version,
        requested_mode: challenge.requested_mode,
        confirmed_binding_digest: [8; 32],
        warning_attestation: [9; 32],
        os_attestation: runne_api::ModeOsAttestationV1::NotRequired,
    };
    let server_context = context;
    let server_auth = auth;
    let server = std::thread::spawn(move || {
        let wire = read_frame(&mut daemon).unwrap();
        let inner = permission_wire_inner_frame(&wire).unwrap();
        assert!(matches!(
            server_auth
                .authenticate_frame(
                    &inner,
                    &server_context,
                    Purpose::ModeControl,
                    Phase::Consent,
                    Direction::DesktopToDaemon,
                    1,
                    unix_millis().unwrap(),
                )
                .unwrap()
                .payload(),
            Payload::ModeConsent(_)
        ));
        let mut result_context = server_context;
        result_context.predecessor_transcript_digest = Sha256::digest(&inner[..]).into();
        let result = PermissionControlResultV1 {
            code: PermissionControlResultCodeV1::Committed,
            command_id: result_context.command_id,
            public_request_digest: result_context.public_request_digest,
            receipt_digest: Some([10; 32]),
            authorization_revision: Some(1),
            managed_policy_revision: Some(0),
        };
        let inner = server_auth
            .issue_frame(
                result_context,
                2,
                Direction::DaemonToDesktop,
                Payload::Result(result.clone()),
            )
            .unwrap();
        write_frame(&mut daemon, &permission_wire_outer_frame(&inner).unwrap()).unwrap();
        result
    });
    let mut sent = false;
    let (result, sequence) = supervisor
        .process
        .as_mut()
        .unwrap()
        .finish_permission_mode_exchange(&exchange, 1, Payload::ModeConsent(consent), &mut sent)
        .unwrap();
    assert!(sent);
    assert_eq!(sequence, 2);
    assert!(result == server.join().unwrap());
}

fn connected_ready_v1_supervisor() -> (
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

fn pending_context_v1(
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

fn server_issue_challenge(
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

fn server_cancel(
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

#[test]
fn verified_v1_owner_cancels_then_starts_the_next_exchange() {
    let (mut supervisor, mut daemon, keys, owned) = connected_ready_v1_supervisor();
    let epoch = keys
        .permission_control_native_authenticator()
        .native_key_epoch();
    let pending1 = pending_context_v1(&owned, epoch);
    let pending2 = pending_context_v1(&owned, epoch);
    let server_pending1 = pending1.clone();
    let server_pending2 = pending2.clone();
    let server_keys = keys;
    let server = std::thread::spawn(move || {
        let server_auth = PermissionControlAuthenticatorV1::from_protected_activation(
            &server_keys,
            Purpose::ModeControl,
        );
        let first = server_issue_challenge(&mut daemon, &server_auth, &server_pending1, 0);
        server_cancel(&mut daemon, &server_auth, first, 1);
        let second = server_issue_challenge(&mut daemon, &server_auth, &server_pending2, 2);
        server_cancel(&mut daemon, &server_auth, second, 3);
    });

    supervisor
        .request_permission_mode_challenge(&pending1)
        .unwrap();
    assert!(
        supervisor.cancel_permission_mode().unwrap().code
            == PermissionControlResultCodeV1::Cancelled
    );
    supervisor
        .request_permission_mode_challenge(&pending2)
        .unwrap();
    assert!(
        supervisor.cancel_permission_mode().unwrap().code
            == PermissionControlResultCodeV1::Cancelled
    );
    server.join().unwrap();
    let sequence = supervisor.permission_control_sequence.as_ref().unwrap();
    assert_eq!(sequence.last_authenticated_sequence, 4);
    assert!(sequence.active.is_none());
    let child = &mut supervisor.process.as_mut().unwrap().child;
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one V1 renewal scenario checks stale and renewed session exchanges"
)]
fn v1_renewal_rejects_old_consent_and_request_then_keeps_sequence_for_new_session() {
    let (mut supervisor, mut daemon, keys, owned) = connected_ready_v1_supervisor();
    let epoch = keys
        .permission_control_native_authenticator()
        .native_key_epoch();
    let old_pending = pending_context_v1(&owned, epoch);
    let server_old_pending = old_pending.clone();
    let server_keys = keys;
    let server_owned = owned;
    let (owned_sender, owned_receiver) = std::sync::mpsc::channel();
    let (pending_sender, pending_receiver) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let server_auth = PermissionControlAuthenticatorV1::from_protected_activation(
            &server_keys,
            Purpose::ModeControl,
        );
        server_issue_challenge(&mut daemon, &server_auth, &server_old_pending, 0);
        let renewal_frame = read_frame(&mut daemon).unwrap();
        let renewal = ProtectedRenewRequestV1::decode_frame(&renewal_frame).unwrap();
        renewal
            .verify_exact(&server_owned, 0, &server_keys)
            .unwrap();
        let issued = unix_millis().unwrap();
        let mut ticket = ProtectedRenewTicketV1::new(
            &renewal,
            *uuid::Uuid::now_v7().as_bytes(),
            [19; 32],
            issued,
            issued + 30_000,
        )
        .unwrap();
        let next_owned = ticket.next_owned_launch();
        owned_sender.send(next_owned).unwrap();
        ticket.sign(&server_keys);
        write_frame(&mut daemon, &ticket.encode_frame().unwrap()).unwrap();
        let new_pending = pending_receiver.recv().unwrap();
        let next = server_issue_challenge(&mut daemon, &server_auth, &new_pending, 1);
        server_cancel(&mut daemon, &server_auth, next, 2);
    });

    let stale_challenge = supervisor
        .request_permission_mode_challenge(&old_pending)
        .unwrap();
    let stale_exchange = supervisor
        .permission_control_sequence
        .as_ref()
        .unwrap()
        .active
        .clone()
        .unwrap();
    assert!(stale_exchange.challenge == stale_challenge);
    supervisor
        .process
        .as_mut()
        .unwrap()
        .renew_profile()
        .unwrap();
    let next_owned = owned_receiver.recv().unwrap();
    let warning = crate::permission_reauth_linux::mock_native_permission_warning_confirmation(
        &stale_exchange.challenge,
        &stale_exchange.context,
    )
    .unwrap();
    assert!(matches!(
        supervisor.complete_permission_mode_consent_with_consumer(
            warning,
            None,
            |token, digest| {
                token
                    .consume_verified(digest, [0xa7; 32])
                    .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)
            }
        ),
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    ));
    assert!(matches!(
        supervisor.request_permission_mode_challenge(&old_pending),
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    ));
    let sequence = supervisor.permission_control_sequence.as_ref().unwrap();
    assert_eq!(sequence.last_authenticated_sequence, 1);
    assert!(sequence.active.is_none());
    let new_pending = pending_context_v1(&next_owned, epoch);
    pending_sender.send(new_pending.clone()).unwrap();
    supervisor
        .request_permission_mode_challenge(&new_pending)
        .unwrap();
    assert!(
        supervisor.cancel_permission_mode().unwrap().code
            == PermissionControlResultCodeV1::Cancelled
    );
    server.join().unwrap();
    assert_eq!(
        supervisor
            .permission_control_sequence
            .as_ref()
            .unwrap()
            .last_authenticated_sequence,
        3
    );
    let child = &mut supervisor.process.as_mut().unwrap().child;
    let _ = child.kill();
    let _ = child.wait();
}
