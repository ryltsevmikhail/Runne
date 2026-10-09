use super::*;
use std::{os::unix::net::UnixStream, time::Duration};

const MOCK_FINGERPRINT: [u8; 32] = [0xa7; 32];

fn ready_supervisor() -> (
    ProtectedBundledRuntimeSupervisor,
    UnixStream,
    runne_api::ProtectedActivationKeys,
    runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
) {
    let (channel, daemon) = UnixStream::pair().unwrap();
    let timeout = Some(Duration::from_secs(2));
    channel.set_read_timeout(timeout).unwrap();
    daemon.set_read_timeout(timeout).unwrap();
    let (process, keys) = v3_process(channel);
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!("V3 fixture");
    };
    let owned = owned.clone();
    let root = std::env::temp_dir().join(format!("mode-mock-{}", uuid::Uuid::now_v7()));
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

fn pending(
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
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
            native_key_epoch: 0,
            command_id: uuid::Uuid::now_v7().to_string(),
            idempotency_key: "mode-mock-test".to_owned(),
            public_request_digest: [4; 32],
            predecessor_transcript_digest: [0; 32],
            issued_at_unix_ms: now,
            expires_at_unix_ms: now + 20_000,
        },
    }
}

fn challenge(
    pending: &PermissionModeNativePendingV2,
    context: &PermissionControlContextV1,
    mode: runne_api::PermissionModeSelectionV1,
) -> PermissionControlModeChallengeV1 {
    PermissionControlModeChallengeV1 {
        principal: pending.principal_id.clone(),
        workspace_id: *uuid::Uuid::parse_str(&pending.workspace_id)
            .unwrap()
            .as_bytes(),
        workspace_label: "workspace".to_owned(),
        expected_authorization_revision: 0,
        requested_mode: mode,
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

#[expect(
    clippy::too_many_lines,
    reason = "This fixture exercises one complete authenticated permission-mode exchange."
)]
fn run_mode(mode: runne_api::PermissionModeSelectionV1) {
    let (mut supervisor, mut daemon, keys, owned) = ready_supervisor();
    let epoch = keys
        .permission_control_native_authenticator()
        .native_key_epoch();
    let mut pending = pending(&owned);
    pending.context.native_key_epoch = epoch;
    let server_pending = pending.clone();
    let server_auth =
        PermissionControlAuthenticatorV1::from_protected_activation(&keys, Purpose::ModeControl);
    let server = std::thread::spawn(move || {
        let mut context = server_pending.context.control_context().unwrap();
        let auth = server_auth;
        let request_wire = read_frame(&mut daemon).unwrap();
        let request = permission_wire_inner_frame(&request_wire).unwrap();
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
        context.predecessor_transcript_digest = Sha256::digest(&request[..]).into();
        let challenge = challenge(&server_pending, &context, mode);
        let challenge_frame = auth
            .issue_frame(
                context.clone(),
                1,
                Direction::DaemonToDesktop,
                Payload::ModeChallenge(challenge),
            )
            .unwrap();
        let challenge_wire = permission_wire_outer_frame(&challenge_frame).unwrap();
        write_frame(&mut daemon, &challenge_wire).unwrap();
        context.predecessor_transcript_digest = Sha256::digest(&challenge_frame[..]).into();
        let consent_wire = read_frame(&mut daemon).unwrap();
        let consent_frame = permission_wire_inner_frame(&consent_wire).unwrap();
        let authenticated = auth
            .authenticate_frame(
                &consent_frame,
                &context,
                Purpose::ModeControl,
                Phase::Consent,
                Direction::DesktopToDaemon,
                1,
                unix_millis().unwrap(),
            )
            .unwrap();
        let Payload::ModeConsent(consent) = authenticated.payload() else {
            panic!("mock completion must send consent");
        };
        assert!(consent.requested_mode == mode);
        if mode == runne_api::PermissionModeSelectionV1::FullAccess {
            let runne_api::ModeOsAttestationV1::Fresh {
                qualified_fingerprint,
                authenticated_at_unix_ms,
            } = &consent.os_attestation
            else {
                panic!("FullAccess requires mock fresh PAM evidence");
            };
            assert_eq!(*qualified_fingerprint, MOCK_FINGERPRINT);
            assert!(*authenticated_at_unix_ms >= context.issued_at_unix_ms);
        } else {
            assert!(matches!(
                &consent.os_attestation,
                runne_api::ModeOsAttestationV1::NotRequired
            ));
        }
        context.predecessor_transcript_digest = Sha256::digest(&consent_frame[..]).into();
        let result = PermissionControlResultV1 {
            code: PermissionControlResultCodeV1::Committed,
            command_id: context.command_id,
            public_request_digest: context.public_request_digest,
            receipt_digest: Some([8; 32]),
            authorization_revision: Some(1),
            managed_policy_revision: Some(1),
        };
        let result_frame = auth
            .issue_frame(
                context,
                2,
                Direction::DaemonToDesktop,
                Payload::Result(result.clone()),
            )
            .unwrap();
        let result_wire = permission_wire_outer_frame(&result_frame).unwrap();
        write_frame(&mut daemon, &result_wire).unwrap();
        result
    });
    let challenge = supervisor
        .request_permission_mode_challenge(&pending)
        .unwrap();
    assert!(challenge.requested_mode == mode);
    let result = supervisor
        .test_complete_permission_mode_with_mock_native_authority()
        .unwrap();
    assert!(result.code == PermissionControlResultCodeV1::Committed);
    assert!(matches!(
        supervisor.test_complete_permission_mode_with_mock_native_authority(),
        Err(ProtectedBundledRuntimeError::InvalidState)
    ));
    assert!(result == server.join().unwrap());
}

#[test]
fn mock_native_authority_completes_each_current_mode_exchange() {
    run_mode(runne_api::PermissionModeSelectionV1::AskAlways);
    run_mode(runne_api::PermissionModeSelectionV1::RiskBased);
    run_mode(runne_api::PermissionModeSelectionV1::FullAccess);
}

#[test]
fn mock_completion_rejects_missing_or_expired_active_exchange() {
    let (mut supervisor, _daemon, _keys, _owned) = ready_supervisor();
    assert!(matches!(
        supervisor.test_complete_permission_mode_with_mock_native_authority(),
        Err(ProtectedBundledRuntimeError::InvalidState)
    ));

    let (mut supervisor, _daemon, _keys, owned) = ready_supervisor();
    let mut pending = pending(&owned);
    let now = unix_millis().unwrap();
    pending.context.issued_at_unix_ms = now.saturating_sub(5_000);
    pending.context.expires_at_unix_ms = now.saturating_sub(1);
    let context = pending.context.control_context().unwrap();
    let mut challenge = challenge(
        &pending,
        &context,
        runne_api::PermissionModeSelectionV1::RiskBased,
    );
    challenge.ceremony_expires_at_unix_ms = context.expires_at_unix_ms;
    let control_owner = supervisor
        .process
        .as_ref()
        .unwrap()
        .permission_control_owner()
        .unwrap();
    supervisor.permission_control_sequence = Some(PermissionControlSequenceV1 {
        owner: control_owner,
        last_authenticated_sequence: 1,
        active: Some(PermissionModeExchangeV1 {
            owner: control_owner,
            context,
            challenge,
        }),
    });
    assert!(matches!(
        supervisor.test_complete_permission_mode_with_mock_native_authority(),
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    ));
}
