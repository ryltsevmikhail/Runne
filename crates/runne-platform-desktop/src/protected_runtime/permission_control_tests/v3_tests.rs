use super::*;

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
