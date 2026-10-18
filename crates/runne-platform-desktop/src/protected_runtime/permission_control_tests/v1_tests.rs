use super::*;

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
