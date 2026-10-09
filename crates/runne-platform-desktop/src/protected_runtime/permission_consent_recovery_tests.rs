use super::*;
use std::{
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

#[test]
fn prewrite_consent_rejections_cancel_and_allow_the_next_challenge() {
    for failure in [
        PreparationFailure::RejectedOsEvidence,
        PreparationFailure::MissingOsEvidence,
        PreparationFailure::MismatchedWarning,
    ] {
        exercise_preparation_failure(failure);
    }
}

#[derive(Clone, Copy)]
enum PreparationFailure {
    RejectedOsEvidence,
    MissingOsEvidence,
    MismatchedWarning,
}

fn exercise_preparation_failure(failure: PreparationFailure) {
    let (mut supervisor, mut daemon, keys, owned) = connected_ready_v3_supervisor();
    let initial_mode = match failure {
        PreparationFailure::MismatchedWarning => runne_api::PermissionModeSelectionV1::RiskBased,
        PreparationFailure::RejectedOsEvidence | PreparationFailure::MissingOsEvidence => {
            runne_api::PermissionModeSelectionV1::FullAccess
        }
    };
    let epoch = keys
        .permission_control_native_authenticator()
        .native_key_epoch();
    let pending = pending_context(&owned, epoch);
    let retry_pending = pending_context(&owned, epoch);
    let server_pending = pending.clone();
    let server_retry_pending = retry_pending.clone();
    let server_auth =
        PermissionControlAuthenticatorV1::from_protected_activation(&keys, Purpose::ModeControl);
    let server = std::thread::spawn(move || {
        let context = serve_challenge(&mut daemon, &server_auth, &server_pending, 0, initial_mode);
        serve_cancel(&mut daemon, &server_auth, context, 1);
        let context = serve_challenge(
            &mut daemon,
            &server_auth,
            &server_retry_pending,
            2,
            runne_api::PermissionModeSelectionV1::RiskBased,
        );
        serve_cancel(&mut daemon, &server_auth, context, 3);
    });

    let challenge = supervisor
        .request_permission_mode_challenge(&pending)
        .unwrap();
    assert!(challenge.requested_mode == initial_mode);
    let exchange = supervisor.current_permission_mode_exchange().unwrap().0;
    let warning = crate::permission_reauth_linux::mock_native_permission_warning_confirmation(
        &exchange.challenge,
        &exchange.context,
    )
    .unwrap();
    let cancelled = match failure {
        PreparationFailure::RejectedOsEvidence => {
            let now = Instant::now();
            let token = runne_linux_pam::FreshOsReauthentication::test_fixture(
                exchange.challenge.issued_challenge_binding_digest,
                rustix::process::geteuid().as_raw(),
                [0x72; 32],
                unix_millis().unwrap(),
                now + Duration::from_secs(5),
                now,
            );
            let consume_called = std::cell::Cell::new(false);
            let result = supervisor.complete_permission_mode_consent_with_consumer(
                warning,
                Some(token),
                |_, _| {
                    consume_called.set(true);
                    Err(ProtectedBundledRuntimeError::OwnershipMismatch)
                },
            );
            assert!(consume_called.get());
            result
        }
        PreparationFailure::MissingOsEvidence => {
            supervisor.complete_permission_mode_consent(warning, None)
        }
        PreparationFailure::MismatchedWarning => {
            supervisor
                .permission_control_sequence
                .as_mut()
                .unwrap()
                .active
                .as_mut()
                .unwrap()
                .challenge
                .requested_mode = runne_api::PermissionModeSelectionV1::FullAccess;
            supervisor.complete_permission_mode_consent(warning, None)
        }
    }
    .expect("pre-write validation failure returns the authenticated cancel result");
    assert!(cancelled.code == PermissionControlResultCodeV1::Cancelled);
    assert!(supervisor.current_permission_mode_exchange().is_err());

    let retry = supervisor
        .request_permission_mode_challenge(&retry_pending)
        .expect("authenticated cancel clears the previous active challenge");
    assert!(retry.requested_mode == runne_api::PermissionModeSelectionV1::RiskBased);
    let second_cancel = supervisor.cancel_permission_mode().unwrap();
    assert!(second_cancel.code == PermissionControlResultCodeV1::Cancelled);
    assert!(supervisor.current_permission_mode_exchange().is_err());
    server.join().unwrap();
}

fn serve_challenge(
    daemon: &mut UnixStream,
    auth: &PermissionControlAuthenticatorV1,
    pending: &PermissionModeNativePendingV2,
    previous_sequence: u64,
    mode: runne_api::PermissionModeSelectionV1,
) -> PermissionControlContextV1 {
    let mut context = pending.context.control_context().unwrap();
    let wire_request = read_frame(daemon).unwrap();
    let request = permission_wire_inner_frame(&wire_request).unwrap();
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
    context.predecessor_transcript_digest = Sha256::digest(&request[..]).into();
    let mut challenge = mode_challenge(pending, &context);
    challenge.requested_mode = mode;
    let frame = auth
        .issue_frame(
            context.clone(),
            previous_sequence + 1,
            Direction::DaemonToDesktop,
            Payload::ModeChallenge(challenge),
        )
        .unwrap();
    write_frame(daemon, &permission_wire_outer_frame(&frame).unwrap()).unwrap();
    context.predecessor_transcript_digest = Sha256::digest(&frame[..]).into();
    context
}

fn serve_cancel(
    daemon: &mut UnixStream,
    auth: &PermissionControlAuthenticatorV1,
    mut context: PermissionControlContextV1,
    previous_sequence: u64,
) {
    let wire_cancel = read_frame(daemon).unwrap();
    let cancel = permission_wire_inner_frame(&wire_cancel).unwrap();
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
    let result = PermissionControlResultV1 {
        code: PermissionControlResultCodeV1::Cancelled,
        command_id: context.command_id,
        public_request_digest: context.public_request_digest,
        receipt_digest: None,
        authorization_revision: None,
        managed_policy_revision: None,
    };
    let frame = auth
        .issue_frame(
            context,
            previous_sequence + 1,
            Direction::DaemonToDesktop,
            Payload::Result(result),
        )
        .unwrap();
    write_frame(daemon, &permission_wire_outer_frame(&frame).unwrap()).unwrap();
}
