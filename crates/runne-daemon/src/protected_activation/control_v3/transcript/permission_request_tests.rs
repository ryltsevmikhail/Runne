use super::*;
use runne_api::protected_activation::permission_control_v1::{
    PermissionControlAuthenticatorV1 as Authenticator, PermissionControlDirectionV1 as Direction,
    PermissionControlPayloadV1 as Payload, PermissionControlPhaseV1 as Phase,
    PermissionControlPurposeV1 as Purpose,
};
use runne_api::{ApiPrincipalId, PermissionControlModeRequestV1, ProtectedOwnedLaunchV1};
use runne_application::{
    local_session::LocalSessionService,
    permission_modes::{PermissionMode, PermissionScope, PresetVersion},
    ports::{ProjectWorkspaceRepository, RuntimeAuthorityId},
    project_trust::{ProjectTrustPersistence, ProjectTrustProjectId, ProjectTrustStatus},
};
use runne_domain::{
    id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId},
    project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace},
};
use runne_security::SecretBroker;
use runne_store::{
    ProjectTrustStore, ProjectWorkspaceStore, schema,
    store::{
        NativeModeConfirmationRequestV2, PermissionModeAuthorityContext,
        ProtectedNativeLaunchContext, StoreTransaction,
    },
};
use sha2::Digest;
use std::{
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
};

#[path = "permission_request_tests/fixture.rs"]
mod fixture;

use fixture::*;
#[test]
fn request_challenge_cancel_result_round_trip_uses_real_daemon_channel_and_store() {
    assert!(
        permission_wire_inner_frame(&[0, 0, 0, 3, b'a', b'b', b'c'])
            .unwrap()
            .is_none()
    );
    let fixture = fixture();
    let (client_socket, server_socket) = UnixStream::pair().unwrap();
    let mut client = ProtectedActivationChannel::new(client_socket).unwrap();
    let mut daemon = ProtectedActivationChannel::new(server_socket).unwrap();
    let context = fixture.pending.context.control_context().unwrap();
    let auth =
        Authenticator::from_protected_activation(&fixture.channel_keys, Purpose::ModeControl);
    let request = auth
        .issue_frame(
            context.clone(),
            1,
            Direction::DesktopToDaemon,
            Payload::ModeRequest(PermissionControlModeRequestV1),
        )
        .unwrap();
    client
        .write_control_frame(&permission_wire_outer_frame(&request).unwrap())
        .unwrap();
    let wire_request = daemon.read_control_frame().unwrap();
    assert_eq!(
        permission_wire_inner_frame(&wire_request).unwrap(),
        Some(&request[..])
    );
    let mut active = None;
    assert_eq!(
        dispatch_permission_mode_request(
            &mut daemon,
            &wire_request,
            &fixture.channel_keys,
            &fixture.owned,
            0,
            &mut active,
            Some(&fixture.root),
        )
        .unwrap(),
        Some(1)
    );
    let wire_challenge = client.read_control_frame().unwrap();
    let challenge_frame = permission_wire_inner_frame(&wire_challenge)
        .unwrap()
        .unwrap();
    assert_eq!(
        &permission_wire_outer_frame(challenge_frame).unwrap()[..],
        &wire_challenge[..]
    );
    let mut challenge_context = context.clone();
    challenge_context.predecessor_transcript_digest = sha2::Sha256::digest(&request).into();
    let authenticated = auth
        .authenticate_frame(
            challenge_frame,
            &challenge_context,
            Purpose::ModeControl,
            Phase::Challenge,
            Direction::DaemonToDesktop,
            0,
            runtime::unix_now_millis().unwrap(),
        )
        .unwrap();
    assert!(matches!(authenticated.payload(), Payload::ModeChallenge(_)));
    let mut cancel_context = context.clone();
    cancel_context.predecessor_transcript_digest = sha2::Sha256::digest(challenge_frame).into();
    let cancel = auth
        .issue_frame(
            cancel_context.clone(),
            2,
            Direction::DesktopToDaemon,
            Payload::Cancel,
        )
        .unwrap();
    client
        .write_control_frame(&permission_wire_outer_frame(&cancel).unwrap())
        .unwrap();
    let wire_cancel = daemon.read_control_frame().unwrap();
    assert_eq!(
        permission_wire_inner_frame(&wire_cancel).unwrap(),
        Some(&cancel[..])
    );
    assert_eq!(
        dispatch_permission_mode_request(
            &mut daemon,
            &wire_cancel,
            &fixture.channel_keys,
            &fixture.owned,
            1,
            &mut active,
            Some(&fixture.root),
        )
        .unwrap(),
        Some(2)
    );
    let wire_result = client.read_control_frame().unwrap();
    let result_frame = permission_wire_inner_frame(&wire_result).unwrap().unwrap();
    cancel_context.predecessor_transcript_digest = sha2::Sha256::digest(&cancel).into();
    let result = auth
        .authenticate_frame(
            result_frame,
            &cancel_context,
            Purpose::ModeControl,
            Phase::Result,
            Direction::DaemonToDesktop,
            1,
            runtime::unix_now_millis().unwrap(),
        )
        .unwrap();
    assert!(
        matches!(result.payload(), Payload::Result(value) if value.code == runne_api::PermissionControlResultCodeV1::Cancelled)
    );
    assert!(active.is_none());
    let legacy = [0, 0, 0, 3, b'a', b'b', b'c'];
    client.write_control_frame(&legacy).unwrap();
    let legacy_read = daemon.read_control_frame().unwrap();
    assert!(permission_wire_inner_frame(&legacy_read).unwrap().is_none());
    assert_eq!(&legacy_read[..], &legacy);
    assert!(
        dispatch_permission_mode_request(
            &mut daemon,
            &legacy_read,
            &fixture.channel_keys,
            &fixture.owned,
            2,
            &mut active,
            Some(&fixture.root),
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn v1_control_loop_registers_the_owner_before_dispatching_permission_frames() {
    let fixture = fixture_with_owner_observation(false);
    let (client_socket, server_socket) = UnixStream::pair().unwrap();
    let mut client = ProtectedActivationChannel::new(client_socket).unwrap();
    let server_channel = ProtectedActivationChannel::new(server_socket).unwrap();
    let server_keys = fixture.channel_keys.clone();
    let server_owned = fixture.owned.clone();
    let sessions = Arc::clone(&fixture.sessions);
    let root = Arc::clone(&fixture.root);
    let server = std::thread::spawn(move || {
        crate::protected_activation::control::run_control_loop(
            server_channel,
            server_keys,
            server_owned,
            sessions,
            Arc::new(|| std::time::Duration::from_secs(1)),
            Some(root),
        )
    });

    let context = fixture.pending.context.control_context().unwrap();
    let auth =
        Authenticator::from_protected_activation(&fixture.channel_keys, Purpose::ModeControl);
    let request = auth
        .issue_frame(
            context.clone(),
            1,
            Direction::DesktopToDaemon,
            Payload::ModeRequest(PermissionControlModeRequestV1),
        )
        .unwrap();
    client
        .write_control_frame(&permission_wire_outer_frame(&request).unwrap())
        .unwrap();
    let wire_challenge = client.read_control_frame().unwrap();
    let challenge = permission_wire_inner_frame(&wire_challenge)
        .unwrap()
        .unwrap();
    let mut challenge_context = context.clone();
    challenge_context.predecessor_transcript_digest = sha2::Sha256::digest(&request).into();
    let authenticated = auth
        .authenticate_frame(
            challenge,
            &challenge_context,
            Purpose::ModeControl,
            Phase::Challenge,
            Direction::DaemonToDesktop,
            0,
            runtime::unix_now_millis().unwrap(),
        )
        .unwrap();
    assert!(matches!(authenticated.payload(), Payload::ModeChallenge(_)));

    let mut cancel_context = context.clone();
    cancel_context.predecessor_transcript_digest = sha2::Sha256::digest(challenge).into();
    let cancel = auth
        .issue_frame(
            cancel_context.clone(),
            2,
            Direction::DesktopToDaemon,
            Payload::Cancel,
        )
        .unwrap();
    client
        .write_control_frame(&permission_wire_outer_frame(&cancel).unwrap())
        .unwrap();
    let wire_result = client.read_control_frame().unwrap();
    let result_frame = permission_wire_inner_frame(&wire_result).unwrap().unwrap();
    cancel_context.predecessor_transcript_digest = sha2::Sha256::digest(&cancel).into();
    let result = auth
        .authenticate_frame(
            result_frame,
            &cancel_context,
            Purpose::ModeControl,
            Phase::Result,
            Direction::DaemonToDesktop,
            1,
            runtime::unix_now_millis().unwrap(),
        )
        .unwrap();
    assert!(matches!(
        result.payload(),
        Payload::Result(value) if value.code == runne_api::PermissionControlResultCodeV1::Cancelled
    ));

    let mut shutdown = runne_api::ProtectedShutdownV1::new(fixture.owned.clone());
    shutdown.sign(&fixture.channel_keys);
    client
        .write_control_frame(&shutdown.encode_frame().unwrap())
        .unwrap();
    let acknowledgement =
        runne_api::ProtectedShutdownAckV1::decode_frame(&client.read_control_frame().unwrap())
            .unwrap();
    acknowledgement
        .verify_exact(&fixture.owned, &fixture.channel_keys)
        .unwrap();
    assert!(server.join().unwrap().is_ok());
}

fn initialize_identity(path: &std::path::Path, authority: &[u8; 16]) {
    let connection = schema::open_managed_connection(path, schema::ConnectionMode::Writer).unwrap();
    schema::apply_migrations(&connection).unwrap();
    schema::ensure_authority_id(&connection, authority).unwrap();
    schema::ensure_event_log_lineage_id(&connection).unwrap();
}
