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
struct Fixture {
    _directory: tempfile::TempDir,
    root: Arc<ProtectedRootControl>,
    channel_keys: ProtectedActivationKeys,
    sessions: Arc<Mutex<LocalSessionService>>,
    owned: runne_api::ProtectedOwnedLaunchV1,
    pending: runne_api::PermissionModeNativePendingV2,
}
fn fixture() -> Fixture {
    fixture_with_owner_observation(true)
}
fn fixture_with_owner_observation(observe: bool) -> Fixture {
    let (owned, keys, sessions) = crate::protected_activation::test_enrollment_owned_and_sessions();
    let principal = ApiPrincipalId::new(owned.stable().principal_id().to_owned()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    let db = daemon.join("control.sqlite");
    let authority = uuid::Uuid::now_v7();
    let authority_id = RuntimeAuthorityId(authority.simple().to_string());
    initialize_identity(&db, authority.as_bytes());
    let store = StoreTransaction::open(
        db.to_str().unwrap(),
        authority_id.clone(),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let project_id = ProjectId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let workspace_id = WorkspaceId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    repository
        .create_project(
            principal.as_str(),
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("wire-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            principal.as_str(),
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("wire-workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .open_workspace(
            principal.as_str(),
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("wire-open").unwrap(),
            workspace_id,
            1,
        )
        .unwrap();
    let trust_path = daemon.join("trust-anchor.sqlite");
    let trust = ProjectTrustStore::open(&trust_path, *authority.as_bytes()).unwrap();
    let trust_project = ProjectTrustProjectId::from_bytes(project_id.into_bytes());
    let initial = trust.load(trust_project).unwrap();
    trust
        .commit(
            trust_project,
            ProjectTrustStatus::Trusted,
            0,
            initial.token(),
        )
        .unwrap();
    let lease = trust.acquire_effect_lease(trust_project).unwrap();
    let epoch = keys
        .permission_control_native_authenticator()
        .native_key_epoch();
    let launch = ProtectedNativeLaunchContext::new(
        *owned.launch_authority_id(),
        *owned.desktop_host_instance_id(),
        *owned.daemon_instance_id(),
        owned.launch_generation(),
        epoch,
    )
    .unwrap()
    .with_protected_session_id(*owned.session_id())
    .unwrap();
    let scope = PermissionScope {
        runtime_authority_id: authority_id,
        principal_id: principal.clone(),
        workspace_id,
    };
    let command_id = CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let request = NativeModeConfirmationRequestV2 {
        command_id,
        idempotency_key: IdempotencyKey::new("wire-mode").unwrap(),
        scope: scope.clone(),
        expected_authorization_revision: 0,
        requested_mode: PermissionMode::RiskBased,
        preset_version: PresetVersion::V1,
        expires_at_unix_ms: None,
    };
    let authority = PermissionModeAuthorityContext::new(
        &principal,
        trust_project,
        lease.as_ref(),
        Some(&launch),
    );
    store
        .begin_permission_mode_confirmation_v2(request, &authority)
        .unwrap();
    let host = PermissionControlHost::new(
        store.clone(),
        repository.clone(),
        Arc::clone(&sessions),
        None,
    );
    let compatible =
        ProtectedOwnedLaunchV1::compatibility_view_of_enrollment_launch_v3(&owned).unwrap();
    if observe {
        host.observe_launch(&compatible, &keys).unwrap();
    }
    let admission = crate::application::root_handle_admission::RootHandleAdmissionAuthority::new(
        &keys,
        repository,
        store.runtime_authority_id().0.clone(),
        Arc::clone(&sessions),
        crate::application::root_handle_admission::TrustGate::closed(),
    );
    let root = ProtectedRootControl::new_with_permission_control(admission, host);
    let pending = store
        .discover_permission_mode_native_pending_command_v2(&principal, &launch, command_id)
        .unwrap()
        .unwrap();
    Fixture {
        _directory: directory,
        root,
        channel_keys: keys,
        sessions,
        owned: compatible,
        pending,
    }
}
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
