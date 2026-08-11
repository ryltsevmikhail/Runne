#![cfg(all(unix, feature = "desktop-protected", feature = "test-support"))]

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gocode_api::{
    ApiActor, ApiPrincipalId, BindWorkspaceRootCommand, ExecutableIdentityV1, LaunchSecret,
    ProjectCommandContext, ProjectWorkspaceCommandHostPort, ProtectedActivationKeys,
    ProtectedOwnedLaunchV1, ProtectedReadyV1, ProtectedRuntimeProfileV1, RuntimeSessionBinding,
    StableRuntimeBinding, StableRuntimeBindingV1,
};
use gocode_application::local_session::LocalSessionService;
use gocode_application::ports::{ProjectWorkspaceRepository, RuntimeAuthorityId};
use gocode_daemon::application::root_handle_admission::{
    RootAdmissionGateway, RootHandleAdmissionAuthority,
};
use gocode_daemon::protected_activation::{
    ProtectedActivationChannel, dispatch_root_handle_control_frame, run_control_loop,
};
use gocode_domain::{
    event::Sensitivity,
    id::{CommandId, DaemonInstanceId, EventLogLineageId, IdempotencyKey, ProjectId, WorkspaceId},
    project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace},
};
use gocode_platform_desktop::{
    BundledRuntimeProcessStatus, ProtectedBundledRuntimeError, ProtectedBundledRuntimeProcess,
    VerifiedRootHandle,
};
use gocode_runtime::RuntimeProjectWorkspaceHost;
use gocode_security::SecretBroker;
use gocode_store::{ProjectWorkspaceStore, schema, store::StoreTransaction};

const AUTHORITY: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const LINEAGE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
const DAEMON: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 3];
const SESSION: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 4];
const PROJECT: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 5];
const WORKSPACE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 6];

#[test]
fn inherited_child_binds_the_exact_admission_once() {
    if let Some(path) = std::env::var_os("GOCODE_B1B_TOKEN_PATH") {
        child(path.as_os_str());
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let token_path = directory.path().join("admission.token");
    let root = VerifiedRootHandle::open(directory.path()).unwrap();
    let (parent, child_channel) = UnixStream::pair().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "inherited_child_binds_the_exact_admission_once"])
        .env("GOCODE_B1B_TOKEN_PATH", &token_path)
        .stdin(Stdio::from(OwnedFd::from(child_channel)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (keys, owned) = fixture();
    let mut process =
        ProtectedBundledRuntimeProcess::test_root_transport_process(child, parent, keys, owned);
    let admission = process
        .prepare_root_admission(&root, workspace(), 1)
        .unwrap();
    assert_eq!(
        admission.encode_token().unwrap(),
        std::fs::read_to_string(&token_path).unwrap()
    );
    assert!(matches!(
        process.prepare_root_admission(&root, workspace(), 1),
        Err(ProtectedBundledRuntimeError::OwnershipMismatch)
    ));
    process.request_graceful_stop().unwrap();
    assert_eq!(
        process.wait_for_exit(Duration::from_secs(5)).unwrap(),
        BundledRuntimeProcessStatus::Exited
    );
}

fn child(token_path: &std::ffi::OsStr) {
    let mut channel = ProtectedActivationChannel::from_inherited_stdin()
        .unwrap()
        .unwrap();
    let (keys, owned) = fixture();
    let (_database, repository, authority) = child_authority(&keys);
    let gateway = RootAdmissionGateway::protected(Arc::clone(&authority));
    let mut used = std::collections::VecDeque::new();
    let first = channel.read_control_frame().unwrap();
    let sequence = dispatch_root_handle_control_frame(
        &mut channel,
        &first,
        &keys,
        &owned,
        &mut used,
        0,
        now(),
        Some(&authority),
    )
    .unwrap()
    .unwrap();
    let token = authority
        .take_test_admission()
        .unwrap()
        .encode_token()
        .unwrap();
    std::fs::write(token_path, &token).unwrap();
    let host = RuntimeProjectWorkspaceHost::new(repository, gateway.clone(), gateway.clone());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert_eq!(
        runtime
            .block_on(host.bind_workspace_root(command("bind-1"), bind(&token)))
            .unwrap()
            .new_version,
        2
    );
    assert!(
        runtime
            .block_on(host.bind_workspace_root(command("bind-2"), bind(&token)))
            .is_err()
    );
    authority.fence().unwrap();
    assert!(
        gocode_application::ports::RootAdmissionVerifier::verify_root_admission(
            &gateway,
            gocode_api::RootHandleAdmission::decode_token(&token).unwrap()
        )
        .is_err()
    );
    let second = channel.read_control_frame().unwrap();
    dispatch_root_handle_control_frame(
        &mut channel,
        &second,
        &keys,
        &owned,
        &mut used,
        sequence,
        now(),
        Some(&authority),
    )
    .unwrap()
    .unwrap();
    runtime.block_on(host.shutdown());
    run_control_loop(
        channel,
        keys,
        owned,
        Arc::new(Mutex::new(session_service())),
        Arc::new(|| Duration::from_secs(1)),
        Some(authority),
    )
    .unwrap();
}

fn child_authority(
    keys: &ProtectedActivationKeys,
) -> (
    tempfile::TempDir,
    ProjectWorkspaceStore,
    Arc<RootHandleAdmissionAuthority>,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("event-log.db");
    let writer = schema::open_with_pragmas(path.to_str().unwrap()).unwrap();
    schema::apply_migrations(&writer).unwrap();
    let reader = rusqlite::Connection::open(&path).unwrap();
    reader.execute_batch("PRAGMA query_only = ON;").unwrap();
    let store = StoreTransaction::open_with_connections(
        path.to_str().unwrap(),
        writer,
        reader,
        RuntimeAuthorityId("b1b-transport".into()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    let repository = ProjectWorkspaceStore::from_store(store);
    repository
        .create_project(
            "local-owner",
            CommandId::from_bytes(PROJECT),
            &IdempotencyKey::new("project").unwrap(),
            Project::create(
                ProjectId::from_bytes(PROJECT),
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            "local-owner",
            CommandId::from_bytes(WORKSPACE),
            &IdempotencyKey::new("workspace").unwrap(),
            Workspace::create(
                workspace(),
                ProjectId::from_bytes(PROJECT),
                ProjectWorkspaceDisplayName::new("Workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    let authority = RootHandleAdmissionAuthority::new(
        keys,
        repository.clone(),
        "b1b-transport".into(),
        Arc::new(Mutex::new(session_service())),
    );
    (directory, repository, authority)
}

fn bind(token: &str) -> BindWorkspaceRootCommand {
    BindWorkspaceRootCommand {
        workspace_id: workspace(),
        expected_version: 1,
        root_admission: gocode_api::RootHandleAdmission::decode_token(token).unwrap(),
    }
}
fn command(key: &str) -> ProjectCommandContext {
    ProjectCommandContext {
        command_id: CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("desktop").unwrap(),
    }
}
fn workspace() -> WorkspaceId {
    WorkspaceId::from_bytes(WORKSPACE)
}

fn fixture() -> (ProtectedActivationKeys, ProtectedOwnedLaunchV1) {
    let keys = LaunchSecret::from_bytes([9; 32]).unwrap().derive_keys();
    let executable = ExecutableIdentityV1::new([1; 32], [2; 32], 1).unwrap();
    let profile =
        ProtectedRuntimeProfileV1::new("fixture", 1, "fixture", [3; 32], [4; 32]).unwrap();
    let stable = StableRuntimeBindingV1::new(
        AUTHORITY,
        "local-owner",
        LINEAGE,
        "fixture",
        [3; 32],
        [4; 32],
    )
    .unwrap();
    let ready = ProtectedReadyV1::new(
        AUTHORITY,
        AUTHORITY,
        executable,
        profile,
        stable,
        DAEMON,
        1,
        SESSION,
        "https://127.0.0.1",
        [5; 32],
        vec![1],
        vec!["fixture".into()],
    )
    .unwrap();
    (keys, ready.owned_launch())
}
fn session_service() -> LocalSessionService {
    let stable = StableRuntimeBinding::new(
        AUTHORITY,
        ApiPrincipalId::new("local-owner").unwrap(),
        EventLogLineageId::from_bytes(LINEAGE),
        "fixture",
        [3; 32],
        [4; 32],
    )
    .unwrap();
    let binding = RuntimeSessionBinding::new(
        stable,
        DaemonInstanceId::from_bytes(DAEMON),
        1,
        SESSION,
        0,
        Sensitivity::Public,
        [5; 32],
    )
    .unwrap();
    LocalSessionService::new(binding, [7; 32])
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}
