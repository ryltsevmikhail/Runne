//! Sealed inherited-root integration fixture, compiled only for test support.

use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_api::{
    ApiPrincipalId, DaemonInstanceId, LaunchSecret, ProtectedActivationKeys,
    ProtectedOwnedLaunchV1, ProtectedReadyV1, ProtectedRuntimeProfileV1, RuntimeSessionBinding,
    StableRuntimeBinding, StableRuntimeBindingV1,
};
use runne_application::local_session::LocalSessionService;
use runne_application::ports::{ProjectWorkspaceRepository, RuntimeAuthorityId};
use runne_domain::{
    event::Sensitivity,
    id::{CommandId, EventLogLineageId, IdempotencyKey, ProjectId, WorkspaceId},
    project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace},
};
use runne_security::SecretBroker;
use runne_store::{ProjectWorkspaceStore, schema, store::StoreTransaction};

use crate::application::root_admission_test_support::RootAdmissionHarness;

use super::ProtectedActivationChannel;
use witness::{publish_exact, read_parent_admission_digest};

mod witness;

const AUTHORITY: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const LINEAGE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
const DAEMON: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 3];
const SESSION: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 4];
const PROJECT: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 5];
const WORKSPACE: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x71, 0, 0x80, 0, 0, 0, 0, 0, 0, 6];

pub fn run_inherited_root_admission_fixture(token_path: &OsStr) {
    let mut channel = ProtectedActivationChannel::from_inherited_stdin()
        .expect("open inherited channel")
        .expect("inherited channel");
    let (keys, owned) = fixture();
    let authority = child_authority(
        &keys,
        std::path::Path::new(token_path)
            .parent()
            .expect("fixture directory"),
    );
    let mut used = std::collections::VecDeque::new();
    let first = channel.read_control_frame().expect("read offer");
    let sequence = authority
        .dispatch(&mut channel, &first, &keys, &owned, &mut used, 0, now())
        .expect("dispatch offer")
        .expect("root frame");
    let parent_admission_digest = read_parent_admission_digest(
        &std::path::Path::new(token_path).with_extension("admission-digest"),
    );
    assert_ne!(parent_admission_digest, [0; 32]);
    publish_exact(
        &std::path::Path::new(token_path).with_extension("outcome"),
        b"durably_recorded_root_bound",
    );
    let second = channel.read_control_frame().expect("read shutdown");
    authority
        .dispatch(
            &mut channel,
            &second,
            &keys,
            &owned,
            &mut used,
            sequence,
            now(),
        )
        .expect("dispatch shutdown")
        .expect("shutdown frame");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(authority.shutdown());
    authority
        .run_control(
            channel,
            keys,
            owned,
            Arc::new(Mutex::new(session_service())),
            Arc::new(|| Duration::from_secs(1)),
        )
        .expect("control loop");
}

fn child_authority(
    keys: &ProtectedActivationKeys,
    directory: &std::path::Path,
) -> RootAdmissionHarness {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .expect("runtime directory permissions");
    }
    let daemon_directory = directory.join("daemon");
    std::fs::create_dir(&daemon_directory).expect("daemon directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&daemon_directory, std::fs::Permissions::from_mode(0o700))
            .expect("daemon directory permissions");
    }
    let path = daemon_directory.join("event-log.db");
    let writer =
        schema::open_managed_connection(&path, schema::ConnectionMode::Writer).expect("writer");
    schema::apply_migrations(&writer).expect("migrations");
    let reader =
        schema::open_managed_connection(&path, schema::ConnectionMode::Reader).expect("reader");
    let store = StoreTransaction::open_with_connections(
        path.to_str().expect("database path"),
        writer,
        reader,
        RuntimeAuthorityId("b1b-transport".into()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .expect("store");
    let repository = ProjectWorkspaceStore::from_store(store);
    repository
        .create_project(
            "local-owner",
            CommandId::from_bytes(PROJECT),
            &IdempotencyKey::new("project").expect("key"),
            Project::create(
                ProjectId::from_bytes(PROJECT),
                ProjectWorkspaceDisplayName::new("Project".into()).expect("name"),
            ),
        )
        .expect("project");
    repository
        .create_workspace(
            "local-owner",
            CommandId::from_bytes(WORKSPACE),
            &IdempotencyKey::new("workspace").expect("key"),
            Workspace::create(
                workspace(),
                ProjectId::from_bytes(PROJECT),
                ProjectWorkspaceDisplayName::new("Workspace".into()).expect("name"),
            ),
        )
        .expect("workspace");
    RootAdmissionHarness::new(
        keys,
        repository.clone(),
        "b1b-transport".into(),
        Arc::new(Mutex::new(session_service())),
    )
}

const fn workspace() -> WorkspaceId {
    WorkspaceId::from_bytes(WORKSPACE)
}

fn fixture() -> (ProtectedActivationKeys, ProtectedOwnedLaunchV1) {
    let keys = LaunchSecret::from_bytes([9; 32])
        .expect("secret")
        .derive_keys();
    let executable = runne_api::ExecutableIdentityV1::new([1; 32], [2; 32], 1).expect("exe");
    let profile =
        ProtectedRuntimeProfileV1::new("fixture", 1, "fixture", [3; 32], [4; 32]).expect("profile");
    let stable = StableRuntimeBindingV1::new(
        AUTHORITY,
        "local-owner",
        LINEAGE,
        "fixture",
        [3; 32],
        [4; 32],
    )
    .expect("stable");
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
    .expect("ready");
    (keys, ready.owned_launch())
}

fn session_service() -> LocalSessionService {
    let stable = StableRuntimeBinding::new(
        AUTHORITY,
        ApiPrincipalId::new("local-owner").expect("principal"),
        EventLogLineageId::from_bytes(LINEAGE),
        "fixture",
        [3; 32],
        [4; 32],
    )
    .expect("stable");
    let binding = RuntimeSessionBinding::new(
        stable,
        DaemonInstanceId::from_bytes(DAEMON),
        1,
        SESSION,
        0,
        Sensitivity::Public,
        [5; 32],
    )
    .expect("binding");
    LocalSessionService::new(binding, [7; 32])
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_millis()
        .try_into()
        .expect("millis")
}
