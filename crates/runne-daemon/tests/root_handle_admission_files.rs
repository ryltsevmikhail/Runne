#![cfg(all(unix, feature = "desktop-protected", feature = "test-support"))]

#[path = "root_handle_admission_authority/fixture.rs"]
mod fixture;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use runne_api::{
    ApiActor, ApiPrincipalId, BindWorkspaceRootCommand, LaunchSecret, ProjectCommandContext,
    ProtectedActivationKeys, RootAdmissionAuthenticator, RootAdmissionRequest,
    RootAdmissionVerificationContext, RootHandleAdmission, RootHandleTransferAuthenticator,
    RootHandleTransferContext, RootHandleTransferOffer, RuntimeSessionBinding,
    StableRuntimeBinding, WorkspaceFileListRequest,
};
use runne_application::local_session::LocalSessionService;
use runne_application::ports::RuntimeAuthorityId;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_domain::event::Sensitivity;
use runne_domain::id::{CommandId, DaemonInstanceId, EventLogLineageId, IdempotencyKey, ProjectId};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_security::SecretBroker;
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};
use rusqlite::Connection;
use std::path::PathBuf;

use runne_daemon::application::root_admission_authority_fixture::RootAdmissionAuthorityFixture;

fn real_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

fn store() -> (tempfile::TempDir, PathBuf, StoreTransaction) {
    let directory = tempfile::tempdir().expect("directory");
    let runtime = directory.path().join("runtime");
    let daemon = runtime.join("runne-daemon");
    std::fs::create_dir_all(&daemon).expect("database layout");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
            .expect("runtime permissions");
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))
            .expect("daemon permissions");
    }
    let path = daemon.join("admission-files.sqlite");
    let guard: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = StoreTransaction::open(
        path.to_str().expect("database path"),
        RuntimeAuthorityId(fixture::AUTHORITY_NAME.into()),
        guard,
    )
    .expect("store");
    (directory, path, store)
}

fn offer_at_version(
    keys: &ProtectedActivationKeys,
    workspace: runne_api::WorkspaceId,
    expected_version: u64,
    now: u64,
) -> RootHandleTransferOffer {
    let context = RootHandleTransferContext::new(
        fixture::AUTHORITY,
        fixture::SESSION,
        1,
        10,
        11,
        1_000,
        workspace,
        expected_version,
        [4; 16],
        now,
        now + 30_000,
    )
    .expect("transfer context");
    let authenticator = RootHandleTransferAuthenticator::from_protected_activation(keys);
    RootHandleTransferOffer::new(context, 1, &authenticator).expect("offer")
}

async fn bind_at(
    authority: &RootAdmissionAuthorityFixture,
    admission: RootHandleAdmission,
    expected_version: u64,
    label: u8,
) -> Result<runne_api::WorkspaceCommandAck, runne_api::ProjectWorkspaceHostError> {
    let mut command_id = [0u8; 16];
    command_id[0] = label;
    authority
        .bind_workspace_root(
            ProjectCommandContext {
                command_id: CommandId::from_bytes(command_id),
                idempotency_key: IdempotencyKey::new(&format!("bind-marker-{label}")).expect("key"),
                principal: ApiPrincipalId::new(fixture::PRINCIPAL).expect("principal"),
                actor: ApiActor::new("desktop").expect("actor"),
            },
            BindWorkspaceRootCommand {
                workspace_id: fixture::workspace(),
                expected_version,
                root_admission: admission,
            },
        )
        .await
}

fn list_paths(authority: &RootAdmissionAuthorityFixture) -> Vec<String> {
    let request =
        WorkspaceFileListRequest::new(fixture::workspace(), "", 50).expect("list request");
    let page = authority.list_files(&request).expect("bound root lists");
    page.items()
        .iter()
        .map(|entry| entry.relative_path().to_owned())
        .collect()
}

// Regression for the live attach finding: the bind an admission authorizes
// advances the workspace past its expected version, and the bound root must
// keep serving file reads (including the empty root listing path) there.
#[tokio::test]
async fn bound_root_lists_its_files_after_the_bind_advances_the_version() {
    let (_directory, _path, store) = fixture::store();
    let root_dir = tempfile::tempdir().expect("workspace root");
    std::fs::write(root_dir.path().join("pr24-open.txt"), b"marker").expect("marker file");
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = fixture::fixture(store, sessions);
    let issued = authority
        .issue(
            &offer_at_version(&fixture::keys(), fixture::workspace(), 1, real_now()),
            fixture::root_handle(&root_dir),
            real_now(),
        )
        .expect("current-session admission is issued");
    bind_at(&authority, issued.admission, 1, 0x0A)
        .await
        .expect("bind accepted");
    let request =
        WorkspaceFileListRequest::new(fixture::workspace(), "", 50).expect("list request");
    let page = authority.list_files(&request).expect("bound root lists");
    let paths: Vec<&str> = page
        .items()
        .iter()
        .map(|entry| entry.relative_path())
        .collect();
    assert_eq!(paths, vec!["pr24-open.txt"]);
}

// Negative regression: after the workspace is re-bound to a different folder,
// the previously admitted root must stop serving reads, and a replayed stale
// admission for the superseded binding must be rejected instead of quietly
// restoring it (the >= currency check assumes this invalidation exists).
#[tokio::test]
async fn rebinding_replaces_the_served_root_and_stale_admissions_cannot_restore_it() {
    let (_directory, _path, store) = fixture::store();
    let root_a = tempfile::tempdir().expect("root A");
    std::fs::write(root_a.path().join("a.txt"), b"a").expect("marker a");
    let root_b = tempfile::tempdir().expect("root B");
    std::fs::write(root_b.path().join("b.txt"), b"b").expect("marker b");
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = fixture::fixture(store, sessions);
    let now = real_now();

    // Three admissions for folder A at v1; only the first is ever bound.
    let issued_a1 = authority
        .issue(
            &offer_at_version(&fixture::keys(), fixture::workspace(), 1, now),
            fixture::root_handle(&root_a),
            now,
        )
        .expect("admission A1");
    let issued_a2 = authority
        .issue(
            &offer_at_version(&fixture::keys(), fixture::workspace(), 1, now),
            fixture::root_handle(&root_a),
            now,
        )
        .expect("admission A2");
    let issued_a3 = authority
        .issue(
            &offer_at_version(&fixture::keys(), fixture::workspace(), 1, now),
            fixture::root_handle(&root_a),
            now,
        )
        .expect("admission A3");
    bind_at(&authority, issued_a1.admission, 1, 0x0A)
        .await
        .expect("bind A");
    assert_eq!(list_paths(&authority), vec!["a.txt".to_owned()]);

    // Re-bind to folder B at the current version: it must fully replace the
    // served root.
    let later = real_now();
    let issued_b = authority
        .issue(
            &offer_at_version(&fixture::keys(), fixture::workspace(), 2, later),
            fixture::root_handle(&root_b),
            later,
        )
        .expect("admission B");
    bind_at(&authority, issued_b.admission, 2, 0x0B)
        .await
        .expect("bind B");
    assert_eq!(list_paths(&authority), vec!["b.txt".to_owned()]);

    // A replayed stale A admission (issued at v1, store now past it) may
    // verify its signature against the retained pending, but the bind it
    // authorizes is rejected by the version check and no promotion happens:
    // the superseded root can never come back into the serving state.
    let stale_bind = bind_at(&authority, issued_a2.admission, 1, 0x0C).await;
    assert!(stale_bind.is_err(), "stale bind must fail closed");
    assert_eq!(list_paths(&authority), vec!["b.txt".to_owned()]);
    let stale_claims = authority
        .verify(issued_a3.admission)
        .expect("in-TTL pending verifies");
    // Receipt-replay: confirm re-delivers the superseded admission's claims;
    // the monotonic guard skips the promotion, the newer root stays served.
    authority
        .confirm_root_admission(&stale_claims)
        .expect("replay acks without restoring the superseded root");
    assert_eq!(list_paths(&authority), vec!["b.txt".to_owned()]);
}
