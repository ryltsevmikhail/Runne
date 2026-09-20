//! Production reachability of the editor launch path on THIS macOS host,
//! measured through the REAL daemon admission gateway
//! (issue → bind → `open_editor` → `launch_system_default_editor`).
//!
//! Recorded outcome on macOS 27 (26A5388g): `launch_system_default_editor`
//! derives the opener target from `root_path`, which reads `/dev/fd/N` via
//! `readlink`; that syscall returns EINVAL for every process on macOS 27, so
//! the production editor launch fails closed with
//! `WorkspaceEditorHostError::Unavailable` BEFORE any opener spawn. This test
//! pins that fail-closed state as the current production behavior — the
//! validate-then-path TOCTOU (see
//! crates/runne-platform-desktop/tests/macos_editor_launch_race.rs) is
//! therefore NOT reachable through production on this OS until the fd→path
//! mechanism is replaced, and neither model counts as a demonstrated
//! production exploit.
//!
//! The benign read control proves the gateway itself is live (admission,
//! bind and file serving all work) so the Unavailable verdict is attributable
//! to the editor launch path alone.
#![cfg(all(
    target_os = "macos",
    unix,
    feature = "desktop-protected",
    feature = "test-support"
))]

// The shared admission fixture serves several admission test targets; unused
// fixture items here are expected.
#[path = "root_handle_admission_authority/fixture.rs"]
#[allow(dead_code)]
mod fixture;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use runne_api::{
    ApiActor, ApiPrincipalId, BindWorkspaceRootCommand, EditorLaunchTargetV1, LaunchSecret,
    OpenEditorRequest, ProjectCommandContext, ProtectedActivationKeys, RootAdmissionAuthenticator,
    RootAdmissionRequest, RootAdmissionVerificationContext, RootHandleAdmission,
    RootHandleTransferAuthenticator, RootHandleTransferContext, RootHandleTransferOffer,
    RuntimeSessionBinding, StableRuntimeBinding, WorkspaceFileReadRequest,
};
use runne_application::local_session::LocalSessionService;
use runne_daemon::application::root_admission_authority_fixture::RootAdmissionAuthorityFixture;
use runne_domain::id::{CommandId, IdempotencyKey};

fn real_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

fn offer(
    keys: &ProtectedActivationKeys,
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
        fixture::workspace(),
        expected_version,
        [4; 16],
        now,
        now + 30_000,
    )
    .expect("transfer context");
    let authenticator = RootHandleTransferAuthenticator::from_protected_activation(keys);
    RootHandleTransferOffer::new(context, 1, &authenticator).expect("offer")
}

async fn bind(authority: &RootAdmissionAuthorityFixture, admission: RootHandleAdmission) {
    authority
        .bind_workspace_root(
            ProjectCommandContext {
                command_id: CommandId::from_bytes([
                    0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                idempotency_key: IdempotencyKey::new("editor-reachability-bind").expect("key"),
                principal: ApiPrincipalId::new(fixture::PRINCIPAL).expect("principal"),
                actor: ApiActor::new("desktop").expect("actor"),
            },
            BindWorkspaceRootCommand {
                workspace_id: fixture::workspace(),
                expected_version: 1,
                root_admission: admission,
            },
        )
        .await
        .expect("bind accepted");
}

#[tokio::test]
async fn production_editor_launch_is_fail_closed_on_this_macos() {
    let (_directory, path, store) = fixture::store();
    let root_dir = tempfile::tempdir().expect("workspace root");
    std::fs::create_dir_all(root_dir.path().join("notes")).expect("notes directory");
    std::fs::write(root_dir.path().join("notes/plan.md"), b"CANARY-PLAN").expect("benign file");
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let (_trust_store, trust) = fixture::trust_composition(&path);
    fixture::grant_trusted(&_trust_store);
    let authority = fixture::fixture_with_trust(store, sessions, trust);
    let issued = authority
        .issue(
            &offer(&fixture::keys(), 1, real_now()),
            fixture::root_handle(&root_dir),
            real_now(),
        )
        .expect("admission issued");
    bind(&authority, issued.admission).await;

    // Control: the same bound root serves file reads — the gateway is live.
    let read =
        WorkspaceFileReadRequest::new(fixture::workspace(), "notes/plan.md").expect("read request");
    assert_eq!(
        authority
            .read_file(fixture::PRINCIPAL, &read)
            .expect("gateway read")
            .content(),
        "CANARY-PLAN"
    );

    // Production editor launch on this host: fail-closed Unavailable (the
    // /dev/fd readlink dependency dies on macOS 27 before any opener runs).
    // Recorded as the current production outcome; if the fd→path mechanism is
    // replaced, this assertion MUST be revisited together with the TOCTOU
    // model in crates/runne-platform-desktop/tests/macos_editor_launch_race.rs.
    let request = OpenEditorRequest::new(
        fixture::workspace(),
        "notes/plan.md",
        EditorLaunchTargetV1::SystemDefault,
    )
    .expect("editor request");
    let outcome = authority.open_editor(fixture::PRINCIPAL, &request);
    match outcome {
        Err(runne_api::WorkspaceEditorHostError::Unavailable) => {}
        other => panic!(
            "editor launch outcome changed on this host: {other:?} — revisit the \
             reachability model and the TOCTOU analysis before trusting either"
        ),
    }
}
