//! Production reachability of the editor launch path on THIS macOS host,
//! measured through the REAL daemon admission gateway
//! (issue → bind → `open_editor` → `launch_system_default_editor`).
//!
//! The macOS native backend currently refuses the system-default editor
//! launch BY DECISION: `launch_system_default_editor` runs the shared
//! fd-relative validation and then returns
//! `RootHandleBrokerError::Unavailable` without deriving any opener target
//! and without spawning anything. This is a deliberate, temporary
//! macOS-backend limitation (the opener target would have to be re-resolved
//! from a path the validation cannot pin to the checked object), NOT a
//! claim that the feature never worked on any macOS version. The gateway
//! maps that verdict to `WorkspaceEditorHostError::Unavailable`, which is
//! the deterministic outcome the main test pins.
//!
//! Two early rejections through the same gateway prove the verdict is
//! specific to the launch stage: a foreign principal and a sensitive path
//! (`.env`) are both answered `Forbidden` before the editor host is ever
//! consulted.
//!
//! `runne_platform_desktop::launcher_spawn_attempt_count()` is incremented
//! only immediately before `Command::spawn`, so it reading 0 after every
//! `open_editor` call proves no opener process was ever attempted.
//!
//! The benign read control proves the gateway itself is live (admission,
//! bind and file serving all work) so the Unavailable verdict is attributable
//! to the editor launch path alone.
//!
//! If the macOS backend gains a pinned opener-target mechanism, the
//! `Unavailable` assertion MUST be revisited together with the TOCTOU model
//! in crates/runne-platform-desktop/tests/macos_editor_launch_race.rs.
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
    RuntimeSessionBinding, StableRuntimeBinding, WorkspaceEditorHostError,
    WorkspaceFileReadRequest,
};
use runne_application::local_session::LocalSessionService;
use runne_daemon::application::root_admission_authority_fixture::RootAdmissionAuthorityFixture;
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_platform_desktop::launcher_spawn_attempt_count;

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

    let plan_request = OpenEditorRequest::new(
        fixture::workspace(),
        "notes/plan.md",
        EditorLaunchTargetV1::SystemDefault,
    )
    .expect("editor request");
    let env_request = OpenEditorRequest::new(
        fixture::workspace(),
        ".env",
        EditorLaunchTargetV1::SystemDefault,
    )
    .expect("sensitive editor request");

    // Early rejection (a): a foreign principal never reaches the editor host.
    assert_eq!(
        authority.open_editor("other-principal", &plan_request),
        Err(WorkspaceEditorHostError::Forbidden),
        "open_editor must reject a foreign principal with Forbidden"
    );

    // Early rejection (b): sensitive workspace files never reach the editor host.
    assert_eq!(
        authority.open_editor(fixture::PRINCIPAL, &env_request),
        Err(WorkspaceEditorHostError::Forbidden),
        "open_editor must reject a sensitive path (.env) with Forbidden"
    );
    assert_eq!(
        launcher_spawn_attempt_count(),
        0,
        "the early rejections must not reach the launcher"
    );

    // Main: the macOS backend refuses the launch by decision after the shared
    // fd-relative validation — a deterministic Unavailable, no opener target
    // derivation, no spawn. If the backend gains a pinned opener-target
    // mechanism, this assertion MUST be revisited together with the TOCTOU
    // model in crates/runne-platform-desktop/tests/macos_editor_launch_race.rs.
    assert_eq!(
        authority.open_editor(fixture::PRINCIPAL, &plan_request),
        Err(WorkspaceEditorHostError::Unavailable),
        "the macOS backend must fail the editor launch closed by decision"
    );

    // The counter increments only immediately before Command::spawn, so 0
    // after the full open_editor sequence proves no opener was ever attempted.
    assert_eq!(
        launcher_spawn_attempt_count(),
        0,
        "open_editor must not attempt any opener spawn on this host"
    );
}
