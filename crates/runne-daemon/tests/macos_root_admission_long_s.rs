//! macOS regression: the REAL daemon admission gateway (issue → bind →
//! read through `RootAdmissionGateway`) must deny a long-s variant of a
//! denied path without delivering the denied file's canary. On policy
//! revision 1 the variant is admitted and the canary is delivered — that is
//! the documented macOS bypass, so this test is red on revision 1 by design
//! and green once the policy revision covers the fold. A benign file read
//! stays the positive control.
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
    ApiActor, ApiPrincipalId, BindWorkspaceRootCommand, LaunchSecret, ProjectCommandContext,
    ProtectedActivationKeys, RootAdmissionAuthenticator, RootAdmissionRequest,
    RootAdmissionVerificationContext, RootHandleAdmission, RootHandleTransferAuthenticator,
    RootHandleTransferContext, RootHandleTransferOffer, RuntimeSessionBinding,
    StableRuntimeBinding, WorkspaceFileReadRequest,
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

async fn bind(
    authority: &RootAdmissionAuthorityFixture,
    admission: RootHandleAdmission,
    expected_version: u64,
    label: u8,
) {
    let mut command_id = [0u8; 16];
    command_id[0] = label;
    authority
        .bind_workspace_root(
            ProjectCommandContext {
                command_id: CommandId::from_bytes(command_id),
                idempotency_key: IdempotencyKey::new(format!("long-s-bind-{label}")).expect("key"),
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
        .expect("bind accepted");
}

fn read(authority: &RootAdmissionAuthorityFixture, path: &str) -> Result<String, String> {
    let request = WorkspaceFileReadRequest::new(fixture::workspace(), path).expect("read request");
    authority
        .read_file(fixture::PRINCIPAL, &request)
        .map(|content| content.content().to_owned())
        .map_err(|error| format!("{error:?}"))
}

#[tokio::test]
async fn long_s_variant_of_denied_path_is_denied_without_delivery() {
    let (_directory, path, store) = fixture::store();
    let root_dir = tempfile::tempdir().expect("workspace root");
    std::fs::write(root_dir.path().join("id_rsa"), b"CANARY-IDRSA").expect("denied canary");
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
    bind(&authority, issued.admission, 1, 0x0A).await;

    // Positive control: the benign file reads through the real gateway.
    assert_eq!(
        read(&authority, "notes/plan.md").expect("benign read"),
        "CANARY-PLAN"
    );

    // The long-s variant of the denied name must be refused as a policy
    // denial; either way the id_rsa canary must never be delivered.
    let long_s = read(&authority, "id_r\u{017F}a");
    match long_s {
        Err(_) => {} // denied by admission — the invariant holds end-to-end
        Ok(content) => panic!(
            "long-s variant of a denied path was served through the real daemon \
             admission and delivered denied canary content: {content:?}"
        ),
    }
}
