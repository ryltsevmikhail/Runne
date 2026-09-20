//! macOS regression: the REAL daemon admission gateway (issue → bind →
//! read through `RootAdmissionGateway`) must deny a long-s variant of a
//! denied path with the typed policy-denial error — exactly
//! `WorkspaceFileHostError::Forbidden` per the host contract
//! (`TrustSourceError::into_files`); `Unavailable`/`NotFound` do not count
//! as a correct policy refusal — and the denied file's canary must not be
//! delivered. Before the gateway request the test proves, on the same
//! fixture root, that native resolution actually reaches `id_rsa` through
//! the long-s spelling (on a case-sensitive volume that equivalence is
//! absent, which is asserted explicitly instead). On policy revision 1 the
//! variant is admitted and the canary is delivered — that is the documented
//! macOS bypass, so this test is red on revision 1 by design and green once
//! the policy revision covers the fold. A benign file read stays the
//! positive gateway control.
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
    StableRuntimeBinding, WorkspaceFileHostError, WorkspaceFileReadRequest,
};
use runne_application::local_session::LocalSessionService;
use runne_daemon::application::root_admission_authority_fixture::RootAdmissionAuthorityFixture;
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_platform_desktop::VerifiedRootHandle;

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

fn read(
    authority: &RootAdmissionAuthorityFixture,
    path: &str,
) -> Result<String, WorkspaceFileHostError> {
    let request = WorkspaceFileReadRequest::new(fixture::workspace(), path).expect("read request");
    authority
        .read_file(fixture::PRINCIPAL, &request)
        .map(|content| content.content().to_owned())
}

#[tokio::test]
async fn long_s_variant_of_denied_path_is_policy_denied_without_delivery() {
    let (_directory, path, store) = fixture::store();
    let root_dir = tempfile::tempdir().expect("workspace root");
    std::fs::write(root_dir.path().join("id_rsa"), b"CANARY-IDRSA").expect("denied canary");
    std::fs::write(root_dir.path().join("mode_probe.txt"), b"mode").expect("mode probe");
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

    // Filesystem precondition, same fixture root: on the default
    // case-insensitive APFS the long-s spelling natively reaches id_rsa, so
    // the gateway denial below is the load-bearing defense. On a
    // case-sensitive volume that equivalence is absent — asserted here
    // explicitly — and the gateway denial is still required at the policy
    // level.
    let native =
        VerifiedRootHandle::open(&std::fs::canonicalize(root_dir.path()).expect("canonical root"))
            .expect("native root");
    if native
        .read_text_relative("MODE_PROBE.txt", 16)
        .is_ok_and(|content| content == "mode")
    {
        assert_eq!(
            native
                .read_text_relative("id_r\u{017F}a", 64)
                .expect("native long-s read"),
            "CANARY-IDRSA",
            "precondition: the long-s spelling must natively reach id_rsa on this volume"
        );
    } else {
        assert!(
            native.read_text_relative("id_r\u{017F}a", 64).is_err(),
            "case-sensitive volume must not resolve the long-s spelling onto id_rsa"
        );
        eprintln!("volume mode: case-sensitive — native long-s equivalence absent by design");
    }

    // Positive gateway control: the benign file reads through the gateway.
    assert_eq!(
        read(&authority, "notes/plan.md").expect("benign read"),
        "CANARY-PLAN"
    );

    // The long-s variant of the denied name must be refused with the typed
    // policy denial exactly: `Forbidden` per `TrustSourceError::into_files`.
    // `Unavailable`/`NotFound` do not count; nor may the canary be delivered.
    assert_eq!(
        read(&authority, "id_r\u{017F}a"),
        Err(WorkspaceFileHostError::Forbidden),
        "long-s variant of a denied path must be typed policy-denied, not served"
    );
}
