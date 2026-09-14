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
    StableRuntimeBinding,
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

fn fail_closed<T>(
    result: Result<T, runne_application::ports::RootAdmissionVerifierError>,
) -> runne_application::ports::RootAdmissionVerifierError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("verdict must fail closed"),
    }
}

fn authority_with_seed(
    store: runne_store::store::StoreTransaction,
    sessions: Arc<Mutex<LocalSessionService>>,
) -> RootAdmissionAuthorityFixture {
    fixture::fixture(store, sessions)
}

#[test]
fn admitted_admission_verifies_once_for_the_current_session() {
    let (directory, path, store) = fixture::store();
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = authority_with_seed(store, sessions);
    let now = real_now();
    let issued = authority
        .issue(
            &fixture::offer(&fixture::keys(), fixture::workspace(), now),
            fixture::root_handle(&directory),
            now,
        )
        .expect("current-session admission is issued");
    let seeded = fixture::database_state(&path);
    let claims = authority.verify(issued.admission).expect("verdict accepts");
    assert_eq!(claims.workspace_id(), fixture::workspace());
    assert_eq!(claims.expected_version(), 1);
    assert_eq!(authority.retained_effect(), (1, 1));
    assert_eq!(
        fixture::database_state(&path),
        seeded,
        "verify alone must not bind durably"
    );
}

#[test]
fn expired_admission_is_rejected_without_durable_effect() {
    let (directory, path, store) = fixture::store();
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = authority_with_seed(store, sessions);
    let past = 1_000_000_000_000;
    let issued = authority
        .issue(
            &fixture::offer(&fixture::keys(), fixture::workspace(), past),
            fixture::root_handle(&directory),
            past,
        )
        .expect("admission issued against a past daemon clock");
    let before = fixture::database_state(&path);
    let error = fail_closed(authority.verify(issued.admission)); // expired admission must be rejected
    assert_eq!(format!("{error:?}"), "Rejected");
    assert_eq!(authority.retained_effect(), (0, 0));
    assert_eq!(fixture::database_state(&path), before);
}

#[test]
fn fenced_session_admission_replay_is_rejected_without_durable_effect() {
    let (directory, path, store) = fixture::store();
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = authority_with_seed(store, sessions);
    let now = real_now();
    let issued = authority
        .issue(
            &fixture::offer(&fixture::keys(), fixture::workspace(), now),
            fixture::root_handle(&directory),
            now,
        )
        .expect("admission issued");
    authority.fence().expect("fence revokes every admission");
    let before = fixture::database_state(&path);
    let error = fail_closed(authority.verify(issued.admission)); // fenced replay must be rejected
    assert_eq!(format!("{error:?}"), "Rejected");
    assert_eq!(authority.retained_effect(), (0, 0));
    assert_eq!(fixture::database_state(&path), before);
}

#[test]
fn foreign_session_admission_is_rejected_without_durable_effect() {
    let (directory, path, store) = fixture::store();
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = authority_with_seed(store, sessions);
    let now = real_now();
    let issued = authority
        .issue(
            &fixture::offer(&fixture::keys(), fixture::workspace(), now),
            fixture::root_handle(&directory),
            now,
        )
        .expect("admission issued");
    authority.replace_session(fixture::session_service(fixture::FOREIGN_SESSION));
    let before = fixture::database_state(&path);
    let error = fail_closed(authority.verify(issued.admission)); // foreign-session admission must be rejected
    assert_eq!(format!("{error:?}"), "Rejected");
    assert_eq!(authority.retained_effect(), (1, 0));
    assert_eq!(fixture::database_state(&path), before);
}

#[test]
fn policy_rotation_admission_is_rejected_without_durable_effect() {
    let (directory, path, store) = fixture::store();
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = authority_with_seed(store, sessions);
    let now = real_now();
    let issued = authority
        .issue(
            &fixture::offer(&fixture::keys(), fixture::workspace(), now),
            fixture::root_handle(&directory),
            now,
        )
        .expect("admission issued");
    let rotated = fixture::forge(
        &fixture::keys(),
        &fixture::claims_context(
            RootAdmissionAuthorityFixture::pinned_policy_version() + 1,
            now,
        ),
        fixture::workspace(),
        issued.filesystem_identity,
        issued.offer_digest,
        issued.nonce,
        issued.expires_at,
    );
    let before = fixture::database_state(&path);
    let error = fail_closed(authority.verify(rotated)); // rotated policy claims must be rejected
    assert_eq!(format!("{error:?}"), "Rejected");
    assert_eq!(authority.retained_effect(), (1, 0));
    assert_eq!(fixture::database_state(&path), before);
}

#[test]
fn offer_digest_mismatch_admission_is_rejected_without_durable_effect() {
    let (directory, path, store) = fixture::store();
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = authority_with_seed(store, sessions);
    let now = real_now();
    let issued = authority
        .issue(
            &fixture::offer(&fixture::keys(), fixture::workspace(), now),
            fixture::root_handle(&directory),
            now,
        )
        .expect("admission issued");
    let forged = fixture::forge(
        &fixture::keys(),
        &fixture::claims_context(RootAdmissionAuthorityFixture::pinned_policy_version(), now),
        fixture::workspace(),
        issued.filesystem_identity,
        [0x11; 32],
        issued.nonce,
        issued.expires_at,
    );
    let before = fixture::database_state(&path);
    let error = fail_closed(authority.verify(forged)); // mismatched retained offer must be rejected
    assert_eq!(format!("{error:?}"), "Rejected");
    assert_eq!(authority.retained_effect(), (1, 0));
    assert_eq!(fixture::database_state(&path), before);
}

#[test]
fn unavailable_authority_rejects_without_panic_or_durable_effect() {
    let (directory, path, store) = fixture::store();
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = authority_with_seed(store, sessions);
    let now = real_now();
    let issued = authority
        .issue(
            &fixture::offer(&fixture::keys(), fixture::workspace(), now),
            fixture::root_handle(&directory),
            now,
        )
        .expect("admission issued");
    let before = fixture::database_state(&path);
    let error = fail_closed(authority.verify_unavailable_authority(issued.admission)); // absent authority
    assert_eq!(format!("{error:?}"), "Unavailable");
    assert_eq!(authority.retained_effect(), (1, 0));
    assert_eq!(fixture::database_state(&path), before);
}

#[tokio::test]
async fn direct_bind_without_an_admission_verdict_is_rejected() {
    let (_directory, path, store) = fixture::store();
    fixture::seed_workspace(&store);
    let sessions = Arc::new(Mutex::new(fixture::session_service(fixture::SESSION)));
    let authority = authority_with_seed(store, sessions);
    let now = real_now();
    let direct = fixture::forge(
        &fixture::keys(),
        &fixture::claims_context(RootAdmissionAuthorityFixture::pinned_policy_version(), now),
        fixture::workspace(),
        [7; 32],
        [8; 32],
        [0x77; 16],
        now + 30_000,
    );
    let before = fixture::database_state(&path);
    let result = authority
        .bind_workspace_root(
            ProjectCommandContext {
                command_id: CommandId::from_bytes([3; 16]),
                idempotency_key: IdempotencyKey::new("direct-bind").expect("key"),
                principal: ApiPrincipalId::new(fixture::PRINCIPAL).expect("principal"),
                actor: ApiActor::new("desktop").expect("actor"),
            },
            BindWorkspaceRootCommand {
                workspace_id: fixture::workspace(),
                expected_version: 1,
                root_admission: direct,
            },
        )
        .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("direct bind without a verdict must be rejected"),
    };
    assert_eq!(format!("{error:?}"), "Forbidden");
    assert_eq!(fixture::database_state(&path), before);
}
