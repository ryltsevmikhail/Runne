use super::super::*;
use crate::protected_activation::control_v3::initial_exchange::session_test_support::{
    session, session_with_active,
};
use runne_api::{ProviderCredentialEnrollmentActionV2 as Action, ProviderCredentialProviderV2};

pub(super) fn request(
    session: &DaemonProtectedCredentialEnrollmentSession,
    keys: &ProtectedActivationKeys,
    command: &BeginProviderCredentialEnrollment,
) -> Vec<u8> {
    let context = runne_api::ProviderCredentialCommandContext {
        command_id: runne_domain::id::CommandId::parse(command.command_identity()).unwrap(),
        idempotency_key: runne_domain::id::IdempotencyKey::new(command.idempotency_key()).unwrap(),
        principal: runne_api::ApiPrincipalId::new("protected-desktop-owner").unwrap(),
        actor: runne_api::ApiActor::new("runne-tauri-native-host").unwrap(),
    };
    let intent = runne_api::ProviderCredentialBeginIntentBinding::new(command, &context);
    let facts = &session.facts;
    let binding = runne_api::ProtectedCredentialEnrollmentRequestBinding::new(
        facts.launch_authority,
        facts.session,
        facts.daemon,
        facts.launch_generation,
        facts.supervisor_generation,
        *uuid::Uuid::now_v7().as_bytes(),
        facts.release,
        facts.tauri_peer,
        [8; 32],
        session.broker_evidence,
        runne_api::protected_credential_native_intent_digest(command.native_intent_id()),
        *intent.action_provider_revision_digest(),
        *intent.command_identity_digest(),
        now() - 1_000,
        now() + 20_000,
    )
    .unwrap();
    ProtectedCredentialEnrollmentControlFrame::Request(
        ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(keys)
            .issue_request(binding, 1)
            .unwrap(),
    )
    .encode_frame()
}

pub(super) fn command(action: Action) -> BeginProviderCredentialEnrollment {
    command_at_revision(action, 1)
}

fn command_at_revision(action: Action, revision: u64) -> BeginProviderCredentialEnrollment {
    BeginProviderCredentialEnrollment::new(
        action,
        ProviderCredentialProviderV2::OpenAi,
        revision,
        "018f8d23-7f90-7c00-8000-000000000001",
        "qualified-session",
        "native-intent",
    )
    .unwrap()
}

pub(super) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

/// Fixture databases live at `<tempdir>/runne-daemon/broker.sqlite` (nested
/// for the identity guard); plain readers must open the same nested path.
pub(super) fn broker_db(database: &tempfile::TempDir) -> std::path::PathBuf {
    database.path().join("runne-daemon").join("broker.sqlite")
}

pub(super) fn rows(database: &tempfile::TempDir, table: &str) -> i64 {
    rusqlite::Connection::open(broker_db(database))
        .unwrap()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn head(database: &tempfile::TempDir) -> (i64, i64, Option<i64>, Option<Vec<u8>>) {
    rusqlite::Connection::open(broker_db(database)).unwrap().query_row(
        "SELECT lifecycle_revision, credential_fence, active_credential_version, active_ref_digest FROM provider_credential_authority_heads WHERE provider_id='openai'",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap()
}

#[test]
fn qualified_unsupported_authenticated_actions_never_reserve_or_mutate() {
    for action in [Action::Revoke, Action::MigrateLegacy] {
        let (mut session, keys, database) = session_with_active(true, true);
        let before = head(&database);
        let command = command_at_revision(action, 2);
        session
            .accept_initial_request(&request(&session, &keys, &command), now())
            .unwrap();
        let codec = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
        let mut tampered = codec.encode_desktop_begin(&command, 1).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(session.begin(&tampered, now()).is_err());
        assert_eq!(session.desktop_sequence, 0);
        for sequence in 1..=2 {
            assert_eq!(
                session.begin(
                    &codec.encode_desktop_begin(&command, sequence).unwrap(),
                    now()
                ),
                Err(ProviderCredentialEnrollmentHostError::AccessDenied)
            );
            assert!(session.rendezvous.is_some());
            assert!(session.handoff.is_none());
            assert!(session.begun.is_none());
            assert!(session.qualification.is_some());
            assert_eq!(rows(&database, "provider_credential_operations"), 1);
            assert_eq!(head(&database), before);
        }
    }
}

#[test]
fn ordinary_revoke_still_clears_active_reference_and_advances_fences() {
    let (mut session, keys, database) = session_with_active(false, true);
    let command = BeginProviderCredentialEnrollment::new(
        Action::Revoke,
        ProviderCredentialProviderV2::OpenAi,
        2,
        "018f8d23-7f90-7c00-8000-000000000001",
        "qualified-session",
        "native-intent",
    )
    .unwrap();
    session
        .accept_initial_request(&request(&session, &keys, &command), now())
        .unwrap();
    let codec = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
    session
        .begin(&codec.encode_desktop_begin(&command, 1).unwrap(), now())
        .unwrap();
    assert_eq!(head(&database), (3, 3, None, None));
    assert_eq!(rows(&database, "provider_credential_operations"), 2);
    assert!(session.take_ticket_authority().is_ok());
}

#[test]
fn qualified_pair_preserves_carrier_across_failed_begin_and_repeated_issuance_selection() {
    let (mut session, keys, database) = session(true);
    let command = command(Action::Pair);
    let codec = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
    assert!(session.begin(b"malformed", now()).is_err());
    session
        .accept_initial_request(&request(&session, &keys, &command), now())
        .unwrap();
    let initial = session
        .begin(&codec.encode_desktop_begin(&command, 1).unwrap(), now())
        .unwrap();
    let first = codec.decode_daemon_snapshot(&initial, 0).unwrap();
    for sequence in 2..=3 {
        assert!(
            session.take_ticket_authority().is_err(),
            "qualified session selected ordinary authority"
        );
        let replay = session
            .begin(
                &codec.encode_desktop_begin(&command, sequence).unwrap(),
                now(),
            )
            .unwrap();
        assert_eq!(
            codec.decode_daemon_snapshot(&replay, sequence - 1).unwrap(),
            first
        );
        assert!(session.qualification.is_some());
    }
    assert_eq!(rows(&database, "provider_credential_operations"), 1);
    assert_eq!(rows(&database, "provider_credential_ticket_attempts"), 0);
    assert_eq!(
        rows(&database, "provider_qualification_admission_fences"),
        0
    );
}

#[test]
fn ordinary_pair_selects_authority_and_empty_profile_revoke_keeps_existing_denial() {
    for action in [Action::Pair, Action::Revoke] {
        let (mut session, keys, database) = session(false);
        let command = command(action);
        session
            .accept_initial_request(&request(&session, &keys, &command), now())
            .unwrap();
        let codec = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
        let result = session.begin(&codec.encode_desktop_begin(&command, 1).unwrap(), now());
        if action == Action::Pair {
            result.unwrap();
            assert!(session.take_ticket_authority().is_ok());
            assert_eq!(rows(&database, "provider_credential_operations"), 1);
        } else {
            assert_eq!(
                result,
                Err(ProviderCredentialEnrollmentHostError::AccessDenied)
            );
            assert!(
                session.rendezvous.is_none(),
                "ordinary Revoke must reach existing Begin validation"
            );
        }
    }
}

#[test]
fn qualified_recovery_rejects_before_start_and_never_falls_back_on_retry() {
    let (mut session, keys, database) = session(true);
    let facts = &session.facts;
    let bootstrap = runne_api::ProtectedCredentialRecoveryBootstrap::new(
        facts.installation,
        facts.release,
        session_binding(facts),
        facts.tauri_peer,
        session.broker_evidence,
        facts.supervisor_generation,
    )
    .unwrap();
    let mut desktop =
        runne_api::ProtectedCredentialRecoveryCodec::for_desktop(&keys, bootstrap).unwrap();
    let request = desktop
        .encode_desktop_request(*uuid::Uuid::now_v7().as_bytes())
        .unwrap();
    for _ in 0..2 {
        assert!(session.accept_initial_request(&request, now()).is_err());
        assert!(
            !session.recovery.started,
            "qualified Recovery entered the ordinary recovery path"
        );
        assert!(
            session
                .offer_cleanup_recovery(&request, now() / 1000)
                .is_err()
        );
        assert!(session.take_ticket_authority().is_err());
        assert!(session.pending.is_none());
        assert!(session.qualification.is_some());
    }
    assert_eq!(rows(&database, "provider_credential_operations"), 0);
}
