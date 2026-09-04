use std::sync::Arc;

use runne_api::{
    ApiActor, ApiPrincipalId, BeginProviderCredentialEnrollment, LaunchSecret,
    ProtectedCredentialEnrollmentAuthenticator, ProtectedCredentialEnrollmentControlFrame,
    ProtectedCredentialEnrollmentLifecycleCodec, ProtectedCredentialEnrollmentRequestBinding,
    ProviderCredentialBeginIntentBinding, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialEnrollmentHostError,
    ProviderCredentialOperationStateV2, ProviderCredentialProviderV2,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{CredentialAuthorityPair, CredentialEnrollmentAuthorityPair};
use runne_secure_store::{
    CredentialReadbackObservation, ExactAbsenceReadback, ExactVersionReadback,
    ProviderCredentialReadback, SecureStoreError,
};

use super::{DaemonProviderCredentialEnrollmentControl, ProtectedEnrollmentSessionFacts};

pub(super) struct NoReadback;

impl ProviderCredentialReadback for NoReadback {
    fn readback_exact_version(
        &self,
        _: ExactVersionReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    fn readback_exact_absence(
        &self,
        _: ExactAbsenceReadback,
    ) -> Result<CredentialReadbackObservation, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }
}

#[test]
fn protected_begin_without_verified_request_admission_is_rejected_before_store() {
    let directory = tempfile::tempdir().unwrap();
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (enrollment_store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &directory.path().join("protected-session.sqlite"),
            lifecycle,
            enrollment_store.clone(),
        )
        .unwrap();
    let control = Arc::new(
        DaemonProviderCredentialEnrollmentControl::new(
            Arc::new(store),
            Arc::new(NoReadback),
            measurements,
            enrollment_store,
            id(9),
            10,
            #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
            None,
        )
        .unwrap(),
    );
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let facts = ProtectedEnrollmentSessionFacts::for_test();
    let rendezvous =
        super::super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let mut session = control
        .start_test_protected_session(&keys, facts, rendezvous)
        .unwrap();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "protected-session",
        "protected-intent",
    )
    .unwrap();
    let frame = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys)
        .encode_desktop_begin(&command, 1)
        .unwrap();

    assert_eq!(
        session.begin(&frame, 110_000),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn protected_request_admission_begin_and_exact_replay_return_one_safe_projection() {
    let (control, keys) = control();
    let facts = ProtectedEnrollmentSessionFacts::for_test();
    let rendezvous =
        super::super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let broker = runne_api::protected_credential_broker_evidence_binding(
        [6; 32],
        rendezvous.channel_binding(),
        rendezvous.publication_public_key(),
    );
    let mut session = control
        .start_test_protected_session(&keys, facts, rendezvous)
        .unwrap();
    let command = command();
    let context = context(&command);
    let intent = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    let binding = ProtectedCredentialEnrollmentRequestBinding::new(
        id(1),
        id(2),
        id(3),
        4,
        8,
        id(4),
        [6; 32],
        [7; 32],
        [8; 32],
        broker,
        runne_api::protected_credential_native_intent_digest("protected-intent"),
        *intent.action_provider_revision_digest(),
        *intent.command_identity_digest(),
        now - 1_000,
        now + 20_000,
    )
    .unwrap();
    let authenticator =
        ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys);
    let request = ProtectedCredentialEnrollmentControlFrame::Request(
        authenticator.issue_request(binding, 1).unwrap(),
    )
    .encode_frame();
    let (kind, admission) = session.accept_initial_request(&request, now).unwrap();
    assert_eq!(kind, super::InitialCredentialExchange::Intent);
    assert!(!admission.is_empty());
    assert_eq!(
        session.accept_request(&request, now),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
    let lifecycle = ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
    let first_frame = session
        .begin(&lifecycle.encode_desktop_begin(&command, 1).unwrap(), now)
        .unwrap();
    let first = lifecycle.decode_daemon_snapshot(&first_frame, 0).unwrap();
    let replay_frame = session
        .begin(&lifecycle.encode_desktop_begin(&command, 2).unwrap(), now)
        .unwrap();
    let replay = lifecycle.decode_daemon_snapshot(&replay_frame, 1).unwrap();
    assert_eq!(first.state(), ProviderCredentialOperationStateV2::Prepared);
    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    {
        assert_eq!(
            session.encode_terminal_snapshot(first.clone()),
            Err(ProviderCredentialEnrollmentHostError::InvariantViolation)
        );
        let after_rejection = session
            .begin(&lifecycle.encode_desktop_begin(&command, 3).unwrap(), now)
            .unwrap();
        assert_eq!(
            lifecycle
                .decode_daemon_snapshot(&after_rejection, 2)
                .unwrap(),
            first
        );
    }
    assert_eq!(first.operation_handle(), replay.operation_handle());
    assert_eq!(first.broker_rendezvous_id(), replay.broker_rendezvous_id());
    let handoff = session.take_bound_broker_handoff().unwrap();
    assert!(handoff.matches_safe_operation_for_test(&first, &control.handles));
    assert!(session.take_bound_broker_handoff().is_err());
    assert!(session.require_durable_terminal().is_err());
    #[cfg(feature = "desktop-protected")]
    assert!(
        crate::protected_activation::require_shutdown_terminal(Some(&session), true).is_err(),
        "cached terminal marker must not authorize shutdown before durable terminal"
    );
    let operation = control.handles.resolve(first.operation_handle()).unwrap();
    runne_provider::ProviderCredentialEnrollmentStore::cancel_before_claim(
        control.store.as_ref(),
        runne_provider::ClosePreparedCredentialOperation::new(
            operation,
            runne_provider::CredentialOperationState::Cancelled,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(!session.begun_is_terminal());
    assert_eq!(session.require_durable_terminal(), Ok(()));
    #[cfg(feature = "desktop-protected")]
    assert!(crate::protected_activation::require_shutdown_terminal(Some(&session), false).is_err());
    #[cfg(feature = "desktop-protected")]
    assert!(crate::protected_activation::require_shutdown_terminal(Some(&session), true).is_ok());
}

fn control() -> (
    Arc<DaemonProviderCredentialEnrollmentControl>,
    runne_api::ProtectedActivationKeys,
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.keep().join("protected-happy.sqlite");
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (enrollment_store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &path,
            lifecycle,
            enrollment_store.clone(),
        )
        .unwrap();
    let control = Arc::new(
        DaemonProviderCredentialEnrollmentControl::new(
            Arc::new(store),
            Arc::new(NoReadback),
            measurements,
            enrollment_store,
            id(9),
            10,
            #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
            None,
        )
        .unwrap(),
    );
    (
        control,
        LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys(),
    )
}

fn command() -> BeginProviderCredentialEnrollment {
    BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "protected-session",
        "protected-intent",
    )
    .unwrap()
}

fn context(command: &BeginProviderCredentialEnrollment) -> ProviderCredentialCommandContext {
    ProviderCredentialCommandContext {
        command_id: CommandId::parse(command.command_identity()).unwrap(),
        idempotency_key: IdempotencyKey::new(command.idempotency_key()).unwrap(),
        principal: ApiPrincipalId::new("protected-desktop-owner").unwrap(),
        actor: ApiActor::new("runne-tauri-native-host").unwrap(),
    }
}

fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70;
    value[8] = 0x80;
    value
}
