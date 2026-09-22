use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::ProtectedEnrollmentSessionFacts;
use super::protected_session_tests::{control, id};
use crate::application::provider_credential_enrollment::ProviderCredentialVerificationHost;
use runne_api::{
    ApiActor, ApiPrincipalId, ProtectedCredentialEnrollmentAuthenticator,
    ProtectedCredentialEnrollmentControlFrame, ProtectedCredentialEnrollmentRequestBinding,
    ProviderCredentialCommandContext, ProviderCredentialEnrollmentHostError,
    ProviderCredentialOperationHandleV2, ProviderCredentialOperationKindV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2, ProviderCredentialVerificationKindV2,
    ProviderCredentialVerifyIntentBinding, VerifyProviderCredential,
};
use runne_domain::id::{CommandId, IdempotencyKey};

struct RecordingVerifier(Arc<AtomicUsize>);

impl ProviderCredentialVerificationHost for RecordingVerifier {
    fn verify(
        &self,
        _: runne_api::ProviderCredentialBaseRequestAuthority,
        _: runne_api::ProviderCredentialIntentConsumptionProof,
        _: ProviderCredentialCommandContext,
        command: VerifyProviderCredential,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        ProviderCredentialOperationSnapshotV2::new(
            ProviderCredentialOperationHandleV2::from_bytes([11; 48]).unwrap(),
            None,
            command.provider(),
            ProviderCredentialOperationKindV2::VerifyRemote,
            ProviderCredentialOperationStateV2::Completed,
            1,
            1,
            false,
            Some(runne_api::ProviderCredentialLastDispositionV2::Completed),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}

#[test]
fn protected_verify_requires_native_request_admission_and_reaches_the_installed_host() {
    let (control, keys) = control();
    let calls = Arc::new(AtomicUsize::new(0));
    control
        .install_verification(Arc::new(RecordingVerifier(Arc::clone(&calls))))
        .unwrap();
    let facts = ProtectedEnrollmentSessionFacts::for_test();
    let rendezvous =
        super::super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let (session_id, _, release, _, supervisor, peer, _, _) = facts.http_authority_parts();
    let broker = runne_api::protected_credential_broker_evidence_binding(
        release,
        rendezvous.channel_binding(),
        rendezvous.publication_public_key(),
    );
    let mut session = control
        .start_test_protected_session(&keys, facts.clone(), rendezvous)
        .unwrap();
    #[cfg(target_os = "linux")]
    session.activate_linux_catalog_fixture();
    let command = command("00000000-0000-7000-8000-000000000011", "verify-intent");
    let context = context(&command);
    let intent = ProviderCredentialVerifyIntentBinding::new(&command, &context);
    let now = now_millis();
    let binding = ProtectedCredentialEnrollmentRequestBinding::new(
        id(1),
        session_id,
        id(3),
        4,
        supervisor,
        id(4),
        release,
        peer,
        [8; 32],
        broker,
        runne_api::protected_credential_native_intent_digest(command.native_intent_id()),
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
    session.accept_request(&request, now).unwrap();
    let lifecycle =
        runne_api::ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
    let snapshot = session
        .begin_or_verify(&lifecycle.encode_desktop_verify(&command, 1).unwrap(), now)
        .unwrap();
    let snapshot = lifecycle.decode_daemon_snapshot(&snapshot, 0).unwrap();
    assert_eq!(
        snapshot.operation_kind(),
        ProviderCredentialOperationKindV2::VerifyRemote
    );
    assert_eq!(
        snapshot.state(),
        ProviderCredentialOperationStateV2::Completed
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[test]
fn protected_verify_without_native_request_admission_is_rejected_before_host() {
    let (control, keys) = control();
    let calls = Arc::new(AtomicUsize::new(0));
    control
        .install_verification(Arc::new(RecordingVerifier(Arc::clone(&calls))))
        .unwrap();
    let facts = ProtectedEnrollmentSessionFacts::for_test();
    let rendezvous =
        super::super::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap();
    let mut session = control
        .start_test_protected_session(&keys, facts, rendezvous)
        .unwrap();
    let command = command("00000000-0000-7000-8000-000000000012", "missing-intent");
    let lifecycle =
        runne_api::ProtectedCredentialEnrollmentLifecycleCodec::from_protected_activation(&keys);
    assert_eq!(
        session.begin_or_verify(
            &lifecycle.encode_desktop_verify(&command, 1).unwrap(),
            now_millis()
        ),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

fn command(identity: &str, intent: &str) -> VerifyProviderCredential {
    VerifyProviderCredential::new(
        ProviderCredentialProviderV2::KimiCoding,
        1,
        ProviderCredentialVerificationKindV2::Remote,
        identity,
        intent,
    )
    .unwrap()
}

fn context(command: &VerifyProviderCredential) -> ProviderCredentialCommandContext {
    ProviderCredentialCommandContext {
        command_id: CommandId::parse(command.command_identity()).unwrap(),
        idempotency_key: IdempotencyKey::new(command.command_identity()).unwrap(),
        principal: ApiPrincipalId::new("protected-desktop-owner").unwrap(),
        actor: ApiActor::new("runne-tauri-native-host").unwrap(),
    }
}

fn now_millis() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}
