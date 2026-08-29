use runne_api::{
    ApiActor, ApiPrincipalId, BeginProviderCredentialEnrollment, LaunchSecret,
    ProtectedCredentialEnrollmentAdmissionBinding, ProtectedCredentialEnrollmentAuthenticator,
    ProtectedCredentialEnrollmentControlFrame, ProtectedCredentialEnrollmentRequestBinding,
    ProviderCredentialBeginIntentBinding, ProviderCredentialCommandContext,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialProviderV2,
    ProviderCredentialRequestAuthorityPair, protected_credential_native_intent_digest,
};
use runne_domain::id::{CommandId, IdempotencyKey};

use super::admission_registry::PendingCredentialHttpAdmissions;
use super::control_exchange::{
    DaemonAuthenticatedCredentialHttpAdmissionExchange, DaemonCredentialHttpAdmissionExpectation,
    RegisteredCredentialHttpAdmissionExchange,
};

#[test]
fn registers_one_verified_exchange_and_consumes_it_once() {
    let (exchange, request, admission) = fixture(expectation());
    let exchange = exchange
        .register(request, admission, context(), 110_000)
        .unwrap();

    assert!(take_exact(&exchange).is_ok());
    assert!(take_exact(&exchange).is_err());
}

#[test]
fn rejects_substituted_action_provider_revision_native_intent_and_sequence_before_issue() {
    let bindings = begin_bindings();
    for expected in [
        expectation_with(
            [10; 32],
            native_intent("intent-a"),
            1,
            2,
            uuid(2),
            [11; 32],
            [7; 32],
        ),
        expectation_with(
            bindings.0,
            native_intent("intent-b"),
            1,
            2,
            uuid(2),
            [11; 32],
            [7; 32],
        ),
        expectation_with(
            bindings.0,
            native_intent("intent-a"),
            2,
            3,
            uuid(2),
            [11; 32],
            [7; 32],
        ),
    ] {
        let (exchange, request, admission) = fixture(expected);
        assert!(
            exchange
                .register(request, admission, context(), 110_000)
                .is_err()
        );
    }
}

#[test]
fn rejects_expired_wrong_or_missing_session_and_wrong_peer_before_issue() {
    let bindings = begin_bindings();
    for expected in [
        expectation_with(
            bindings.0,
            native_intent("intent-a"),
            1,
            2,
            uuid(9),
            [11; 32],
            [7; 32],
        ),
        expectation_with(
            bindings.0,
            native_intent("intent-a"),
            1,
            2,
            uuid(2),
            [13; 32],
            [7; 32],
        ),
        expectation_with(
            bindings.0,
            native_intent("intent-a"),
            1,
            2,
            uuid(2),
            [11; 32],
            [13; 32],
        ),
    ] {
        let (exchange, request, admission) = fixture(expected);
        assert!(
            exchange
                .register(request, admission, context(), 110_000)
                .is_err()
        );
    }

    let (exchange, request, admission) = fixture(expectation());
    assert!(
        exchange
            .register(request, admission, context(), 120_000)
            .is_err()
    );
    assert!(
        DaemonCredentialHttpAdmissionExpectation::new(
            [0; 16],
            [10; 32],
            [8; 32],
            [9; 32],
            native_intent("intent-a"),
            1,
            2,
            [7; 32],
            120_000,
        )
        .is_err()
    );
}

fn take_exact(
    exchange: &RegisteredCredentialHttpAdmissionExchange,
) -> Result<
    (
        runne_api::ProviderCredentialBaseRequestAuthority,
        runne_api::ProviderCredentialIntentConsumptionProof,
        ProviderCredentialCommandContext,
    ),
    runne_api::ProviderCredentialEnrollmentHostError,
> {
    exchange.resolve_begin(uuid(2), &begin_command(), 110_000)
}

fn fixture(
    expected: DaemonCredentialHttpAdmissionExpectation,
) -> (
    DaemonAuthenticatedCredentialHttpAdmissionExchange,
    runne_api::VerifiedProtectedCredentialEnrollmentRequest,
    runne_api::VerifiedProtectedCredentialEnrollmentAdmission,
) {
    fixture_with_bindings(expected, begin_bindings())
}

fn fixture_with_bindings(
    expected: DaemonCredentialHttpAdmissionExpectation,
    bindings: ([u8; 32], [u8; 32]),
) -> (
    DaemonAuthenticatedCredentialHttpAdmissionExchange,
    runne_api::VerifiedProtectedCredentialEnrollmentRequest,
    runne_api::VerifiedProtectedCredentialEnrollmentAdmission,
) {
    let keys = LaunchSecret::from_bytes([1; 32]).unwrap().derive_keys();
    let authenticator =
        ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys);
    let request_binding = ProtectedCredentialEnrollmentRequestBinding::new(
        uuid(1),
        uuid(2),
        uuid(3),
        3,
        2,
        uuid(4),
        [4; 32],
        [7; 32],
        [5; 32],
        [6; 32],
        native_intent("intent-a"),
        bindings.0,
        bindings.1,
        100_000,
        120_000,
    )
    .unwrap();
    let request_frame = ProtectedCredentialEnrollmentControlFrame::Request(
        authenticator
            .issue_request(request_binding.clone(), 1)
            .unwrap(),
    )
    .encode_frame();
    let request = authenticator
        .decode_request(&request_frame, &request_binding, 0, 110_000)
        .unwrap();
    let admission_binding = ProtectedCredentialEnrollmentAdmissionBinding::new(
        [10; 32],
        [4; 32],
        [11; 32],
        2,
        [12; 32],
        4,
        [7; 32],
        [5; 32],
        [6; 32],
        uuid(5),
        120_000,
    )
    .unwrap();
    let admission_frame = ProtectedCredentialEnrollmentControlFrame::Admission(
        authenticator
            .issue_admission(&request, admission_binding.clone(), 2)
            .unwrap(),
    )
    .encode_frame();
    let admission = authenticator
        .decode_admission(&admission_frame, &request, &admission_binding, 1, 110_000)
        .unwrap();
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    (
        DaemonAuthenticatedCredentialHttpAdmissionExchange::new(
            PendingCredentialHttpAdmissions::new(issuer),
            expected,
        ),
        request,
        admission,
    )
}

fn context() -> ProviderCredentialCommandContext {
    ProviderCredentialCommandContext {
        command_id: CommandId::from_bytes([1; 16]),
        idempotency_key: IdempotencyKey::new("credential-admission").unwrap(),
        principal: ApiPrincipalId::new("credential-principal").unwrap(),
        actor: ApiActor::new("credential-host").unwrap(),
    }
}

fn expectation() -> DaemonCredentialHttpAdmissionExpectation {
    let bindings = begin_bindings();
    expectation_with(
        bindings.0,
        native_intent("intent-a"),
        1,
        2,
        uuid(2),
        [11; 32],
        [7; 32],
    )
}

fn expectation_with(
    action_provider_revision: [u8; 32],
    native_intent_digest: [u8; 32],
    request_sequence: u64,
    admission_sequence: u64,
    protected_session_id: [u8; 16],
    protected_session_binding: [u8; 32],
    authenticated_tauri_peer: [u8; 32],
) -> DaemonCredentialHttpAdmissionExpectation {
    let bindings = begin_bindings();
    DaemonCredentialHttpAdmissionExpectation::new(
        protected_session_id,
        protected_session_binding,
        action_provider_revision,
        bindings.1,
        native_intent_digest,
        request_sequence,
        admission_sequence,
        authenticated_tauri_peer,
        120_000,
    )
    .unwrap()
}

fn begin_command() -> BeginProviderCredentialEnrollment {
    BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        7,
        "00000000-0000-7000-8000-000000000009",
        "credential-admission",
        "intent-a",
    )
    .unwrap()
}

fn begin_bindings() -> ([u8; 32], [u8; 32]) {
    let binding = ProviderCredentialBeginIntentBinding::new(&begin_command(), &context());
    (
        *binding.action_provider_revision_digest(),
        *binding.command_identity_digest(),
    )
}

fn native_intent(value: &str) -> [u8; 32] {
    protected_credential_native_intent_digest(value)
}
fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}

#[path = "control_exchange_tests/http_resolver.rs"]
mod http_resolver;
