use runne_api::{
    ApiActor, ApiPrincipalId, LaunchSecret, ProtectedCredentialEnrollmentAdmissionBinding,
    ProtectedCredentialEnrollmentAuthenticator, ProtectedCredentialEnrollmentControlFrame,
    ProtectedCredentialEnrollmentRequestBinding, ProviderCredentialCommandContext,
    ProviderCredentialRequestAuthorityPair,
};
use runne_domain::id::{CommandId, IdempotencyKey};

use super::*;

#[test]
fn pending_admission_requires_the_exact_native_intent_session_and_claims_once() {
    let (registry, request, admission) = verified_admission();
    registry
        .register(request, admission, context(), 100_000)
        .unwrap();
    assert!(
        registry
            .take("intent-b", uuid(2), [8; 32], [9; 32], 110_000)
            .is_err()
    );
    assert!(
        registry
            .take("intent-a", uuid(2), [8; 32], [9; 32], 110_000)
            .is_ok()
    );
    assert!(
        registry
            .take("intent-a", uuid(2), [8; 32], [9; 32], 110_000)
            .is_err()
    );
    let (request, admission) = verified_frames();
    assert!(
        registry
            .register(request, admission, context(), 110_000)
            .is_err()
    );
}

#[test]
fn matching_intent_with_substituted_claim_consumes_the_admission() {
    let (registry, request, admission) = verified_admission();
    registry
        .register(request, admission, context(), 100_000)
        .unwrap();
    assert!(
        registry
            .take("intent-a", uuid(2), [8; 32], [10; 32], 110_000)
            .is_err()
    );
    assert!(
        registry
            .take("intent-a", uuid(2), [8; 32], [9; 32], 110_000)
            .is_err()
    );
    let (request, admission) = verified_frames();
    assert!(
        registry
            .register(request, admission, context(), 110_000)
            .is_err()
    );
}

#[test]
fn concurrent_duplicate_registration_issues_only_one_pending_authority() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let registry = std::sync::Arc::new(PendingCredentialHttpAdmissions::new(issuer));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let registry = std::sync::Arc::clone(&registry);
        let barrier = std::sync::Arc::clone(&barrier);
        let (request, admission) = verified_frames();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            registry.register(request, admission, context(), 100_000)
        }));
    }
    barrier.wait();
    let accepted = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .filter(Result::is_ok)
        .count();
    assert_eq!(accepted, 1);
    assert!(
        registry
            .take("intent-a", uuid(2), [8; 32], [9; 32], 110_000)
            .is_ok()
    );
}

fn verified_admission() -> (
    PendingCredentialHttpAdmissions,
    VerifiedProtectedCredentialEnrollmentRequest,
    VerifiedProtectedCredentialEnrollmentAdmission,
) {
    let (request, admission) = verified_frames();
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    (
        PendingCredentialHttpAdmissions::new(issuer),
        request,
        admission,
    )
}

fn verified_frames() -> (
    VerifiedProtectedCredentialEnrollmentRequest,
    VerifiedProtectedCredentialEnrollmentAdmission,
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
        [5; 32],
        [6; 32],
        [7; 32],
        protected_credential_native_intent_digest("intent-a"),
        [8; 32],
        [9; 32],
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
        [5; 32],
        [6; 32],
        [7; 32],
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
    (request, admission)
}

fn context() -> ProviderCredentialCommandContext {
    ProviderCredentialCommandContext {
        command_id: CommandId::from_bytes([1; 16]),
        idempotency_key: IdempotencyKey::new("credential-admission").unwrap(),
        principal: ApiPrincipalId::new("credential-principal").unwrap(),
        actor: ApiActor::new("credential-host").unwrap(),
    }
}

fn uuid(value: u8) -> [u8; 16] {
    [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, value]
}
