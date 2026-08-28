use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialEnrollmentHostError,
    ProviderCredentialOperationKindV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2, ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialOperationSnapshot,
};

use super::super::{CredentialEnrollmentReadback, ProviderCredentialAdmission};
use super::begin_admission_support::context;

struct NoReadback;

impl CredentialEnrollmentReadback for NoReadback {
    fn observe(
        &self,
        _: &CredentialOperationSnapshot,
        _: &runne_provider::CredentialBrokerCommand,
    ) -> Result<runne_provider::BindCredentialReadback, ProviderCredentialEnrollmentHostError> {
        Err(ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}

#[test]
fn begin_recovers_then_returns_the_exact_idempotent_prepared_projection() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "begin-idempotency",
        "begin-intent",
    )
    .unwrap();
    let context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            4_000_000_000,
        )
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (lifecycle_authority, _) = CredentialAuthorityPair::new().split();
    let (enrollment_authority, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &directory.path().join("begin.sqlite"),
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();
    let reader = NoReadback;
    let begin = super::super::begin::ProviderCredentialEnrollmentBegin::new(
        ProviderCredentialAdmission::new(verifier, measurements),
        super::super::operation_handle::ProviderCredentialOperationHandleIssuer::new([9; 32]),
        &store,
        &reader,
    );

    let first = begin
        .admit(&authority, &proof, &context, &command, 100)
        .unwrap();
    let replay = begin
        .admit(&authority, &proof, &context, &command, 100)
        .unwrap();

    assert_eq!(first.operation_handle(), replay.operation_handle());
    assert_eq!(
        first.operation_kind(),
        ProviderCredentialOperationKindV2::Pair
    );
    assert_eq!(first.state(), ProviderCredentialOperationStateV2::Prepared);
    assert_eq!(first.lifecycle_revision(), 1);
    assert_eq!(first.readiness_revision(), 1);
    let operation_handle = hex::encode(first.operation_handle().as_bytes());
    assert_ne!(
        first.broker_rendezvous_id(),
        Some(operation_handle.as_str())
    );
}
