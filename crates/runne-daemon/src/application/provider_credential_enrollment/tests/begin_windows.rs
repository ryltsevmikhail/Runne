use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialEnrollmentHostError,
    ProviderCredentialProviderV2, ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{CredentialAuthorityPair, CredentialEnrollmentAuthorityPair};

use super::super::{CredentialEnrollmentReadback, ProviderCredentialAdmission};
use super::begin_admission_support::context;

struct NoReadback;

impl CredentialEnrollmentReadback for NoReadback {
    fn observe(
        &self,
        _: &runne_provider::CredentialOperationSnapshot,
        _: &runne_provider::CredentialBrokerCommand,
    ) -> Result<runne_provider::BindCredentialReadback, ProviderCredentialEnrollmentHostError> {
        Err(ProviderCredentialEnrollmentHostError::InvariantViolation)
    }
}

// Windows has no unix broker rendezvous transport: begin must refuse with the
// typed unsupported error, after the shared admission and durable recovery
// checks, never by simulating enrollment success.
#[cfg(windows)]
#[test]
fn begin_returns_the_typed_unsupported_refusal_on_windows() {
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
            &{
                let daemon = directory.path().join("runne-daemon");
                std::fs::create_dir_all(&daemon).unwrap();
                daemon.join("begin.sqlite")
            },
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();
    let handles =
        super::super::operation_handle::ProviderCredentialOperationHandleIssuer::new([9; 32]);
    let rendezvous =
        super::super::broker::pending::PendingBrokerRendezvousRegistry::new(handles.duplicate());
    let begin = super::super::begin::ProviderCredentialEnrollmentBegin::new(
        ProviderCredentialAdmission::new(verifier, measurements),
        handles.duplicate(),
        &store,
        &NoReadback,
        rendezvous,
    );

    assert!(matches!(
        begin.admit(&authority, &proof, &context, &command, 100),
        Err(ProviderCredentialEnrollmentHostError::Unsupported)
    ));
}
