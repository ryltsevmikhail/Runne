use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialEnrollmentHostError,
    ProviderCredentialOperationKindV2, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2, ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialOperationSnapshot,
    ProviderCredentialEnrollmentStore,
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
fn resume_authenticates_the_handle_and_installation_before_recovery() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "resume-idempotency",
        "resume-intent",
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
            &directory.path().join("resume.sqlite"),
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();
    let lifecycle = store
        .begin_admission_snapshot(&runne_provider::ProviderId::new("openai").unwrap())
        .unwrap();
    let begin_admission = ProviderCredentialAdmission::new(verifier.clone(), measurements);
    let operation = match begin_admission
        .admit_begin(&authority, &proof, &command, &context, lifecycle, &store)
        .unwrap()
    {
        super::super::coordinator::ProviderCredentialBeginAdmission::FreshWinner(effect) => {
            effect.consume()
        }
        super::super::coordinator::ProviderCredentialBeginAdmission::ExactReplay(_) => {
            panic!("first begin must create an operation")
        }
    };
    let handles =
        super::super::operation_handle::ProviderCredentialOperationHandleIssuer::new([9; 32]);
    let handle = handles.issue(operation.operation_id());
    let (_, resume_measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let reader = NoReadback;
    let resume = super::super::resume::ProviderCredentialEnrollmentResume::new(
        ProviderCredentialAdmission::new(verifier, resume_measurements),
        handles.duplicate(),
        &store,
        &reader,
        super::super::broker::pending::PendingBrokerRendezvousRegistry::new(handles.duplicate()),
    );

    let projection = resume.load(&authority, handle, 100).unwrap();
    assert_eq!(projection.operation_handle(), handle);
    assert_eq!(
        projection.operation_kind(),
        ProviderCredentialOperationKindV2::Pair
    );
    assert_eq!(
        projection.state(),
        ProviderCredentialOperationStateV2::Prepared
    );
    assert_eq!(projection.broker_rendezvous_id(), None);
    let foreign_authority = issuer
        .issue_base([7; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    assert_eq!(
        resume.load(&foreign_authority, handle, 100),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}
