use std::sync::Arc;

use runne_api::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialEnrollmentHostError,
    ProviderCredentialEnrollmentHostPort, ProviderCredentialOperationStateV2,
    ProviderCredentialProviderV2, ProviderCredentialRequestAuthorityPair,
};
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialOperationSnapshot,
};

use super::super::{CredentialEnrollmentReadback, host::ProviderCredentialVerificationHost};
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

struct RejectVerification;

impl ProviderCredentialVerificationHost for RejectVerification {
    fn verify(
        &self,
        _: runne_api::ProviderCredentialBaseRequestAuthority,
        _: runne_api::ProviderCredentialIntentConsumptionProof,
        _: runne_api::ProviderCredentialCommandContext,
        _: runne_api::VerifyProviderCredential,
    ) -> Result<
        runne_api::ProviderCredentialOperationSnapshotV2,
        ProviderCredentialEnrollmentHostError,
    > {
        Err(ProviderCredentialEnrollmentHostError::Unsupported)
    }
}

#[tokio::test]
async fn composed_host_begins_then_resumes_the_same_safe_operation() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = BeginProviderCredentialEnrollment::new(
        ProviderCredentialEnrollmentActionV2::Pair,
        ProviderCredentialProviderV2::OpenAi,
        1,
        "018f8d23-7f90-7c00-8000-000000000001",
        "host-idempotency",
        "host-intent",
    )
    .unwrap();
    let command_context = context();
    let binding = ProviderCredentialBeginIntentBinding::new(&command, &command_context);
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
    let legacy_import_authority = enrollment_authority.clone();
    let store =
        runne_store::provider::SqliteProviderCredentialLifecycleStore::open_with_authorities(
            &directory.path().join("host.sqlite"),
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();
    let reader = NoReadback;
    let host = super::super::host::DaemonProviderCredentialEnrollmentHost::new(
        verifier,
        measurements,
        legacy_import_authority,
        super::super::operation_handle::ProviderCredentialOperationHandleIssuer::new([9; 32]),
        &store,
        &reader,
        RejectVerification,
        Arc::new(|| 100),
    );

    let begun = host
        .begin(authority, proof, command_context, command)
        .await
        .unwrap();
    let resume_authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let resumed = host
        .resume(resume_authority, context(), begun.operation_handle())
        .await
        .unwrap();

    assert_eq!(begun.operation_handle(), resumed.operation_handle());
    assert_eq!(
        resumed.state(),
        ProviderCredentialOperationStateV2::Prepared
    );
    let rendezvous: [u8; 48] = hex::decode(begun.broker_rendezvous_id().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let forged_resume =
        runne_api::ProviderCredentialOperationHandleV2::from_bytes(rendezvous).unwrap();
    let rendezvous_authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();

    assert!(
        host.resume(rendezvous_authority, context(), forged_resume)
            .await
            .is_err()
    );
}
