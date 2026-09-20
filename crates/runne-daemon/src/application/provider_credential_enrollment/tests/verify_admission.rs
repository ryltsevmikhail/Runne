use runne_api::{
    ProviderCredentialEnrollmentHostError, ProviderCredentialProviderV2,
    ProviderCredentialRequestAuthorityPair, ProviderCredentialVerificationKindV2,
    ProviderCredentialVerifyIntentBinding, VerifyProviderCredential,
};

use super::super::{ProviderCredentialAdmission, ProviderCredentialVerificationHost};
use super::begin_admission_support::context;
use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentAuthorityPair, CredentialVerificationLease,
    CredentialVerificationResult,
};
use runne_secure_store::{ProviderCredentialVerificationReadback, SecureStoreError};

struct PanicReader;

impl ProviderCredentialVerificationReadback for PanicReader {
    fn verify_local(
        &self,
        _: &CredentialVerificationLease,
    ) -> Result<CredentialVerificationResult, SecureStoreError> {
        panic!("remote verification must not materialize or inspect native credentials")
    }
}

#[test]
fn daemon_verify_rejects_a_provider_substituted_intent_before_store_access() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let expected = verify(ProviderCredentialProviderV2::OpenAi);
    let context = context();
    let substituted = verify(ProviderCredentialProviderV2::DeepSeek);
    let binding = ProviderCredentialVerifyIntentBinding::new(&substituted, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            10,
        )
        .unwrap();
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let admission = ProviderCredentialAdmission::new(verifier, measurements);

    assert_eq!(
        admission.require_verify_command(&authority, &proof, &expected, &context),
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    );
}

#[test]
fn remote_verify_is_rejected_before_the_local_native_reader() {
    let (issuer, verifier) = ProviderCredentialRequestAuthorityPair::new().split();
    let authority = issuer
        .issue_base([1; 32], [2; 32], [3; 32], 1, [4; 32], 1, [5; 32])
        .unwrap();
    let command = verify_with_kind(
        ProviderCredentialProviderV2::OpenAi,
        ProviderCredentialVerificationKindV2::Remote,
    );
    let context = context();
    let binding = ProviderCredentialVerifyIntentBinding::new(&command, &context);
    let proof = issuer
        .issue_intent_proof(
            [6; 32],
            [3; 32],
            *binding.action_provider_revision_digest(),
            *binding.command_identity_digest(),
            200,
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
                daemon.join("remote-rejected.sqlite")
            },
            lifecycle_authority,
            enrollment_authority,
        )
        .unwrap();
    let verifier = crate::application::provider_credential_verification::LocalProviderCredentialVerification::new(
        ProviderCredentialAdmission::new(verifier, measurements),
        super::super::operation_handle::ProviderCredentialOperationHandleIssuer::new([9; 32]),
        &store,
        &PanicReader,
    );

    assert_eq!(
        verifier.verify(authority, proof, context, command),
        Err(ProviderCredentialEnrollmentHostError::Unsupported)
    );
}

fn verify(provider: ProviderCredentialProviderV2) -> VerifyProviderCredential {
    verify_with_kind(provider, ProviderCredentialVerificationKindV2::Local)
}

fn verify_with_kind(
    provider: ProviderCredentialProviderV2,
    verification_kind: ProviderCredentialVerificationKindV2,
) -> VerifyProviderCredential {
    VerifyProviderCredential::new(
        provider,
        7,
        verification_kind,
        "018f8d23-7f90-7c00-8000-000000000001",
        "native-intent",
    )
    .unwrap()
}
