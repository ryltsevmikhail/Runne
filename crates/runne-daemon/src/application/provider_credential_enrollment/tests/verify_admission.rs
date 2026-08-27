use runne_api::{
    ProviderCredentialEnrollmentHostError, ProviderCredentialProviderV2,
    ProviderCredentialRequestAuthorityPair, ProviderCredentialVerificationKindV2,
    ProviderCredentialVerifyIntentBinding, VerifyProviderCredential,
};

use super::super::ProviderCredentialAdmission;
use super::begin_admission_support::context;
use runne_provider::CredentialEnrollmentAuthorityPair;

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

fn verify(provider: ProviderCredentialProviderV2) -> VerifyProviderCredential {
    VerifyProviderCredential::new(
        provider,
        7,
        ProviderCredentialVerificationKindV2::Local,
        "018f8d23-7f90-7c00-8000-000000000001",
        "native-intent",
    )
    .unwrap()
}
