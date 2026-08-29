#[test]
fn credential_missing_keeps_v2_transport_admissible_but_other_provider_failures_close_it() {
    use runne_api::ProviderActivationReadinessV1::{
        CredentialAccessDenied, CredentialIdentityMismatch, CredentialMissing, Ready,
        SecureStoreUnavailable,
    };

    assert!(!provider_readiness_blocks_launch(Ready));
    assert!(!provider_readiness_blocks_launch(CredentialMissing));
    for readiness in [
        CredentialAccessDenied,
        CredentialIdentityMismatch,
        SecureStoreUnavailable,
    ] {
        assert!(provider_readiness_blocks_launch(readiness));
    }
}
