#[test]
fn recoverable_store_unavailability_keeps_control_transport_admissible() {
    use runne_api::ProviderActivationReadinessV1::{
        CredentialAccessDenied, CredentialIdentityMismatch, CredentialMissing, Ready,
        SecureStoreUnavailable,
    };

    assert!(!provider_readiness_blocks_launch(Ready));
    assert!(!provider_readiness_blocks_launch(CredentialMissing));
    assert!(!provider_readiness_blocks_launch(SecureStoreUnavailable));
    for readiness in [CredentialAccessDenied, CredentialIdentityMismatch] {
        assert!(provider_readiness_blocks_launch(readiness));
    }
}
