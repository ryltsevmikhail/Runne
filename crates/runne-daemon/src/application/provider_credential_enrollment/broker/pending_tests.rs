use runne_provider::CredentialOperationId;

use crate::application::provider_credential_enrollment::operation_handle::ProviderCredentialOperationHandleIssuer;

use super::PendingBrokerRendezvousRegistry;

#[test]
fn restarted_registry_has_no_live_rendezvous_authority() {
    let registry =
        PendingBrokerRendezvousRegistry::new(ProviderCredentialOperationHandleIssuer::new([9; 32]));
    let operation = CredentialOperationId::from_bytes([1; 16]).unwrap();

    assert!(!registry.has_live(operation, 1));
}
