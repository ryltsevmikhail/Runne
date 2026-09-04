use runne_provider::*;

pub fn target(version: CredentialVersionRef) -> CredentialBrokerTarget {
    CredentialBrokerTarget::ExactLegacySource(CredentialLegacyCleanupBinding::from_parts(
        CredentialOperationId::from_bytes([20; 16]).unwrap(),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        version,
        CredentialBindingDigest::from_measured([7; 32]).unwrap(),
    ))
}

pub fn revision(action: CredentialOperationAction) -> u64 {
    if action == CredentialOperationAction::LegacySourceCleanup { 2 } else { 1 }
}
