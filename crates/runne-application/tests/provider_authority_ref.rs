use runne_application::provider::{ProviderAdmissionError, ProviderEffectAuthorityRef};

#[test]
fn authority_reference_rejects_zero_identity_and_revision() {
    assert_eq!(
        ProviderEffectAuthorityRef::new([0; 16], 1),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    assert_eq!(
        ProviderEffectAuthorityRef::new([1; 16], 0),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
}
