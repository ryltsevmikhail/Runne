use super::http::generate_handle_key;
use super::install_local_readback_once;
use runne_provider::{CredentialVerificationLease, CredentialVerificationResult};
use runne_secure_store::{ProviderCredentialVerificationReadback, SecureStoreError};
use std::sync::{Arc, OnceLock};

struct Reader;

impl ProviderCredentialVerificationReadback for Reader {
    fn verify_local(
        &self,
        _: &CredentialVerificationLease,
    ) -> Result<CredentialVerificationResult, SecureStoreError> {
        Ok(CredentialVerificationResult::Verified)
    }
}

#[test]
fn local_readback_mount_is_idempotent_only_for_same_arc() {
    let slot = OnceLock::new();
    let first: Arc<dyn ProviderCredentialVerificationReadback> = Arc::new(Reader);
    let different: Arc<dyn ProviderCredentialVerificationReadback> = Arc::new(Reader);

    assert!(install_local_readback_once(&slot, Arc::clone(&first)).is_ok());
    assert!(install_local_readback_once(&slot, Arc::clone(&first)).is_ok());
    assert!(install_local_readback_once(&slot, different).is_err());
}

#[test]
fn control_handle_keys_are_nonzero_and_process_local() {
    let first = generate_handle_key().unwrap();
    let second = generate_handle_key().unwrap();
    assert_ne!(first, [0; 32]);
    assert_ne!(first, second);
}

#[test]
fn control_constructor_has_one_unconditional_portable_implementation() {
    let source = include_str!("construct.rs");
    let production = source;
    let signature = "pub(crate) fn new(";
    assert_eq!(production.matches(signature).count(), 1);
    assert!(production.contains(concat!(
        "impl DaemonProviderCredentialEnrollmentControl {\n",
        "    pub(crate) fn new("
    )));
    let constructor = production.split_once(signature).unwrap().1;
    let constructor = constructor.split_once("pub(crate) fn install_").unwrap().0;
    assert!(!constructor.contains("ProviderCredentialEnrollmentHostError::Unsupported"));
}
