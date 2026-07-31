#[cfg(not(target_os = "macos"))]
use gocode_secure_store::StubStore;
use gocode_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};

#[test]
fn journal_key_requires_nonzero_identity_version_generation_and_authority() {
    assert!(ProviderJournalKeyRef::new([0; 16], 1, [2; 16], 3).is_err());
    assert!(ProviderJournalKeyRef::new([1; 16], 0, [2; 16], 3).is_err());
    assert!(ProviderJournalKeyRef::new([1; 16], 1, [0; 16], 3).is_err());
    assert!(ProviderJournalKeyRef::new([1; 16], 1, [2; 16], 0).is_err());
}

#[test]
fn key_material_debug_never_exposes_secret_bytes() {
    let key_ref = ProviderJournalKeyRef::new([1; 16], 2, [3; 16], 4).unwrap();
    let marker = [0x5a; 32];
    let key = ProviderJournalKeyMaterial::new(key_ref, marker).unwrap();

    let debug = format!("{key:?}");
    assert!(!debug.contains(&hex::encode(marker)));
    assert!(debug.contains("redacted"));
    assert_eq!(key.with_bytes(|bytes| *bytes), marker);
}

#[test]
fn generated_journal_keys_are_nonzero_distinct_and_keep_exact_binding() {
    let first_ref = ProviderJournalKeyRef::new([1; 16], 1, [2; 16], 3).unwrap();
    let second_ref = ProviderJournalKeyRef::new([4; 16], 2, [2; 16], 3).unwrap();
    let first = ProviderJournalKeyMaterial::generate(first_ref).unwrap();
    let second = ProviderJournalKeyMaterial::generate(second_ref).unwrap();

    assert_eq!(first.key_ref(), first_ref);
    assert_eq!(second.key_ref(), second_ref);
    assert_ne!(
        first.with_bytes(|bytes| *bytes),
        second.with_bytes(|bytes| *bytes)
    );
    assert_ne!(first.with_bytes(|bytes| *bytes), [0; 32]);
    assert_ne!(second.with_bytes(|bytes| *bytes), [0; 32]);
}

#[test]
fn key_status_is_metadata_only_and_does_not_load_material() {
    struct StatusOnly;
    impl ProviderJournalKeyring for StatusOnly {
        fn retains_multiple_provider_journal_keys(&self) -> bool {
            true
        }
        fn provider_journal_key_status(
            &self,
            _key_ref: ProviderJournalKeyRef,
        ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
            Ok(ProviderJournalKeyStatus::Available)
        }
        fn store_provider_journal_key(
            &self,
            _key: &ProviderJournalKeyMaterial,
        ) -> Result<(), SecureStoreError> {
            unreachable!("status must not store")
        }
        fn load_provider_journal_key(
            &self,
            _key_ref: ProviderJournalKeyRef,
        ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
            unreachable!("status must not load material")
        }
        fn delete_provider_journal_key(
            &self,
            _key_ref: ProviderJournalKeyRef,
            _proof: ProviderJournalKeyDeletionProof,
        ) -> Result<(), SecureStoreError> {
            unreachable!("status must not delete")
        }
    }
    let store = StatusOnly;
    let key_ref = ProviderJournalKeyRef::new([1; 16], 2, [3; 16], 4).unwrap();

    assert_eq!(
        store.provider_journal_key_status(key_ref),
        Ok(ProviderJournalKeyStatus::Available)
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn unsupported_native_backend_fails_closed_for_key_retention() {
    let store = StubStore::new();
    let key_ref = ProviderJournalKeyRef::new([1; 16], 2, [3; 16], 4).unwrap();
    let key = ProviderJournalKeyMaterial::new(key_ref, [5; 32]).unwrap();

    assert!(!store.retains_multiple_provider_journal_keys());
    assert!(matches!(
        store.store_provider_journal_key(&key),
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    ));
    assert!(matches!(
        store.load_provider_journal_key(key_ref),
        Err(SecureStoreError::UnsupportedSecureStoreBackend)
    ));
}
