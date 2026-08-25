#[test]
fn provider_delete_preserves_mismatched_reader_item() {
    let (store, _cleanup) = unique_provider_store("delete-reader-mismatch");
    let current = std::env::current_exe().expect("current test executable");
    let enrolled = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
    let attempted = ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
    let sentinel = ProviderCredentialMaterial::new(b"native-delete-sentinel".to_vec()).unwrap();
    store
        .store_provider_credential(ProviderCredentialId::OpenAi, &sentinel, &enrolled)
        .unwrap();

    assert!(
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi, &attempted)
            .is_err()
    );
    assert_eq!(
        store
            .load_provider_credential(ProviderCredentialId::OpenAi, &enrolled)
            .unwrap()
            .with_bytes(<[u8]>::to_vec),
        b"native-delete-sentinel"
    );
}
