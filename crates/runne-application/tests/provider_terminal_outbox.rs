use runne_application::provider::{
    ProviderEncryptedPayload, ProviderExecutionError, ProviderJournalKeyBinding,
};

#[test]
fn encrypted_payload_debug_excludes_ciphertext_and_plaintext_markers() {
    let marker = b"provider-terminal-sensitive-marker-91";
    let payload = ProviderEncryptedPayload::new(
        [1; 12],
        marker.to_vec(),
        u64::try_from(marker.len() - 16).unwrap(),
        [2; 32],
    )
    .unwrap();

    let debug = format!("{payload:?}");
    assert!(!debug.contains(std::str::from_utf8(marker).unwrap()));
    assert!(!debug.contains(&hex::encode(marker)));
    assert!(debug.contains("ciphertext_len"));
}

#[test]
fn encrypted_payload_and_key_bindings_reject_zero_or_unbounded_metadata() {
    assert_eq!(
        ProviderJournalKeyBinding::new([0; 16], 1, [2; 16], 3),
        Err(ProviderExecutionError::JournalKeyUnavailable)
    );
    assert_eq!(
        ProviderJournalKeyBinding::new([1; 16], 0, [2; 16], 3),
        Err(ProviderExecutionError::JournalKeyUnavailable)
    );
    assert_eq!(
        ProviderEncryptedPayload::new([0; 12], vec![1; 17], 1, [2; 32]),
        Err(ProviderExecutionError::JournalCorrupt)
    );
    assert_eq!(
        ProviderEncryptedPayload::new([1; 12], vec![1; 17], 2, [2; 32]),
        Err(ProviderExecutionError::JournalCorrupt)
    );
    assert!(ProviderEncryptedPayload::new([1; 12], vec![1; 16], 0, [2; 32]).is_ok());
    assert_eq!(
        ProviderEncryptedPayload::new([1; 12], vec![1; 4_194_305], 1, [2; 32]),
        Err(ProviderExecutionError::JournalCorrupt)
    );
}
