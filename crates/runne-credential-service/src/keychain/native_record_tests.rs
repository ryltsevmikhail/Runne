use super::*;

#[test]
fn one_add_record_couples_secret_and_exact_source_revision() {
    let reference = runne_provider::CredentialVersionRef::new(
        runne_provider::ProviderId::new("openai").unwrap(),
        7,
    )
    .unwrap();
    let attributes = add_attributes(
        &CredentialItemLocator::new(&reference),
        b"secret",
        Some([9; 16]),
    );
    let record = decode_record(&attributes).unwrap_or_else(|_| panic!("valid record"));
    assert_eq!(record.source_revision, Some([9; 16]));
    record
        .material
        .consume(|bytes| assert_eq!(bytes, b"secret"));
}

#[test]
fn invalid_revision_metadata_is_not_treated_as_an_ordinary_key() {
    let reference = runne_provider::CredentialVersionRef::new(
        runne_provider::ProviderId::new("openai").unwrap(),
        7,
    )
    .unwrap();
    let locator = CredentialItemLocator::new(&reference);
    assert!(decode_record(&add_attributes(&locator, b"secret", Some([0; 16]))).is_err());
    let plain = decode_record(&add_attributes(&locator, b"secret", None))
        .unwrap_or_else(|_| panic!("plain"));
    assert_eq!(plain.source_revision, None);
}

#[test]
fn record_decoder_rejects_wrong_type_short_revision_and_missing_secret() {
    let reference = runne_provider::CredentialVersionRef::new(
        runne_provider::ProviderId::new("openai").unwrap(),
        7,
    )
    .unwrap();
    let attributes = add_attributes(
        &CredentialItemLocator::new(&reference),
        b"secret",
        Some([9; 16]),
    );
    let mut malformed = unsafe { attributes.to_mutable() };
    let short = CFData::from_buffer(&[9; 15]);
    unsafe {
        malformed.set(kSecAttrGeneric.to_void(), short.to_void());
    }
    assert!(decode_record(&malformed.to_immutable()).is_err());
    let text = CFString::new("not-data");
    unsafe {
        malformed.set(kSecAttrGeneric.to_void(), text.to_void());
    }
    assert!(decode_record(&malformed.to_immutable()).is_err());
    let mut missing = unsafe { attributes.to_mutable() };
    unsafe {
        missing.remove(kSecValueData.to_void());
    }
    assert!(decode_record(&missing.to_immutable()).is_err());
}
