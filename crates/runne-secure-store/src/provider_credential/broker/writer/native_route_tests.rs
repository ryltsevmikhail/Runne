#[cfg(not(feature = "local-native-enrollment-test"))]
#[test]
fn missing_service_configuration_never_constructs_a_legacy_writer() {
    let (_, effects) = runne_provider::CredentialWriterAuthorityPair::new().split();
    let result = super::build_effect_route(
        effects,
        None,
        |_| panic!("missing service must not grant legacy mutation authority"),
        || panic!("missing service must not construct a legacy import source"),
    );
    assert!(matches!(
        result,
        Err(crate::SecureStoreError::UnsupportedSecureStoreBackend)
    ));
}
