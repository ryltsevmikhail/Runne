// macOS-only policy guard: the macOS production route must never silently
// fall back to the in-process legacy writer when the XPC credential service
// configuration is missing. On Linux the legacy in-process route IS the only
// designed effect route (see build_effect_route's linux arm), so this
// assertion does not transfer across platforms.
#[cfg(all(not(feature = "local-native-enrollment-test"), target_os = "macos"))]
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
