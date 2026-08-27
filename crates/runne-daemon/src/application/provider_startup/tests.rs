#[test]
fn typed_startup_constructors_keep_verified_pairing_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigurationSnapshot::from_defaults(&crate::config::BuiltInDefaults::new(directory.path()));
    let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
    let verified = crate::application::VerifiedOwnerPrivateConfig::from_test_parts(config, bootstrap);
    let startup = StartupProvider::verified_external(&verified, ProtectedProviderDependencyCapsule::production());
    assert!(!startup.is_protected());
    assert_eq!(startup.activation.binding(), verified.provider_activation().binding());
}

#[test]
fn external_startup_parts_remain_unprotected_and_keep_provider_dependencies() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigurationSnapshot::from_defaults(&crate::config::BuiltInDefaults::new(directory.path()));
    let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
    let verified = crate::application::VerifiedOwnerPrivateConfig::from_test_parts(config, bootstrap);

    let (activation, provenance, launch_authority, protected, dependencies, keys) =
        StartupProvider::verified_external(&verified, ProtectedProviderDependencyCapsule::production())
            .into_parts();

    assert_eq!(activation.binding(), verified.provider_activation().binding());
    assert!(provenance.is_some());
    assert!(launch_authority.is_none());
    assert!(!protected);
    assert!(dependencies.is_some());
    assert!(keys.is_none());
}

#[cfg(all(unix, feature = "desktop-protected"))]
#[test]
fn protected_constructor_derives_the_pair_from_one_token() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigurationSnapshot::from_defaults(&crate::config::BuiltInDefaults::new(directory.path()));
    let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
    let start = VerifiedProtectedApplicationStart::from_test_parts(config, ProviderActivation::deterministic_v1(), bootstrap);
    assert!(StartupProvider::verified_protected(&start, runne_api::LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys(), ProtectedProviderDependencyCapsule::production()).is_protected());
}
