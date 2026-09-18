#[test]
fn typed_startup_constructors_keep_verified_pairing_atomic() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigurationSnapshot::from_defaults(&crate::config::BuiltInDefaults::new(
        directory.path(),
    ));
    let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
    let verified =
        crate::application::VerifiedOwnerPrivateConfig::from_test_parts(config, bootstrap);
    let startup = StartupProvider::verified_external(
        &verified,
        ProtectedProviderDependencyCapsule::production(),
    );
    assert!(!startup.is_protected());
    assert_eq!(
        startup.activation.binding(),
        verified.provider_activation().binding()
    );
}

#[test]
fn external_startup_parts_remain_unprotected_and_keep_provider_dependencies() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigurationSnapshot::from_defaults(&crate::config::BuiltInDefaults::new(
        directory.path(),
    ));
    let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
    let verified =
        crate::application::VerifiedOwnerPrivateConfig::from_test_parts(config, bootstrap);

    let (activation, provenance, launch_authority, protected, dependencies, keys, capability) =
        StartupProvider::verified_external(
            &verified,
            ProtectedProviderDependencyCapsule::production(),
        )
        .into_parts();

    assert_eq!(
        activation.binding(),
        verified.provider_activation().binding()
    );
    assert!(provenance.is_some());
    assert!(launch_authority.is_none());
    assert!(!protected);
    assert!(dependencies.is_some());
    assert!(keys.is_none());
    assert!(capability.is_none());
}

#[test]
fn deterministic_startup_rejects_every_credentialed_activation() {
    let directory = tempfile::tempdir().unwrap();
    let defaults = crate::config::BuiltInDefaults::new(directory.path());
    let bindings = [
        runne_api::ProviderActivationBindingV1::openai_responses_text_v1(),
        runne_api::ProviderActivationBindingV1::deepseek_responses_text_v1(),
        runne_api::ProviderActivationBindingV1::zai_coding_chat_completions_text_v1(),
        runne_api::ProviderActivationBindingV1::qwencloud_token_chat_completions_text_v1(),
        runne_api::ProviderActivationBindingV1::new(
            runne_api::ProviderActivationModeV1::GenericChatCompletionsTextV1,
            "gocode-chat-completions/fixture/1",
            [1; 32],
        )
        .unwrap(),
        runne_api::ProviderActivationBindingV1::new(
            runne_api::ProviderActivationModeV1::NativeTextV1,
            runne_api::NATIVE_ANTHROPIC_PROFILE_ID,
            runne_api::NATIVE_ANTHROPIC_PROFILE_DIGEST,
        )
        .unwrap(),
        runne_api::ProviderActivationBindingV1::new(
            runne_api::ProviderActivationModeV1::RadiusTextV1,
            runne_api::RADIUS_TEXT_PROFILE_ID,
            [2; 32],
        )
        .unwrap(),
    ];
    for binding in bindings {
        let mut config = ConfigurationSnapshot::from_defaults(&defaults);
        config.provider_activation = ProviderActivation::from_binding(binding);
        assert!(StartupProvider::deterministic(&config).is_err());
    }
}

#[cfg(all(unix, feature = "desktop-protected"))]
#[test]
fn protected_constructor_derives_the_pair_from_one_token() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigurationSnapshot::from_defaults(&crate::config::BuiltInDefaults::new(
        directory.path(),
    ));
    let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
    let start = VerifiedProtectedApplicationStart::from_test_parts(
        config,
        ProviderActivation::deterministic_v1(),
        bootstrap,
    );
    assert!(
        StartupProvider::verified_protected(
            &start,
            runne_api::LaunchSecret::from_bytes([7; 32])
                .unwrap()
                .derive_keys(),
            ProtectedProviderDependencyCapsule::production(),
            None
        )
        .is_protected()
    );
}
