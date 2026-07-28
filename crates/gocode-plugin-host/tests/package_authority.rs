use gocode_plugin_host::{
    InvalidPluginIdentifier, PluginActivationId, PluginAuthorityPort, PluginAuthorityRegistry,
    PluginClass, PluginGeneration, PluginHookId, PluginHostProfileId, PluginPackageCapture,
    PluginPackageContent, PluginTrust,
};

#[test]
fn capture_hashes_package_bytes_instead_of_accepting_digest_claims() {
    let package = b"package-a".to_vec();
    let original = PluginPackageCapture::capture(
        PluginPackageContent::new(
            package.clone(),
            b"manifest-a".to_vec(),
            b"entrypoint-a".to_vec(),
            b"profile-a".to_vec(),
            b"trust-binding-a".to_vec(),
        ),
        PluginClass::Extension,
    );
    let mut substituted_package = package;
    substituted_package[0] = b'P';
    let substituted = PluginPackageCapture::capture(
        PluginPackageContent::new(
            substituted_package,
            b"manifest-a".to_vec(),
            b"entrypoint-a".to_vec(),
            b"profile-a".to_vec(),
            b"trust-binding-a".to_vec(),
        ),
        PluginClass::Extension,
    );

    assert_ne!(original.package_digest(), substituted.package_digest());
}

#[test]
fn builtin_registry_issues_only_its_embedded_authority() {
    let source = PluginPackageCapture::capture(
        PluginPackageContent::new(
            b"gocode-plugin-host/builtin-package-v1".to_vec(),
            b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\n".to_vec(),
            b"gocode-plugin-host/builtin-entrypoint-v1".to_vec(),
            b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\n".to_vec(),
            b"gocode-plugin-host/builtin-trust-binding-v1".to_vec(),
        ),
        PluginClass::Extension,
    );

    let verified = PluginAuthorityRegistry::built_in()
        .verifier_for(&source)
        .unwrap()
        .verify(source)
        .unwrap();

    assert_eq!(verified.effective_trust(), PluginTrust::Restricted);
}

#[test]
fn host_profile_identifier_rejects_empty_control_and_129_byte_values() {
    assert_eq!(
        PluginHostProfileId::new(""),
        Err(InvalidPluginIdentifier::Empty)
    );
    assert_eq!(
        PluginHostProfileId::new("profile\n"),
        Err(InvalidPluginIdentifier::InvalidCharacter)
    );
    assert!(matches!(
        PluginHostProfileId::new("x".repeat(129)),
        Err(InvalidPluginIdentifier::TooLong {
            max: 128,
            actual: 129
        })
    ));
}

#[test]
fn activation_identifier_rejects_empty_control_and_129_byte_values() {
    assert_eq!(
        PluginActivationId::new(""),
        Err(InvalidPluginIdentifier::Empty)
    );
    assert_eq!(
        PluginActivationId::new("activation\n"),
        Err(InvalidPluginIdentifier::InvalidCharacter)
    );
    assert!(matches!(
        PluginActivationId::new("x".repeat(129)),
        Err(InvalidPluginIdentifier::TooLong {
            max: 128,
            actual: 129
        })
    ));
}

#[test]
fn hook_identifier_rejects_empty_control_and_129_byte_values() {
    assert_eq!(PluginHookId::new(""), Err(InvalidPluginIdentifier::Empty));
    assert_eq!(
        PluginHookId::new("hook\n"),
        Err(InvalidPluginIdentifier::InvalidCharacter)
    );
    assert!(matches!(
        PluginHookId::new("x".repeat(129)),
        Err(InvalidPluginIdentifier::TooLong {
            max: 128,
            actual: 129
        })
    ));
}

#[test]
fn generation_zero_is_not_a_valid_plugin_generation() {
    assert_eq!(PluginGeneration::new(0), None);
}
