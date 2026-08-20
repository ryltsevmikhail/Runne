use runne_plugin_host::{
    InvalidPluginIdentifier, PluginActivationId, PluginAuthorityPort, PluginAuthorityRegistry,
    PluginClass, PluginGeneration, PluginHookId, PluginHostProfileId, PluginPackageCapture,
    PluginPackageContent, PluginPackageFile, PluginPackageFileKind, PluginTrust,
};

const BUILTIN_MANIFEST: &[u8] = b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\nfile_table_digest=sha256:7c095321ed00395bc7d98a7256f7493884c68727c9390ca67d6fa0fd5e7d0ef8\nprotocol_profile=builtin-profile-v2|sha256:6dbddbd754f8bff3d62cfefd31095bce32563ac2627705c924261c0bfe4f6c5d\nfile=entrypoint|executable|40|sha256:b819bdc75d5ae1d0f9f0611f08f58802c88cbbd015bef7aff3a0c3160e832834\nfile=package|data|37|sha256:c48131eae8e78a0f2fccc5d0bae39d73e44a8a1eb74484b1cc500e43de7e8253\n";
const BUILTIN_PROFILE: &[u8] = b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\nversion=1.0\nbootstrap_schema_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\nwire_contract_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222\nsession_schema_bundle_digest=sha256:3333333333333333333333333333333333333333333333333333333333333333\nfeatures=bootstrap-v2\nbounds_profile_digest=sha256:4444444444444444444444444444444444444444444444444444444444444444\n";

#[test]
fn capture_rejects_file_bytes_that_do_not_match_the_declared_table() {
    let mut substituted_entrypoint = b"gocode-plugin-host/builtin-entrypoint-v1".to_vec();
    substituted_entrypoint[0] = b'E';
    assert!(
        PluginPackageContent::try_new(
            b"gocode-plugin-host/builtin-package-v1".to_vec(),
            BUILTIN_MANIFEST.to_vec(),
            substituted_entrypoint,
            BUILTIN_PROFILE.to_vec(),
            b"gocode-plugin-host/builtin-trust-binding-v1".to_vec(),
        )
        .is_err()
    );
}

#[test]
fn package_file_rejects_portable_path_aliases_and_windows_devices() {
    for path in [
        "../x",
        "a//b",
        "/a",
        "C:/a",
        "a\\b",
        "CON/x",
        "a/COM1.exe",
        "gocode-plugin.toml",
        "GOCODE-PLUGIN.TOML",
    ] {
        assert!(
            PluginPackageFile::try_new(path.to_owned(), PluginPackageFileKind::Data, vec![])
                .is_err(),
            "{path}"
        );
    }
    let too_deep = std::iter::repeat_n("a", 33).collect::<Vec<_>>().join("/");
    assert!(PluginPackageFile::try_new(too_deep, PluginPackageFileKind::Data, vec![]).is_err());
    let file = PluginPackageFile::try_new(
        "bin/plugin".to_owned(),
        PluginPackageFileKind::Executable,
        vec![1],
    )
    .unwrap();
    assert_eq!(file.path(), "bin/plugin");
    assert_eq!(file.bytes(), [1]);
}

#[test]
fn builtin_registry_issues_only_its_embedded_authority() {
    let source = PluginPackageCapture::capture(
        PluginPackageContent::try_new(
            b"gocode-plugin-host/builtin-package-v1".to_vec(),
            BUILTIN_MANIFEST.to_vec(),
            b"gocode-plugin-host/builtin-entrypoint-v1".to_vec(),
            BUILTIN_PROFILE.to_vec(),
            b"gocode-plugin-host/builtin-trust-binding-v1".to_vec(),
        )
        .unwrap(),
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
fn same_version_runne_plugin_header_is_not_an_alias() {
    let runne_manifest = String::from_utf8(BUILTIN_MANIFEST.to_vec())
        .unwrap()
        .replacen("GOCODE_PLUGIN_MANIFEST_V1", "RUNNE_PLUGIN_MANIFEST_V1", 1)
        .into_bytes();
    assert!(
        PluginPackageContent::try_new(
            b"gocode-plugin-host/builtin-package-v1".to_vec(),
            runne_manifest,
            b"gocode-plugin-host/builtin-entrypoint-v1".to_vec(),
            BUILTIN_PROFILE.to_vec(),
            b"gocode-plugin-host/builtin-trust-binding-v1".to_vec(),
        )
        .is_err()
    );
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
