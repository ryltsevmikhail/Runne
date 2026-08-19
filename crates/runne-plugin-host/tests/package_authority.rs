use runne_plugin_host::{
    InvalidPluginIdentifier, PluginActivationId, PluginAuthorityPort, PluginAuthorityRegistry,
    PluginClass, PluginGeneration, PluginHookId, PluginHostProfileId, PluginPackageCapture,
    PluginPackageContent, PluginPackageFile, PluginPackageFileKind, PluginTrust,
};

const BUILTIN_MANIFEST: &[u8] = b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=builtin\npackage_version=1.0.0\nhost_identity=host\nplugin_identity=plugin\ntarget_identity=target\nentrypoint=entrypoint\nfile_table_digest=sha256:323c9209e107923ed099aa3e8a015ea71cc0c45ea1f3eae041c609bfbd1f5674\nprotocol_profile=builtin-profile-v2|sha256:66e64e0e083bc81b3b8043f9c3aeb306065abb7e0c47456c9f28cdb27e77823a\nfile=entrypoint|executable|39|sha256:c62efb3b0643adea80e7a6eb62c47661b285be4d8c2145b7eb5cfc7d82ba8ceb\nfile=package|data|36|sha256:035f422735e30a22bed0262055206c36fca329f1e2fe2dbad8191a9441fb3572\n";
const BUILTIN_PROFILE: &[u8] = b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=builtin-profile-v2\nversion=1.0\nbootstrap_schema_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\nwire_contract_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222\nsession_schema_bundle_digest=sha256:3333333333333333333333333333333333333333333333333333333333333333\nfeatures=bootstrap-v2\nbounds_profile_digest=sha256:4444444444444444444444444444444444444444444444444444444444444444\n";

#[test]
fn capture_rejects_file_bytes_that_do_not_match_the_declared_table() {
    let mut substituted_entrypoint = b"runne-plugin-host/builtin-entrypoint-v1".to_vec();
    substituted_entrypoint[0] = b'E';
    assert!(
        PluginPackageContent::try_new(
            b"runne-plugin-host/builtin-package-v1".to_vec(),
            BUILTIN_MANIFEST.to_vec(),
            substituted_entrypoint,
            BUILTIN_PROFILE.to_vec(),
            b"runne-plugin-host/builtin-trust-binding-v1".to_vec(),
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
        "runne-plugin.toml",
        "Runne-PLUGIN.TOML",
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
            b"runne-plugin-host/builtin-package-v1".to_vec(),
            BUILTIN_MANIFEST.to_vec(),
            b"runne-plugin-host/builtin-entrypoint-v1".to_vec(),
            BUILTIN_PROFILE.to_vec(),
            b"runne-plugin-host/builtin-trust-binding-v1".to_vec(),
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
