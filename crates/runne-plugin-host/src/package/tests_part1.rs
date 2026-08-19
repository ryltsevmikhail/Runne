    use super::*;

    fn content() -> PluginPackageContent {
        PluginPackageContent::new(
            b"package-a".to_vec(),
            b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
            b"entrypoint-a".to_vec(),
            b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
            b"trust-binding-a".to_vec(),
        )
    }

    fn declared_manifest(package: &[u8], entrypoint: &[u8]) -> Vec<u8> {
        upgrade_legacy_test_manifest(
            b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n",
            package,
            entrypoint,
            &upgrade_legacy_test_profile(
                b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n",
            ),
        )
    }

    fn source() -> PluginPackageSource {
        PluginPackageCapture::capture(content(), PluginClass::Extension)
    }

    fn authority() -> PluginPackageAuthority {
        PluginPackageAuthority::issue(
            &source(),
            PluginClass::Extension,
            PluginTrust::RegistryVerified,
        )
        .unwrap()
    }

    fn registry() -> PluginAuthorityRegistry {
        PluginAuthorityRegistry::from_trusted_loader(vec![authority()]).unwrap()
    }

    #[test]
    fn registry_issues_a_verifier_from_its_opaque_authority() {
        let source = source();
        let verifier = registry().verifier_for(&source).unwrap();

        let verified = verifier.verify(source).unwrap();
        assert_eq!(verified.effective_trust(), PluginTrust::RegistryVerified);
    }

    #[test]
    fn declared_file_table_rejects_missing_extra_alias_and_digest_mismatch() {
        let package = b"package-a";
        let entrypoint = b"entrypoint-a";
        let manifest = declared_manifest(package, entrypoint);
        let profile_bytes =
            upgrade_legacy_test_profile(b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n");
        let profile = parse_profile(&profile_bytes).unwrap();
        let trust = b"trust-binding-a".to_vec();

        let missing = PluginPackageContent::try_from_files(
            manifest.clone(),
            vec![
                PluginPackageFile::try_new(
                    "entrypoint-a".to_owned(),
                    PluginPackageFileKind::Executable,
                    entrypoint.to_vec(),
                )
                .unwrap(),
            ],
            profile.clone(),
            trust.clone(),
        );
        assert!(matches!(
            missing,
            Err(PluginPackageCaptureError::FileTableMismatch)
        ));

        let extra = PluginPackageContent::try_from_files(
            manifest.clone(),
            vec![
                PluginPackageFile::try_new(
                    "entrypoint-a".to_owned(),
                    PluginPackageFileKind::Executable,
                    entrypoint.to_vec(),
                )
                .unwrap(),
                PluginPackageFile::try_new(
                    "package".to_owned(),
                    PluginPackageFileKind::Data,
                    package.to_vec(),
                )
                .unwrap(),
                PluginPackageFile::try_new(
                    "resource".to_owned(),
                    PluginPackageFileKind::Data,
                    vec![1],
                )
                .unwrap(),
            ],
            profile.clone(),
            trust.clone(),
        );
        assert!(matches!(
            extra,
            Err(PluginPackageCaptureError::FileTableMismatch)
        ));

        let alias = PluginPackageContent::try_from_files(
            manifest.clone(),
            vec![
                PluginPackageFile::try_new(
                    "entrypoint-a".to_owned(),
                    PluginPackageFileKind::Executable,
                    entrypoint.to_vec(),
                )
                .unwrap(),
                PluginPackageFile::try_new(
                    "Package".to_owned(),
                    PluginPackageFileKind::Data,
                    package.to_vec(),
                )
                .unwrap(),
                PluginPackageFile::try_new(
                    "package".to_owned(),
                    PluginPackageFileKind::Data,
                    package.to_vec(),
                )
                .unwrap(),
            ],
            profile.clone(),
            trust.clone(),
        );
        assert!(matches!(
            alias,
            Err(PluginPackageCaptureError::DuplicatePath)
        ));

        let mut mismatched_digest = manifest;
        let digest_offset = mismatched_digest
            .windows(b"sha256:".len())
            .rposition(|window| window == b"sha256:")
            .unwrap()
            + b"sha256:".len();
        mismatched_digest[digest_offset] = if mismatched_digest[digest_offset] == b'0' {
            b'1'
        } else {
            b'0'
        };
        let mismatch = PluginPackageContent::try_new(
            package.to_vec(),
            mismatched_digest,
            entrypoint.to_vec(),
            profile_bytes,
            trust,
        );
        assert!(matches!(
            mismatch,
            Err(PluginPackageCaptureError::FileTableMismatch)
        ));
    }

    #[test]
    fn manifest_binds_the_complete_protocol_profile_into_package_identity() {
        let first = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-a".to_vec(),
                b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );
        let second = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-a".to_vec(),
                b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=profile-b\n".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );

        assert_ne!(first.manifest_digest, second.manifest_digest);
        assert_ne!(first.package_digest, second.package_digest);
        assert_ne!(
            first.protocol_profile_digest,
            second.protocol_profile_digest
        );
    }

    #[test]
    fn mutation_of_original_input_cannot_change_retained_verified_bytes() {
        let mut original_package = b"package-a".to_vec();
        let source = PluginPackageCapture::capture(
            PluginPackageContent::new(
                original_package.clone(),
                b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );
        let expected_package = source
            .content
            .files
            .iter()
            .find(|file| file.path() == "package")
            .unwrap()
            .bytes
            .clone();
        original_package[0] = b'P';
        let verifier = registry().verifier_for(&source).unwrap();

        let verified = verifier.verify(source).unwrap();

        let retained_package = verified
            .source
            .content
            .files
            .iter()
            .find(|file| file.path() == "package")
            .unwrap();
        assert_eq!(retained_package.bytes, expected_package);
        assert_ne!(retained_package.bytes.as_ref(), original_package.as_slice());
    }

    #[test]
    fn changed_content_cannot_reuse_registry_verification() {
        let changed = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-b".to_vec(),
                b"RUNNE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"RUNNE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
                b"trust-binding-a".to_vec(),
            ),
            PluginClass::Extension,
        );

        assert_eq!(
            registry().verifier_for(&changed),
            Err(PluginAuthorityPortError::Unavailable)
        );
    }

    #[test]
    fn rejects_package_digest_substitution() {
        let mut source = source();
        source.package_digest = PluginDigest::from_bytes([9; 32]);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::PackageDigestMismatch)
        );
    }

    #[test]
    fn rejects_manifest_digest_substitution() {
        let mut source = source();
        source.manifest_digest = PluginDigest::from_bytes([8; 32]);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::ManifestDigestMismatch)
        );
    }

    #[test]
    fn rejects_entrypoint_digest_substitution() {
        let mut source = source();
        source.entrypoint_digest = PluginDigest::from_bytes([7; 32]);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::EntrypointDigestMismatch)
        );
    }

    #[test]
    fn rejects_declared_class_substitution() {
        let source = PluginPackageCapture::capture(content(), PluginClass::Security);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::DeclaredClassMismatch)
        );
    }
