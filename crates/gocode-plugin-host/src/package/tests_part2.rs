    #[test]
    fn rejects_trust_binding_substitution() {
        let source = PluginPackageCapture::capture(
            PluginPackageContent::new(
                b"package-a".to_vec(),
                b"GOCODE_PLUGIN_MANIFEST_V1\npackage_id=package-a\npackage_version=1.0.0\nhost_identity=host-a\nplugin_identity=plugin-a\ntarget_identity=target-a\nentrypoint=entrypoint-a\n".to_vec(),
                b"entrypoint-a".to_vec(),
                b"GOCODE_PLUGIN_PROFILE_V1\nprofile_id=profile-a\n".to_vec(),
                b"trust-binding-b".to_vec(),
            ),
            PluginClass::Extension,
        );

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::TrustBindingDigestMismatch)
        );
    }

    #[test]
    fn rejects_protocol_profile_substitution() {
        let mut source = source();
        source.protocol_profile_digest = PluginDigest::from_bytes([6; 32]);

        assert_eq!(
            PluginPackageVerifier::new(authority()).verify(source),
            Err(PluginPackageVerificationError::ProtocolProfileDigestMismatch)
        );
    }

    #[test]
    fn registry_advance_invalidates_old_package_lease_and_reverifies_captured_content() {
        let mut registry = registry();
        let activation_id = crate::PluginActivationId::new("advance").unwrap();
        let old_package = registry
            .verifier_for(&source())
            .unwrap()
            .verify(source())
            .unwrap();
        let old_generation = old_package.generation();
        let old_snapshot = old_package.negotiation_snapshot();
        let old_lease =
            crate::PluginGenerationPort::acquire_read_lease(&registry, &activation_id).unwrap();

        registry.advance().unwrap();

        assert_eq!(
            crate::PluginGenerationPort::ready_compare_and_set(&registry, &old_lease),
            Err(crate::PluginGenerationPortError::Unavailable)
        );

        let current_package = registry
            .verifier_for(&source())
            .unwrap()
            .verify(source())
            .unwrap();
        let current_lease =
            crate::PluginGenerationPort::acquire_read_lease(&registry, &activation_id).unwrap();
        assert!(current_package.generation() > old_generation);
        assert_ne!(current_package.negotiation_snapshot(), old_snapshot);
        assert!(
            current_package
                .negotiation_snapshot()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );
        assert_eq!(
            crate::PluginGenerationPort::ready_compare_and_set(&registry, &current_lease),
            Ok(())
        );
    }

    #[test]
    fn active_validation_requires_exact_published_activation_binding() {
        let registry = registry();
        let package = registry
            .verifier_for(&source())
            .unwrap()
            .verify(source())
            .unwrap();
        let published_id = crate::PluginActivationId::new("published").unwrap();
        let unpublished_id = crate::PluginActivationId::new("unpublished").unwrap();
        let published_lease = registry.acquire_read_lease(&published_id).unwrap();
        let unpublished_lease = registry.acquire_read_lease(&unpublished_id).unwrap();
        let unpublished =
            PluginActiveFence::issued(&unpublished_lease, package.negotiation_snapshot());
        assert_eq!(
            registry.validate_active(&unpublished),
            Err(PluginGenerationPortError::Unavailable)
        );

        let published = registry
            .publish_active(&published_lease, package.negotiation_snapshot())
            .unwrap();
        assert!(registry.validate_active(&published).is_ok());
        assert_eq!(
            registry.validate_active(&unpublished),
            Err(PluginGenerationPortError::Unavailable)
        );
    }
