    #[test]
    fn provider_credential_migration_discards_incomplete_backup_after_verifying_primary() {
        if skip_if_partition_limitation(
            "provider_credential_migration_discards_incomplete_backup_after_verifying_primary",
        ) {
            return;
        }
        let (store, _cleanup) = unique_provider_store("incomplete-backup");
        let current = std::env::current_exe().unwrap();
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-incomplete-backup".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &current_policy)
            .unwrap();
        seed_incomplete_provider_item(&store, &store.migration_service(), &current_policy);

        assert_eq!(
            store.provider_credential_status(ProviderCredentialId::OpenAi, &current_policy),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &current_policy)
                .err()
                .expect("incomplete migration rejected"),
            SecureStoreError::CredentialMigrationIncomplete
        );
        assert_eq!(
            store.store_provider_credential(
                ProviderCredentialId::OpenAi,
                &credential,
                &current_policy,
            ),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        store
            .migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            )
            .expect("verified complete primary wins over incomplete backup");
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &replacement_policy,)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
    }

    #[test]
    fn provider_credential_migration_restores_complete_backup_over_incomplete_replacement() {
        if skip_if_partition_limitation(
            "provider_credential_migration_restores_complete_backup_over_incomplete_replacement",
        ) {
            return;
        }
        let (store, _cleanup) = unique_provider_store("incomplete-replacement");
        let current = std::env::current_exe().unwrap();
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-incomplete-replacement".to_vec())
                .unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &current_policy)
            .unwrap();
        MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            let (encoded, primary) = store
                .find_primary_item(keychain)?
                .expect("complete primary before replacement crash");
            let (metadata, _) = store
                .find_named_metadata(keychain, &store.service)?
                .expect("complete primary metadata before replacement crash");
            let current_access = ExactKeychainAccess::new(
                current_policy.writer_path(),
                current_policy.reader_path(),
            )
            .map_err(map_acl_error)?;
            create_populated_provider_item(
                keychain,
                &store.migration_service(),
                &store.account,
                &metadata,
                &current_access,
                &encoded,
                None,
            )?;
            runne_macos_keychain_acl::delete_item(&primary).map_err(map_acl_error)
        })
        .unwrap();
        seed_incomplete_provider_item(&store, &store.service, &replacement_policy);

        assert_eq!(
            store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            ),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &current_policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        store
            .migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            )
            .unwrap();
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
    }

    #[test]
    fn migration_rejects_broad_primary_before_materializing_its_password() {
        if skip_if_partition_limitation(
            "migration_rejects_broad_primary_before_materializing_its_password",
        ) {
            return;
        }
        let (store, _cleanup) = unique_provider_store("broad-primary-reconcile");
        let current = std::env::current_exe().unwrap();
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-broad-primary".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &current_policy)
            .unwrap();
        MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            let (encoded, primary) = store
                .find_primary_item(keychain)?
                .expect("complete primary before forged replacement");
            let current_access =
                ExactKeychainAccess::new(&current, &current).map_err(map_acl_error)?;
            let current_metadata =
                ProviderCredentialMetadata::from_access(&current_policy, current_access.digest());
            create_populated_provider_item(
                keychain,
                &store.migration_service(),
                &store.account,
                &current_metadata,
                &current_access,
                &encoded,
                None,
            )?;
            runne_macos_keychain_acl::delete_item(&primary).map_err(map_acl_error)?;

            let broad_access = ExactKeychainAccess::new(&current, Path::new("/bin/echo"))
                .map_err(map_acl_error)?;
            let broad_metadata =
                ProviderCredentialMetadata::from_access(&current_policy, broad_access.digest());
            let broad_encoded = StoredProviderCredential::encode(
                &credential,
                &current_policy,
                broad_access.digest(),
            )?;
            create_populated_provider_item(
                keychain,
                &store.service,
                &store.account,
                &broad_metadata,
                &broad_access,
                &broad_encoded,
                None,
            )
            .map(|_| ())
        })
        .unwrap();

        PROVIDER_CREDENTIAL_PASSWORD_READS.set(0);
        assert_eq!(
            store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            ),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        assert_eq!(
            PROVIDER_CREDENTIAL_PASSWORD_READS.get(),
            1,
            "only the verified backup may be materialized before primary ACL rejection"
        );
    }
