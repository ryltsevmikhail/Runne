    #[test]
    fn untrusted_process_cannot_read_raw_credential_without_ui() {
        let (store, _cleanup) = unique_provider_store("raw-untrusted-reader");
        let current = std::env::current_exe().expect("current test executable");
        let untrusted = ExecutableCopy::new(&current, "raw-untrusted-reader");
        untrusted.resign_with_distinct_identity();
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-raw-denial".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .unwrap();

        let mut child = std::process::Command::new(&untrusted.0)
            .args([
                "--exact",
                "macos::tests::untrusted_process_raw_credential_child",
                "--nocapture",
            ])
            .env("RUNNE_RAW_DENIAL_SERVICE", &store.service)
            .env("RUNNE_RAW_DENIAL_ACCOUNT", &store.account)
            .spawn()
            .expect("launch untrusted raw reader");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll untrusted raw reader") {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().expect("kill hung untrusted raw reader");
                let _ = child.wait();
                panic!("untrusted raw reader did not fail closed without UI");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(status.success(), "untrusted raw reader child failed");
    }

    #[test]
    fn untrusted_process_raw_credential_child() {
        let (Some(service), Some(account)) = (
            std::env::var_os("RUNNE_RAW_DENIAL_SERVICE"),
            std::env::var_os("RUNNE_RAW_DENIAL_ACCOUNT"),
        ) else {
            return;
        };
        let service = service.into_string().expect("UTF-8 service");
        let account = account.into_string().expect("UTF-8 account");
        let _interaction_lock =
            SecKeychain::disable_user_interaction().expect("disable Keychain UI");
        let keychain = active_keychain().expect("active Keychain");
        let error = keychain
            .find_generic_password(&service, &account)
            .expect_err("unenrolled process must not read raw credential");
        assert!(
            matches!(
                error.code(),
                ERR_SEC_AUTH_FAILED
                    | ERR_SEC_INTERACTION_NOT_ALLOWED
                    | ERR_SEC_NO_ACCESS_FOR_ITEM
                    | ERR_SEC_INVALID_OWNER_EDIT
            ),
            "unexpected raw denial status: {}",
            error.code()
        );
    }

    #[test]
    fn provider_credential_acl_migration_is_explicit_and_preserves_material() {
        if skip_if_partition_limitation(
            "provider_credential_acl_migration_is_explicit_and_preserves_material",
        ) {
            return;
        }
        let (store, _cleanup) = unique_provider_store("migration");
        let current = std::env::current_exe().expect("current test executable");
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-migration".to_vec()).unwrap();

        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &current_policy)
            .unwrap();
        store
            .migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            )
            .unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &replacement_policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &replacement_policy)
                .unwrap_err(),
            SecureStoreError::CredentialAccessDenied
        );
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
    }

    #[test]
    fn provider_credential_migration_recovers_verified_backup_after_restart_boundaries() {
        if skip_if_partition_limitation(
            "provider_credential_migration_recovers_verified_backup_after_restart_boundaries",
        ) {
            return;
        }
        for failpoint in [
            CredentialMigrationFailpoint::BackupEmptyWritten,
            CredentialMigrationFailpoint::BackupWritten,
            CredentialMigrationFailpoint::PrimaryDeleted,
            CredentialMigrationFailpoint::ReplacementEmptyWritten,
            CredentialMigrationFailpoint::ReplacementWritten,
        ] {
            let (store, _cleanup) = unique_provider_store(match failpoint {
                CredentialMigrationFailpoint::BackupEmptyWritten => "recover-after-backup-write",
                CredentialMigrationFailpoint::BackupWritten => "recover-after-backup",
                CredentialMigrationFailpoint::PrimaryDeleted => "recover-after-delete",
                CredentialMigrationFailpoint::ReplacementEmptyWritten => {
                    "recover-after-replacement-write"
                }
                CredentialMigrationFailpoint::ReplacementWritten => "recover-after-replacement",
            });
            let current = std::env::current_exe().expect("current test executable");
            let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
            let replacement_policy =
                ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
            let credential =
                ProviderCredentialMaterial::new(b"native-test-crash-recovery".to_vec()).unwrap();

            store
                .store_provider_credential(
                    ProviderCredentialId::OpenAi,
                    &credential,
                    &current_policy,
                )
                .unwrap();
            assert_eq!(
                store.migrate_provider_credential_access_inner(
                    ProviderCredentialId::OpenAi,
                    &current_policy,
                    &replacement_policy,
                    Some(failpoint),
                ),
                Err(SecureStoreError::CredentialMigrationIncomplete)
            );

            assert_eq!(
                store.provider_credential_status(ProviderCredentialId::OpenAi, &current_policy),
                Err(SecureStoreError::CredentialMigrationIncomplete)
            );
            assert_eq!(
                store
                    .load_provider_credential(ProviderCredentialId::OpenAi, &current_policy)
                    .unwrap_err(),
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

            let first_recovery = store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            );
            if matches!(failpoint, CredentialMigrationFailpoint::PrimaryDeleted) {
                assert_eq!(
                    first_recovery,
                    Err(SecureStoreError::CredentialMigrationIncomplete)
                );
                store
                    .migrate_provider_credential_access(
                        ProviderCredentialId::OpenAi,
                        &current_policy,
                        &replacement_policy,
                    )
                    .unwrap();
            } else {
                // The atomic populated write leaves either a fully proven
                // backup or a fully proven replacement, so one recovery
                // migration completes; only a missing primary needs the
                // backup renamed first.
                first_recovery.unwrap();
            }
            assert_eq!(
                store
                    .provider_credential_status(ProviderCredentialId::OpenAi, &replacement_policy)
                    .unwrap(),
                ProviderCredentialStatus::Configured
            );
            store
                .delete_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap();
        }
    }
