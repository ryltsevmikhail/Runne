    #[test]
    fn provider_credential_delete_is_monotonic_after_every_migration_failpoint() {
        if skip_if_partition_limitation(
            "provider_credential_delete_is_monotonic_after_every_migration_failpoint",
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
                CredentialMigrationFailpoint::BackupEmptyWritten => "delete-after-backup-write",
                CredentialMigrationFailpoint::BackupWritten => "delete-after-backup",
                CredentialMigrationFailpoint::PrimaryDeleted => "delete-after-primary",
                CredentialMigrationFailpoint::ReplacementEmptyWritten => {
                    "delete-after-replacement-write"
                }
                CredentialMigrationFailpoint::ReplacementWritten => "delete-after-replacement",
            });
            let current = std::env::current_exe().expect("current test executable");
            let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
            let replacement_policy =
                ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
            let credential =
                ProviderCredentialMaterial::new(b"native-test-monotonic-delete".to_vec()).unwrap();

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

            store
                .delete_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap();
            assert_eq!(
                store
                    .provider_credential_status(ProviderCredentialId::OpenAi, &current_policy)
                    .unwrap(),
                ProviderCredentialStatus::Missing
            );
            assert_eq!(
                store
                    .load_provider_credential(ProviderCredentialId::OpenAi, &current_policy)
                    .err()
                    .expect("deleted credential remains absent"),
                SecureStoreError::ProviderCredentialNotFound
            );
            store
                .delete_provider_credential(ProviderCredentialId::OpenAi)
                .unwrap();
        }
    }

    #[test]
    fn enrolled_daemon_reader_can_query_status_without_loading_credential() {
        let (store, _cleanup) = unique_provider_store("reader-status");
        let current = std::env::current_exe().expect("current test executable");
        let reader = ExecutableCopy::new(&current, "status-reader");
        let policy = ProviderCredentialAccessPolicy::new(&current, &reader.0).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-reader-status".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .unwrap();

        let output = std::process::Command::new(&reader.0)
            .args([
                "--exact",
                "macos::tests::provider_credential_reader_status_child",
                "--nocapture",
            ])
            .env("RUNNE_PROVIDER_STATUS_SERVICE", &store.service)
            .env("RUNNE_PROVIDER_STATUS_ACCOUNT", &store.account)
            .env("RUNNE_PROVIDER_STATUS_WRITER", &current)
            .output()
            .expect("launch enrolled reader status child");
        assert!(
            output.status.success(),
            "reader status child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn provider_credential_reader_status_child() {
        let (Some(service), Some(account), Some(writer)) = (
            std::env::var_os("RUNNE_PROVIDER_STATUS_SERVICE"),
            std::env::var_os("RUNNE_PROVIDER_STATUS_ACCOUNT"),
            std::env::var_os("RUNNE_PROVIDER_STATUS_WRITER"),
        ) else {
            return;
        };
        let store = MacOsProviderCredentialStore::with_test_item(
            service.into_string().expect("UTF-8 service"),
            account.into_string().expect("UTF-8 account"),
        );
        let current = std::env::current_exe().unwrap();
        let policy = ProviderCredentialAccessPolicy::new(Path::new(&writer), &current).unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
    }

    #[test]
    fn provider_credential_migration_rejects_writer_identity_change() {
        let current = std::env::current_exe().expect("current test executable");
        let replacement_writer = ExecutableCopy::new(&current, "replacement-writer");
        let current_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&replacement_writer.0, &current).unwrap();
        let (store, _cleanup) = unique_provider_store("writer-migration-denied");

        assert_eq!(
            store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &current_policy,
                &replacement_policy,
            ),
            Err(SecureStoreError::CredentialAccessDenied)
        );
    }

    #[test]
    fn provider_credential_process_lock_is_cross_process() {
        let (store, _cleanup) = unique_provider_store("cross-process-lock");
        let current = std::env::current_exe().expect("current test executable");
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let credential =
            ProviderCredentialMaterial::new(b"native-test-lock-operation".to_vec()).unwrap();
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .unwrap();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let child_temp = std::env::temp_dir().join(format!(
            "runne-provider-lock-child-tmp-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&child_temp).unwrap();
        let ready_marker = child_temp.join("ready");
        let configured_marker = child_temp.join("configured");
        // Keep sibling tests from winning the user-wide lock after the parent
        // releases it but before the child can acquire it. The child has its
        // own process-local mutex, so this serializes only this test binary.
        let _operation_lock = KEYCHAIN_INTERACTION_LOCK.lock().unwrap();
        let process_lock = ProviderCredentialProcessLock::acquire().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macos::tests::provider_credential_process_lock_child",
                "--nocapture",
            ])
            .env("RUNNE_PROVIDER_LOCK_TEST_CHILD", "1")
            .env("RUNNE_PROVIDER_LOCK_SERVICE", &store.service)
            .env("RUNNE_PROVIDER_LOCK_ACCOUNT", &store.account)
            .env("RUNNE_PROVIDER_LOCK_MARKER_DIR", &child_temp)
            .env("TMPDIR", &child_temp)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn lock contender");
        wait_for_marker_file(&ready_marker, std::time::Duration::from_secs(5)).unwrap();
        {
            let mut child_stdin = child.stdin.take().unwrap();
            child_stdin.write_all(b"GO\n").unwrap();
            child_stdin.flush().unwrap();
        }
        assert!(
            !configured_marker.exists() && child.try_wait().unwrap().is_none(),
            "child with a different TMPDIR bypassed the process lock"
        );
        drop(process_lock);
        wait_for_marker_file(&configured_marker, std::time::Duration::from_secs(5)).unwrap();
        assert!(child.wait().unwrap().success());
        std::fs::remove_dir_all(child_temp).unwrap();
    }

    #[test]
    fn provider_journal_keychain_access_uses_the_process_lock() {
        let process_lock = ProviderCredentialProcessLock::acquire().unwrap();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let child_temp = std::env::temp_dir().join(format!(
            "runne-journal-lock-child-tmp-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&child_temp).unwrap();
        let ready_marker = child_temp.join("ready");
        let completed_marker = child_temp.join("completed");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macos::tests::provider_journal_process_lock_child",
                "--nocapture",
            ])
            .env("RUNNE_JOURNAL_LOCK_TEST_CHILD", "1")
            .env("RUNNE_JOURNAL_LOCK_MARKER_DIR", &child_temp)
            .spawn()
            .unwrap();
        wait_for_marker_file(&ready_marker, std::time::Duration::from_secs(5)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let bypassed = completed_marker.exists() || child.try_wait().unwrap().is_some();
        drop(process_lock);
        wait_for_marker_file(&completed_marker, std::time::Duration::from_secs(5)).unwrap();
        assert!(child.wait().unwrap().success());
        std::fs::remove_dir_all(child_temp).unwrap();
        assert!(!bypassed, "journal Keychain access bypassed the process lock");
    }

    #[test]
    fn provider_journal_process_lock_child() {
        let Some(marker_dir) = std::env::var_os("RUNNE_JOURNAL_LOCK_MARKER_DIR") else {
            return;
        };
        if std::env::var_os("RUNNE_JOURNAL_LOCK_TEST_CHILD").is_none() {
            return;
        }
        let marker_dir = std::path::PathBuf::from(marker_dir);
        std::fs::write(marker_dir.join("ready"), b"").unwrap();
        let profile = format!("journal-process-lock-child-{}", std::process::id());
        let store = MacOsKeychainStore::new(profile);
        let key_ref = ProviderJournalKeyRef::new([51; 16], 1, [52; 16], 53).unwrap();
        assert_eq!(
            store.provider_journal_key_status(key_ref).unwrap(),
            ProviderJournalKeyStatus::Missing
        );
        std::fs::write(marker_dir.join("completed"), b"").unwrap();
    }

    #[test]
    fn provider_credential_process_lock_child() {
        if std::env::var_os("RUNNE_PROVIDER_LOCK_TEST_CHILD").is_none() {
            return;
        }
        let marker_dir =
            std::path::PathBuf::from(std::env::var_os("RUNNE_PROVIDER_LOCK_MARKER_DIR").unwrap());
        std::fs::write(marker_dir.join("ready"), b"").unwrap();
        let mut go = String::new();
        std::io::stdin().read_line(&mut go).unwrap();
        assert_eq!(go, "GO\n");
        let service = std::env::var("RUNNE_PROVIDER_LOCK_SERVICE").unwrap();
        let account = std::env::var("RUNNE_PROVIDER_LOCK_ACCOUNT").unwrap();
        let store = MacOsProviderCredentialStore::with_test_item(service, account);
        let current = std::env::current_exe().unwrap();
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        std::fs::write(marker_dir.join("configured"), b"").unwrap();
    }
