    #[test]
    fn provider_credential_delete_is_monotonic_after_every_migration_failpoint() {
        for failpoint in [
            CredentialMigrationFailpoint::BackupEmptyWritten,
            CredentialMigrationFailpoint::BackupWritten,
            CredentialMigrationFailpoint::PrimaryDeleted,
            CredentialMigrationFailpoint::ReplacementEmptyWritten,
            CredentialMigrationFailpoint::ReplacementWritten,
        ] {
            let (store, _cleanup) = unique_provider_store(match failpoint {
                CredentialMigrationFailpoint::BackupEmptyWritten => "delete-after-empty-backup",
                CredentialMigrationFailpoint::BackupWritten => "delete-after-backup",
                CredentialMigrationFailpoint::PrimaryDeleted => "delete-after-primary",
                CredentialMigrationFailpoint::ReplacementEmptyWritten => {
                    "delete-after-empty-replacement"
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
                    .unwrap_err(),
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
            .env("GOCODE_PROVIDER_STATUS_SERVICE", &store.service)
            .env("GOCODE_PROVIDER_STATUS_ACCOUNT", &store.account)
            .env("GOCODE_PROVIDER_STATUS_WRITER", &current)
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
            std::env::var_os("GOCODE_PROVIDER_STATUS_SERVICE"),
            std::env::var_os("GOCODE_PROVIDER_STATUS_ACCOUNT"),
            std::env::var_os("GOCODE_PROVIDER_STATUS_WRITER"),
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
            "gocode-provider-lock-child-tmp-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&child_temp).unwrap();
        // Keep sibling tests from winning the user-wide lock after the parent
        // releases it but before the child can acquire it. The child has its
        // own process-local mutex, so this serializes only this test binary.
        let _operation_lock = PROVIDER_CREDENTIAL_KEYCHAIN_LOCK.lock().unwrap();
        let process_lock = ProviderCredentialProcessLock::acquire().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macos::tests::provider_credential_process_lock_child",
                "--nocapture",
            ])
            .env("GOCODE_PROVIDER_LOCK_TEST_CHILD", "1")
            .env("GOCODE_PROVIDER_LOCK_SERVICE", &store.service)
            .env("GOCODE_PROVIDER_LOCK_ACCOUNT", &store.account)
            .env("TMPDIR", &child_temp)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn lock contender");
        let mut child_stdout = BufReader::new(child.stdout.take().unwrap());
        read_child_marker(&mut child_stdout, "READY").unwrap();
        child.stdin.as_mut().unwrap().write_all(b"GO\n").unwrap();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = read_child_marker(&mut child_stdout, "CONFIGURED");
            let _ = acquired_tx.send((result, child_stdout));
        });
        assert!(
            acquired_rx
                .recv_timeout(std::time::Duration::from_millis(500))
                .is_err(),
            "child with a different TMPDIR bypassed the process lock"
        );
        drop(process_lock);
        let (operation, _child_stdout) = acquired_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        operation.unwrap();
        assert!(child.wait().unwrap().success());
        std::fs::remove_dir(child_temp).unwrap();
    }

    #[test]
    fn provider_credential_process_lock_child() {
        if std::env::var_os("GOCODE_PROVIDER_LOCK_TEST_CHILD").is_none() {
            return;
        }
        println!("READY");
        std::io::stdout().flush().unwrap();
        let mut go = String::new();
        std::io::stdin().read_line(&mut go).unwrap();
        assert_eq!(go, "GO\n");
        let service = std::env::var("GOCODE_PROVIDER_LOCK_SERVICE").unwrap();
        let account = std::env::var("GOCODE_PROVIDER_LOCK_ACCOUNT").unwrap();
        let store = MacOsProviderCredentialStore::with_test_item(service, account);
        let current = std::env::current_exe().unwrap();
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        println!("CONFIGURED");
        std::io::stdout().flush().unwrap();
    }
