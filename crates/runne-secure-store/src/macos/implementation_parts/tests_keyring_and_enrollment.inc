    #[test]
    fn shared_keychain_window_disables_user_interaction() {
        let _keychain_locks = acquire_keychain_interaction_locks().unwrap();
        assert!(!SecKeychain::user_interaction_allowed().unwrap());
    }

    #[test]
    fn provider_journal_waits_for_provider_noninteractive_window() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let profile = format!("provider-journal-lock-{}-{unique}", std::process::id());
        let store = std::sync::Arc::new(MacOsKeychainStore::new(&profile));
        let key_ref = ProviderJournalKeyRef::new([31; 16], 1, [32; 16], 33).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _operation_lock = KEYCHAIN_INTERACTION_LOCK.lock().unwrap();
            let _interaction_lock = SecKeychain::disable_user_interaction().unwrap();
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        ready_rx.recv().unwrap();

        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            result_tx
                .send(store.provider_journal_key_status(key_ref))
                .unwrap();
        });
        let early = result_rx.recv_timeout(std::time::Duration::from_millis(100));
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert_eq!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout));
        assert_eq!(
            result_rx.recv().unwrap(),
            Ok(ProviderJournalKeyStatus::Missing)
        );
        worker.join().unwrap();
    }

    #[test]
    fn provider_journal_rotation_retains_versions_and_database_binding() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let profile = format!("provider-journal-rotation-{}-{unique}", std::process::id());
        let store = MacOsKeychainStore::new(&profile);
        let first_ref = ProviderJournalKeyRef::new([21; 16], 1, [22; 16], 23).unwrap();
        let second_ref = ProviderJournalKeyRef::new([21; 16], 2, [22; 16], 23).unwrap();
        let wrong_generation = ProviderJournalKeyRef::new([21; 16], 1, [22; 16], 24).unwrap();
        let first = ProviderJournalKeyMaterial::new(first_ref, [24; 32]).unwrap();
        let second = ProviderJournalKeyMaterial::new(second_ref, [25; 32]).unwrap();

        store.store_provider_journal_key(&first).unwrap();
        store.store_provider_journal_key(&second).unwrap();
        assert_eq!(
            store
                .load_provider_journal_key(first_ref)
                .unwrap()
                .with_bytes(|bytes| *bytes),
            [24; 32]
        );
        assert_eq!(
            store
                .load_provider_journal_key(second_ref)
                .unwrap()
                .with_bytes(|bytes| *bytes),
            [25; 32]
        );
        assert_eq!(
            store
                .load_provider_journal_key(wrong_generation)
                .unwrap_err(),
            SecureStoreError::ProviderJournalKeyNotFound
        );

        let proof = ProviderJournalKeyDeletionProof::for_verified_catalog(0, 0, [26; 32]).unwrap();
        store.delete_provider_journal_key(first_ref, proof).unwrap();
        store
            .delete_provider_journal_key(second_ref, proof)
            .unwrap();
    }

    #[test]
    fn provider_credential_keychain_roundtrip_has_exact_acl_and_idempotent_cleanup() {
        let (store, _cleanup) = unique_provider_store("roundtrip");
        let current = std::env::current_exe().expect("current test executable");
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let first = ProviderCredentialMaterial::new(b"native-test-first".to_vec()).unwrap();
        let replacement =
            ProviderCredentialMaterial::new(b"native-test-replacement".to_vec()).unwrap();

        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Missing
        );
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &first, &policy)
            .unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Configured
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &policy)
                .unwrap()
                .with_bytes(<[u8]>::to_vec),
            b"native-test-first"
        );
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &replacement, &policy)
            .unwrap();
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &policy)
                .unwrap()
                .with_bytes(<[u8]>::to_vec),
            b"native-test-replacement"
        );
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();
        assert_eq!(
            store
                .provider_credential_status(ProviderCredentialId::OpenAi, &policy)
                .unwrap(),
            ProviderCredentialStatus::Missing
        );
    }
    #[test]
    fn provider_credential_incomplete_enrollment_never_reports_configured_and_can_retry() {
        let (store, _cleanup) = unique_provider_store("incomplete-enrollment");
        let current = std::env::current_exe().expect("current test executable");
        let policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let exact = ExactKeychainAccess::new(&current, &current).unwrap();
        let metadata = ProviderCredentialMetadata::from_access(&policy, exact.digest());
        let credential =
            ProviderCredentialMaterial::new(b"native-test-enrollment-retry".to_vec()).unwrap();
        let encoded =
            StoredProviderCredential::encode(&credential, &policy, exact.digest()).unwrap();

        let failure = MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            create_populated_provider_item(
                keychain,
                &store.service,
                &store.account,
                &metadata,
                &exact,
                &encoded,
                Some(CredentialPopulationFailpoint::EmptyItemWritten),
            )
            .map(|_| ())
        });
        assert_eq!(
            failure,
            Err(SecureStoreError::CredentialEnrollmentIncomplete)
        );

        assert_eq!(
            store.provider_credential_status(ProviderCredentialId::OpenAi, &policy),
            Err(SecureStoreError::CredentialEnrollmentIncomplete)
        );
        let replacement_policy =
            ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        assert_eq!(
            store.migrate_provider_credential_access(
                ProviderCredentialId::OpenAi,
                &policy,
                &replacement_policy,
            ),
            Err(SecureStoreError::CredentialMigrationIncomplete)
        );
        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .expect("writer can replace a verified incomplete enrollment");
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &policy)
                .unwrap()
                .with_bytes(<[u8]>::to_vec),
            b"native-test-enrollment-retry"
        );
    }

    #[test]
    fn provider_credential_broad_preseed_never_receives_replacement_material() {
        let (store, _cleanup) = unique_provider_store("broad-preseed");
        let current = std::env::current_exe().expect("current test executable");
        let trusted_policy = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
        let broad_access = ExactKeychainAccess::new(&current, Path::new("/bin/echo")).unwrap();
        let metadata =
            ProviderCredentialMetadata::from_access(&trusted_policy, broad_access.digest())
                .encode();
        let sentinel = ProviderCredentialMaterial::new(b"native-test-sentinel".to_vec()).unwrap();
        let sentinel_encoded =
            StoredProviderCredential::encode(&sentinel, &trusted_policy, broad_access.digest())
                .unwrap();
        MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            let mut item = runne_macos_keychain_acl::create_empty_generic_password(
                keychain,
                &store.service,
                &store.account,
                &metadata,
                &broad_access,
            )
            .map_err(map_acl_error)?;
            item.item_mut()
                .set_password(&sentinel_encoded)
                .map_err(map_keychain_error)
        })
        .unwrap();

        assert_eq!(
            store.provider_credential_status(ProviderCredentialId::OpenAi, &trusted_policy),
            Err(SecureStoreError::CredentialAccessDenied)
        );
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &trusted_policy)
                .unwrap_err(),
            SecureStoreError::CredentialAccessDenied
        );

        let replacement =
            ProviderCredentialMaterial::new(b"native-test-must-not-be-written".to_vec()).unwrap();
        assert_eq!(
            store.store_provider_credential(
                ProviderCredentialId::OpenAi,
                &replacement,
                &trusted_policy,
            ),
            Err(SecureStoreError::CredentialAccessDenied)
        );
        let preserved = MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            let (encoded, _) = keychain
                .find_generic_password(&store.service, &store.account)
                .map_err(map_keychain_error)?;
            StoredProviderCredential::decode(&encoded)
        })
        .unwrap();
        assert_eq!(
            preserved.into_material().with_bytes(<[u8]>::to_vec),
            b"native-test-sentinel"
        );
    }

    #[test]
    fn provider_credential_rejects_writer_read_and_replaced_reader_without_prompt() {
        let (store, _cleanup) = unique_provider_store("negative-reader");
        let current = std::env::current_exe().expect("current test executable");
        let policy = ProviderCredentialAccessPolicy::new(&current, Path::new("/bin/echo")).unwrap();
        let credential = ProviderCredentialMaterial::new(b"native-test-negative".to_vec()).unwrap();
        let _exact = ExactKeychainAccess::new(&current, Path::new("/bin/echo")).unwrap();

        store
            .store_provider_credential(ProviderCredentialId::OpenAi, &credential, &policy)
            .unwrap();
        assert_eq!(
            store
                .load_provider_credential(ProviderCredentialId::OpenAi, &policy)
                .unwrap_err(),
            SecureStoreError::CredentialAccessDenied
        );
        store
            .delete_provider_credential(ProviderCredentialId::OpenAi)
            .unwrap();

        let reader = ExecutableCopy::new(&current, "reader-replacement");
        let stale_policy = ProviderCredentialAccessPolicy::new(&current, &reader.0).unwrap();
        reader.replace_with(Path::new("/bin/echo"));
        assert_eq!(
            store.store_provider_credential(
                ProviderCredentialId::OpenAi,
                &credential,
                &stale_policy,
            ),
            Err(SecureStoreError::CredentialAccessDenied)
        );
    }
