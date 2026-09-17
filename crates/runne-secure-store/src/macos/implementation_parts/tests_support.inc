    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    struct ProviderCredentialCleanup {
        service: String,
        account: String,
    }

    impl Drop for ProviderCredentialCleanup {
        fn drop(&mut self) {
            let _keychain_locks = acquire_keychain_interaction_locks()
                .expect("provider credential test cleanup lock");
            let cleanup = [
                format!("{}{PROVIDER_CREDENTIAL_MIGRATION_SUFFIX}", self.service),
                format!(
                    "{}{PROVIDER_CREDENTIAL_SOURCE_ALTERNATE_SUFFIX}",
                    self.service
                ),
                self.service.clone(),
            ]
            .into_iter()
            .try_for_each(|service| {
                let keychain = active_keychain().map_err(|()| "open test Keychain".to_owned())?;
                match keychain.find_generic_password(&service, &self.account) {
                    Ok((_, item)) => runne_macos_keychain_acl::delete_item(&item)
                        .map_err(|error| format!("delete {service}: {error:?}"))?,
                    Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => {}
                    Err(error) => return Err(format!("delete {service}: {error}")),
                }
                match keychain.find_generic_password(&service, &self.account) {
                    Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
                    Ok(_) => Err(format!("cleanup left {service}")),
                    Err(error) => Err(format!("verify {service}: {error}")),
                }
            });
            if !std::thread::panicking() {
                cleanup.expect("provider credential test cleanup and postcondition");
            }
        }
    }

    struct ExecutableCopy(PathBuf);

    impl ExecutableCopy {
        fn new(source: &Path, label: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "runne-keychain-acl-{label}-{}-{unique}",
                std::process::id()
            ));
            std::fs::copy(source, &path).expect("copy executable");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
                .expect("restrict executable copy");
            Self(path)
        }

        fn replace_with(&self, source: &Path) {
            std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700))
                .expect("make executable copy replaceable");
            std::fs::copy(source, &self.0).expect("replace executable copy");
            std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o500))
                .expect("restrict replaced executable copy");
        }

        fn resign_with_distinct_identity(&self) {
            std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700))
                .expect("make executable copy resignable");
            let output = std::process::Command::new("/usr/bin/codesign")
                .args([
                    "--force",
                    "--sign",
                    "-",
                    "--identifier",
                    "dev.runne.untrusted-keychain-test",
                ])
                .arg(&self.0)
                .output()
                .expect("launch ad-hoc codesign");
            assert!(
                output.status.success(),
                "ad-hoc codesign failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o500))
                .expect("restrict re-signed executable copy");
        }
    }

    impl Drop for ExecutableCopy {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn unique_provider_store(
        label: &str,
    ) -> (MacOsProviderCredentialStore, ProviderCredentialCleanup) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let service = format!(
            "{}.test.{label}.{}.{}",
            crate::PROVIDER_CREDENTIAL_SERVICE,
            std::process::id(),
            unique
        );
        let account = format!("openai-test-{unique}");
        let cleanup = ProviderCredentialCleanup {
            service: service.clone(),
            account: account.clone(),
        };
        (
            MacOsProviderCredentialStore::with_test_item(service, account),
            cleanup,
        )
    }

    fn wait_for_marker_file(path: &Path, timeout: std::time::Duration) -> std::io::Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if path.exists() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("timed out waiting for {}", path.display()),
        ))
    }

    fn seed_incomplete_provider_item(
        store: &MacOsProviderCredentialStore,
        service: &str,
        policy: &ProviderCredentialAccessPolicy,
    ) {
        let exact = ExactKeychainAccess::new(policy.writer_path(), policy.reader_path()).unwrap();
        let metadata =
            ProviderCredentialMetadata::from_access(policy, exact.digest()).encode_incomplete();
        MacOsProviderCredentialStore::with_noninteractive(|keychain| {
            runne_macos_keychain_acl::create_empty_generic_password(
                keychain,
                service,
                &store.account,
                &metadata,
                &exact,
            )
            .map(|_| ())
            .map_err(map_acl_error)
        })
        .unwrap();
    }

    #[test]
    fn profiles_use_distinct_keychain_accounts() {
        let first = MacOsKeychainStore::new("profile-a");
        let second = MacOsKeychainStore::new("profile-b");

        assert_ne!(first.account_name, second.account_name);
    }

    #[test]
    fn rejects_malformed_anchor_bytes() {
        let error = decode_anchor(&[1, 2, 3]).expect_err("malformed anchor");

        assert!(matches!(error, SecureStoreError::CorruptAnchor));
    }

    #[test]
    fn provider_journal_key_codec_rejects_changed_binding_and_corruption() {
        let key_ref = ProviderJournalKeyRef::new([1; 16], 2, [3; 16], 4).unwrap();
        let key = ProviderJournalKeyMaterial::new(key_ref, [5; 32]).unwrap();
        let encoded = encode_provider_journal_key(&key);

        assert_eq!(
            decode_provider_journal_key(
                &encoded,
                ProviderJournalKeyRef::new([1; 16], 2, [3; 16], 5).unwrap(),
            )
            .unwrap_err(),
            SecureStoreError::CorruptProviderJournalKey
        );
        let mut corrupt = encoded;
        corrupt[0] ^= 1;
        assert_eq!(
            decode_provider_journal_key(&corrupt, key_ref).unwrap_err(),
            SecureStoreError::CorruptProviderJournalKey
        );
    }
    #[test]
    fn store_read_delete_roundtrip() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let profile = format!("test-{}-{unique}", std::process::id());
        let store = MacOsKeychainStore::new(&profile);
        // Clean up any leftover from previous runs
        let _ = store.delete_anchor();

        assert_eq!(store.read_anchor().unwrap(), None);

        store.store_anchor(42).unwrap();
        assert_eq!(store.read_anchor().unwrap(), Some(42));

        store.store_anchor(99).unwrap();
        assert_eq!(store.read_anchor().unwrap(), Some(99));

        store.delete_anchor().unwrap();
        assert_eq!(store.read_anchor().unwrap(), None);
    }

    #[test]
    fn provider_journal_key_roundtrip_rejects_conflicting_overwrite() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let profile = format!("provider-journal-test-{}-{unique}", std::process::id());
        let store = MacOsKeychainStore::new(&profile);
        let key_ref = ProviderJournalKeyRef::new([11; 16], 1, [12; 16], 13).unwrap();
        let wrong_ref = ProviderJournalKeyRef::new([11; 16], 1, [12; 16], 14).unwrap();
        let key = ProviderJournalKeyMaterial::new(key_ref, [14; 32]).unwrap();

        assert_eq!(
            store.provider_journal_key_status(key_ref).unwrap(),
            ProviderJournalKeyStatus::Missing
        );
        store.store_provider_journal_key(&key).unwrap();
        assert_eq!(
            store.provider_journal_key_status(key_ref).unwrap(),
            ProviderJournalKeyStatus::Available
        );
        assert_eq!(
            store.provider_journal_key_status(wrong_ref).unwrap(),
            ProviderJournalKeyStatus::Missing
        );
        let loaded = store.load_provider_journal_key(key_ref).unwrap();
        assert_eq!(loaded.with_bytes(|bytes| *bytes), [14; 32]);
        let conflict = ProviderJournalKeyMaterial::new(key_ref, [15; 32]).unwrap();
        assert_eq!(
            store.store_provider_journal_key(&conflict),
            Err(SecureStoreError::CorruptProviderJournalKey)
        );
        assert_eq!(
            store
                .load_provider_journal_key(key_ref)
                .unwrap()
                .with_bytes(|bytes| *bytes),
            [14; 32]
        );

        store
            .delete_provider_journal_key(
                key_ref,
                ProviderJournalKeyDeletionProof::for_verified_catalog(0, 0, [16; 32]).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store.provider_journal_key_status(key_ref).unwrap(),
            ProviderJournalKeyStatus::Missing
        );
        assert_eq!(
            store.load_provider_journal_key(key_ref).unwrap_err(),
            SecureStoreError::ProviderJournalKeyNotFound
        );
    }

    /// True when the running darwin kernel is 27+; macOS 27 splits a saved
    /// Keychain item's partition ACL record on save (macOS 27 storage backlog).
    fn macos_27_partition_limitation() -> bool {
        let Ok(output) = std::process::Command::new("uname").arg("-r").output() else {
            return false;
        };
        let release = String::from_utf8_lossy(&output.stdout);
        let Some(major) = release.split('.').next().and_then(|p| p.trim().parse::<u32>().ok())
        else {
            return false;
        };
        output.status.success() && major >= 27
    }

    /// Prints the documented skip reason; affected tests early-return so macOS 14 CI keeps running the full suite.
    fn skip_if_partition_limitation(test: &str) -> bool {
        if !macos_27_partition_limitation() {
            return false;
        }
        let reason = format!("skipped: {test}: macOS 27 splits saved partition ACL records; partition-protected cross-process credential storage is unavailable by construction until the storage redesign (backlog: macOS 27 credential storage)\n");
        // libtest captures `eprintln!` of passing tests; append to /dev/stderr so the reason stays visible.
        let written = std::fs::OpenOptions::new().append(true).open("/dev/stderr").and_then(|mut stderr| stderr.write_all(reason.as_bytes()));
        if written.is_err() { eprintln!("{reason}"); }
        true
    }
