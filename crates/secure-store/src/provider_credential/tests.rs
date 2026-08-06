use super::*;

struct ExecutableCopy(PathBuf);
impl Drop for ExecutableCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn enrolled_reader_mismatch_is_a_closed_access_denial() {
    let current = std::env::current_exe().expect("current test executable");
    let reader = ExecutableCopy(unique_executable_copy(&current, "reader-mismatch"));
    let policy = ProviderCredentialAccessPolicy::new(&current, &reader.0).unwrap();
    let material = ProviderCredentialMaterial::new(b"test-only-marker".to_vec()).unwrap();
    let encoded = StoredProviderCredential::encode(&material, &policy, [7; 32]).unwrap();
    let stored = StoredProviderCredential::decode(&encoded).unwrap();
    assert_eq!(
        stored.validate_reader_current(),
        Err(SecureStoreError::CredentialAccessDenied)
    );
}

fn unique_executable_copy(source: &Path, label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "gocode-secure-store-{label}-{}-{unique}",
        std::process::id()
    ));
    std::fs::copy(source, &path).expect("copy executable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
            .expect("restrict copied executable");
    }
    path
}

#[test]
fn complete_metadata_preserves_v1_upgrade_and_rollback_layout() {
    let current = std::env::current_exe().unwrap();
    let access = ProviderCredentialAccessPolicy::new(&current, &current).unwrap();
    let metadata = ProviderCredentialMetadata::from_access(&access, [7; 32]);
    let encoded = metadata.encode();
    assert_eq!(encoded.len(), 184);
    assert_eq!(&encoded[..8], b"GCPMDV1\0");
    assert!(
        ProviderCredentialMetadata::decode(&encoded)
            .unwrap()
            .is_complete()
    );
    assert_ne!(&metadata.encode_incomplete()[..8], b"GCPMDV1\0");
}
