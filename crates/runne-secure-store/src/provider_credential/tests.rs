use super::*;

struct ExecutableCopy(PathBuf);
impl Drop for ExecutableCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct CurrentExecutablePermissions {
    path: PathBuf,
    _lock: std::sync::MutexGuard<'static, ()>,
    #[cfg(unix)]
    original_mode: u32,
}

impl Drop for CurrentExecutablePermissions {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(
                &self.path,
                std::fs::Permissions::from_mode(self.original_mode),
            );
        }
    }
}

fn private_current_executable() -> CurrentExecutablePermissions {
    let lock = EXECUTABLE_TEST_LOCK.lock().expect("executable test lock");
    let path = std::env::current_exe().expect("current test executable");
    #[cfg(unix)]
    let original_mode = {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("current executable metadata")
            .permissions()
            .mode();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))
            .expect("restrict current executable");
        mode
    };
    CurrentExecutablePermissions {
        path,
        _lock: lock,
        #[cfg(unix)]
        original_mode,
    }
}

#[test]
fn enrolled_reader_mismatch_is_a_closed_access_denial() {
    let current = private_current_executable();
    let reader = ExecutableCopy(unique_executable_copy(&current.path, "reader-mismatch"));
    let policy = ProviderCredentialAccessPolicy::new(&current.path, &reader.0).unwrap();
    let material = ProviderCredentialMaterial::new(b"test-only-marker".to_vec()).unwrap();
    let encoded = StoredProviderCredential::encode(&material, &policy, [7; 32]).unwrap();
    let stored = StoredProviderCredential::decode(&encoded).unwrap();
    assert_eq!(
        stored.validate_reader_current(),
        Err(SecureStoreError::CredentialAccessDenied)
    );
    drop(current);
}

fn unique_executable_copy(source: &Path, label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "runne-secure-store-{label}-{}-{unique}",
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
    let current = private_current_executable();
    let access = ProviderCredentialAccessPolicy::new(&current.path, &current.path).unwrap();
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
    drop(current);
}

#[test]
fn source_revision_v2_roundtrips_and_v1_is_unavailable() {
    let current = private_current_executable();
    let access = ProviderCredentialAccessPolicy::new(&current.path, &current.path).unwrap();
    let material = ProviderCredentialMaterial::new(b"source-revision-fixture".to_vec()).unwrap();
    let revision = ProviderCredentialSourceRevision::new([0x91; 16]).unwrap();
    let metadata = ProviderCredentialMetadata::from_access_revision(&access, [7; 32], revision);
    let encoded =
        StoredProviderCredential::encode_with_revision(&material, &access, [7; 32], revision)
            .unwrap();
    let decoded_metadata = ProviderCredentialMetadata::decode(&metadata.encode()).unwrap();
    let stored = StoredProviderCredential::decode(&encoded).unwrap();
    assert!(decoded_metadata.validate_writer_current().is_ok());
    assert!(decoded_metadata.access_matches(&access));
    assert_eq!(decoded_metadata.acl_set_digest(), [7; 32]);
    assert_eq!(decoded_metadata.source_revision(), Some(revision));
    assert!(stored.access_matches(&access));
    assert_eq!(stored.acl_set_digest(), [7; 32]);
    assert!(stored.metadata_matches(&decoded_metadata));
    let source = stored.into_source().unwrap();
    assert_eq!(source.revision(), revision);
    assert_eq!(
        source.material().with_bytes(<[u8]>::to_vec),
        b"source-revision-fixture"
    );
    assert_eq!(
        StoredProviderCredential::decode(&encoded)
            .unwrap()
            .into_material()
            .with_bytes(<[u8]>::to_vec),
        b"source-revision-fixture"
    );

    let legacy = StoredProviderCredential::encode(&material, &access, [7; 32]).unwrap();
    assert_eq!(
        StoredProviderCredential::decode(&legacy)
            .unwrap()
            .into_source()
            .unwrap_err(),
        SecureStoreError::ProviderCredentialSourceRevisionUnavailable
    );
    drop(current);
}

#[test]
fn native_oauth_codec_has_separate_32k_bound_and_magic() {
    let current = private_current_executable();
    let access = ProviderCredentialAccessPolicy::new(&current.path, &current.path).unwrap();
    let material = ProviderCredentialMaterial::new_native_oauth(vec![b'o'; 32 * 1024]).unwrap();
    assert_eq!(material.kind(), ProviderCredentialMaterialKind::NativeOAuth);
    let revision = ProviderCredentialSourceRevision::new([0x92; 16]).unwrap();
    let encoded =
        StoredProviderCredential::encode_with_revision(&material, &access, [8; 32], revision)
            .unwrap();
    assert_eq!(&encoded[..8], b"GCPOV1\0\0");
    let decoded = StoredProviderCredential::decode(&encoded).unwrap();
    assert_eq!(
        decoded.material.kind(),
        ProviderCredentialMaterialKind::NativeOAuth
    );
    assert_eq!(decoded.into_material().with_bytes(<[u8]>::len), 32 * 1024);
    assert!(ProviderCredentialMaterial::new(vec![b'l'; 4097]).is_err());
    drop(current);
}
