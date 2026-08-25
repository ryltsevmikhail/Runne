use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::SecureStoreError;
use crate::provider_credential::{
    EXECUTABLE_TEST_LOCK, ProviderCredentialAccessPolicy, ProviderCredentialMaterial,
    StoredProviderCredential,
};

use super::provider_delete::delete_provider_record_with;

const DOMAIN: &[u8] = b"runne/keyring-provider-access/v1\0";

#[test]
#[allow(clippy::significant_drop_tightening)]
fn delete_guard_preserves_sentinel_for_every_policy_mismatch() {
    let current = private_current_executable();
    let temporary = tempfile::tempdir().expect("temporary directory");
    let other_reader = executable_copy(&current.path, temporary.path().join("other-reader"));
    let other_writer = executable_copy(&current.path, temporary.path().join("other-writer"));
    let enrolled = ProviderCredentialAccessPolicy::new(&current.path, &current.path).unwrap();
    let other_reader = ProviderCredentialAccessPolicy::new(&current.path, &other_reader).unwrap();
    let unrelated_writer =
        ProviderCredentialAccessPolicy::new(&other_writer, &current.path).unwrap();
    assert_preserved(&enrolled, &unrelated_writer);
    assert_preserved(&enrolled, &other_reader);
}

#[test]
#[allow(clippy::significant_drop_tightening)]
fn delete_guard_preserves_sentinel_when_reader_remeasurement_fails() {
    let current = private_current_executable();
    let temporary = tempfile::tempdir().expect("temporary directory");
    let reader = temporary.path().join("reader");
    std::fs::copy(&current.path, &reader).expect("copy reader");
    restrict_executable(&reader);
    let stale = ProviderCredentialAccessPolicy::new(&current.path, &reader).unwrap();
    let encoded = encoded_sentinel(&stale);
    make_writable(&reader);
    let mut replacement = std::fs::read(&current.path).expect("read replacement reader");
    replacement[0] ^= 1;
    std::fs::write(&reader, replacement).expect("replace reader");
    restrict_executable(&reader);
    let deletes = AtomicUsize::new(0);

    let result = delete_provider_record_with(
        &stale,
        || Ok(Some(Zeroizing::new(encoded.clone()))),
        || {
            deletes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert!(matches!(
        result,
        Err(SecureStoreError::CredentialIdentityMismatch | SecureStoreError::CredentialAccessDenied)
    ));
    assert_eq!(deletes.load(Ordering::SeqCst), 0);
}

fn assert_preserved(
    enrolled: &ProviderCredentialAccessPolicy,
    attempted: &ProviderCredentialAccessPolicy,
) {
    let encoded = encoded_sentinel(enrolled);
    let deletes = AtomicUsize::new(0);
    let result = delete_provider_record_with(
        attempted,
        || Ok(Some(Zeroizing::new(encoded.clone()))),
        || {
            deletes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(deletes.load(Ordering::SeqCst), 0);
}

fn encoded_sentinel(access: &ProviderCredentialAccessPolicy) -> Vec<u8> {
    let material = ProviderCredentialMaterial::new(b"sentinel-must-survive".to_vec()).unwrap();
    StoredProviderCredential::encode(&material, access, access_digest(access))
        .unwrap()
        .to_vec()
}

fn access_digest(access: &ProviderCredentialAccessPolicy) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    for identity in [access.writer_identity(), access.reader_identity()] {
        digest.update(identity.executable_sha256());
        digest.update(identity.canonical_path_sha256());
        digest.update(identity.byte_length().to_be_bytes());
    }
    digest.finalize().into()
}

fn restrict_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
}

fn make_writable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn executable_copy(source: &Path, destination: std::path::PathBuf) -> std::path::PathBuf {
    std::fs::copy(source, &destination).expect("copy executable");
    restrict_executable(&destination);
    destination
}

struct CurrentExecutablePermissions {
    path: std::path::PathBuf,
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
    let path = std::env::current_exe().expect("current executable");
    #[cfg(unix)]
    let original_mode = {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        mode
    };
    CurrentExecutablePermissions {
        path,
        _lock: lock,
        #[cfg(unix)]
        original_mode,
    }
}
