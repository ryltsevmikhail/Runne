#![cfg(target_os = "linux")]

use std::{path::PathBuf, sync::Arc, time::SystemTime};

use runne_provider::{
    CredentialAuthorityPair, CredentialLease, CredentialNativeCreateValidator,
    CredentialVersionRef, ProviderId,
};
use runne_secure_store::{
    NativeKeyringStore, NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialMaterial, SecureStoreError,
};

struct ValidPrepared;

impl CredentialNativeCreateValidator for ValidPrepared {
    fn validate(&self) -> Result<(), runne_provider::CredentialLifecycleError> {
        Ok(())
    }
}

/// Exercises the production Secret Service + keyutils combo without the
/// broker writer, using a disposable immutable version and guaranteed GC.
#[test]
#[ignore = "requires a live, unlocked Linux Secret Service and keyutils session"]
fn native_secret_service_version_write_readback_and_cleanup() {
    assert_eq!(
        std::env::var_os("RUNNE_NATIVE_SECRET_SERVICE_DIAGNOSTIC").as_deref(),
        Some("1".as_ref())
    );

    let (lifecycle, native_authority) = CredentialAuthorityPair::new().split();
    let store = NativeKeyringStore::new_versioned(native_authority);
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock")
        .as_nanos() as u64;
    // The provider account is validated against the production allowlist;
    // nanosecond version makes this an isolated disposable item.
    let reference = CredentialVersionRef::new(
        ProviderId::new("openai").expect("provider id"),
        nonce.max(1),
    )
    .expect("version reference");
    let exe: PathBuf = std::env::current_exe().expect("test executable");
    let access = ProviderCredentialAccessPolicy::new(&exe, &exe).expect("measured test executable");
    let mut secret = format!("native-diagnostic-{nonce:x}").into_bytes();
    let material = ProviderCredentialMaterial::new(secret.clone()).expect("valid test material");
    secret.fill(0);
    let mut revision = [0_u8; 16];
    revision[8..].copy_from_slice(&nonce.to_be_bytes());
    let source = lifecycle
        .issue_provision_source(revision)
        .expect("source revision");
    let claim = lifecycle
        .native_create_issuer()
        .expect("create issuer")
        .issue_native_create(reference.clone(), &source, Arc::new(ValidPrepared))
        .expect("native create claim");

    let write_result = store.create_version(claim, &material, &access);
    let read_result = if write_result.is_ok() {
        let lease = CredentialLease::new(reference.clone(), [7; 16], i64::MAX, 1)
            .expect("valid dispatch lease");
        let capability = lifecycle.issue_dispatch(lease);
        store.load_version(&capability, &access).map(|loaded| {
            loaded.with_bytes(|bytes| bytes == format!("native-diagnostic-{nonce:x}").as_bytes())
        })
    } else {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    };
    let cleanup_result = store.delete_version(lifecycle.issue_gc(reference.clone()));
    let absence_result = store.version_status(&reference, &access);

    assert!(
        write_result.is_ok(),
        "native write failed: {write_result:?}"
    );
    assert_eq!(
        read_result.as_ref().ok(),
        Some(&true),
        "native exact readback failed: {read_result:?}"
    );
    assert!(
        cleanup_result.is_ok(),
        "native cleanup failed: {cleanup_result:?}"
    );
    assert_eq!(
        absence_result,
        Ok(runne_secure_store::ProviderCredentialStatus::Missing),
        "disposable item remains after cleanup"
    );
}
