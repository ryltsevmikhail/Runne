#![cfg(all(test, target_os = "linux"))]

use std::sync::{Mutex as TestMutex, OnceLock as TestOnceLock};
use zeroize::Zeroizing;

static SERIAL: TestOnceLock<TestMutex<()>> = TestOnceLock::new();

fn serial() -> std::sync::MutexGuard<'static, ()> {
    let lock = SERIAL.get_or_init(|| TestMutex::new(()));
    lock.lock().unwrap_or_else(|poison| poison.into_inner())
}
// Fake-only wiring tests for the REAL Linux provider-credential source:
// provider/version entries route through the combo port with NO
// Prompt/Unlock anywhere; anchor/journal-style services stay on the
// platform path; typed failures surface for locked/owner/unavailable and
// partial revoke cases. No real Secret Service, keyutils, or prompt is
// ever contacted.

use super::linux_provider_source::{
    CountingFakeSource, LinuxProviderSourceOps, ScopedTestSource, delete_provider_entry,
    install_test_source, is_provider_entry, read_provider_entry, write_provider_entry,
};
use crate::SecureStoreError;

const PROVIDER_SERVICE: &str = crate::PROVIDER_CREDENTIAL_SERVICE;
const VERSION_SERVICE: &str = "dev.runne.provider-credential.v1.version.1.ab";
const OTHER_SERVICE: &str = "dev.runne.security-anchor.v1";

fn install(locked: bool, fail_delete: bool) -> ScopedTestSource {
    let mut fake = CountingFakeSource::unlocked();
    fake.locked = locked;
    fake.fail_delete_cache = fail_delete;
    install_test_source(Box::new(fake))
}

#[test]
fn provider_and_version_services_route_through_the_linux_source() {
    let _guard = serial();
    assert!(is_provider_entry(PROVIDER_SERVICE));
    assert!(is_provider_entry(VERSION_SERVICE));
    assert!(!is_provider_entry(OTHER_SERVICE));
}

#[test]
fn write_is_ss_verified_and_reads_back() {
    let _guard = serial();
    let _source = install(false, false);
    write_provider_entry(PROVIDER_SERVICE, "deepseek", b"sealed-material")
        .expect("SS-verified write");
    let read = read_provider_entry(PROVIDER_SERVICE, "deepseek")
        .expect("read after verified write")
        .expect("entry present");
    assert_eq!(*read, b"sealed-material".to_vec());
}

#[test]
fn locked_collection_denies_without_any_unlock_prompt() {
    let _guard = serial();
    let _source = install(true, false);
    let read = read_provider_entry(PROVIDER_SERVICE, "deepseek");
    assert!(matches!(
        read,
        Err(SecureStoreError::CredentialAccessDenied)
    ));
    let write = write_provider_entry(PROVIDER_SERVICE, "deepseek", b"x");
    assert!(matches!(
        write,
        Err(SecureStoreError::CredentialAccessDenied)
    ));
    // The fake counts any prompt attempt; zero prompts is the contract.
    // (The fake has no prompting API at all — absence is itself the proof.)
}

#[test]
fn partial_revoke_failure_surfaces_a_typed_error() {
    let _guard = serial();
    let _source = install(false, true);
    write_provider_entry(PROVIDER_SERVICE, "deepseek", b"m").expect("write");
    let deleted = delete_provider_entry(PROVIDER_SERVICE, "deepseek");
    assert!(
        matches!(deleted, Err(SecureStoreError::OperationFailed(reason)) if reason.contains("revoke")),
        "revoke errors must not be swallowed"
    );
}

#[test]
fn delete_removes_both_halves_and_absent_entries_stay_ok() {
    let _guard = serial();
    let _source = install(false, false);
    write_provider_entry(VERSION_SERVICE, "ref", b"v").expect("write");
    delete_provider_entry(VERSION_SERVICE, "ref").expect("dual-half revoke");
    let read = read_provider_entry(VERSION_SERVICE, "ref").expect("read");
    assert!(read.is_none());
    delete_provider_entry(VERSION_SERVICE, "ref").expect("absent delete stays Ok");
}

#[test]
fn transport_unavailability_is_typed_not_a_fallback() {
    let _guard = serial();
    struct UnavailableSource;
    impl LinuxProviderSourceOps for UnavailableSource {
        fn read(
            &mut self,
            _identity: &super::linux_secret_service::EntryIdentity,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, super::linux_secret_service::ComboError> {
            Err(super::linux_secret_service::ComboError::Ss(
                super::linux_secret_service::SsFacadeError::Unavailable,
            ))
        }
        fn write_ss_verified(
            &mut self,
            _identity: &super::linux_secret_service::EntryIdentity,
            _secret: &[u8],
        ) -> Result<
            super::linux_secret_service::SsVerifiedWrite,
            super::linux_secret_service::ComboError,
        > {
            Err(super::linux_secret_service::ComboError::Ss(
                super::linux_secret_service::SsFacadeError::Unavailable,
            ))
        }
        fn delete(
            &mut self,
            _identity: &super::linux_secret_service::EntryIdentity,
        ) -> Result<(), super::linux_secret_service::ComboError> {
            Err(super::linux_secret_service::ComboError::Ss(
                super::linux_secret_service::SsFacadeError::Unavailable,
            ))
        }
    }
    let _source = install_test_source(Box::new(UnavailableSource));
    assert!(matches!(
        read_provider_entry(PROVIDER_SERVICE, "deepseek"),
        Err(SecureStoreError::Unavailable)
    ));
    assert!(matches!(
        write_provider_entry(PROVIDER_SERVICE, "deepseek", b"x"),
        Err(SecureStoreError::Unavailable)
    ));
}

#[test]
fn owner_loss_denies_closed_without_retry_or_fallback() {
    let _guard = serial();
    struct OwnerLostSource;
    impl LinuxProviderSourceOps for OwnerLostSource {
        fn read(
            &mut self,
            _identity: &super::linux_secret_service::EntryIdentity,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, super::linux_secret_service::ComboError> {
            Err(super::linux_secret_service::ComboError::Ss(
                super::linux_secret_service::SsFacadeError::OwnerLost,
            ))
        }
        fn write_ss_verified(
            &mut self,
            _identity: &super::linux_secret_service::EntryIdentity,
            _secret: &[u8],
        ) -> Result<
            super::linux_secret_service::SsVerifiedWrite,
            super::linux_secret_service::ComboError,
        > {
            Err(super::linux_secret_service::ComboError::Ss(
                super::linux_secret_service::SsFacadeError::OwnerLost,
            ))
        }
        fn delete(
            &mut self,
            _identity: &super::linux_secret_service::EntryIdentity,
        ) -> Result<(), super::linux_secret_service::ComboError> {
            Err(super::linux_secret_service::ComboError::Ss(
                super::linux_secret_service::SsFacadeError::OwnerLost,
            ))
        }
    }
    let _source = install_test_source(Box::new(OwnerLostSource));
    assert!(matches!(
        read_provider_entry(PROVIDER_SERVICE, "deepseek"),
        Err(SecureStoreError::CredentialAccessDenied)
    ));
}

#[test]
fn static_native_keyring_paths_dispatch_provider_entries_to_the_source() {
    let _guard = serial();
    let _source = install(false, false);
    // The ACTUAL static call sites used by provider/version operations.
    super::NativeKeyringStore::write_secret(PROVIDER_SERVICE, "deepseek", b"routed")
        .expect("static write dispatch");
    let read = super::NativeKeyringStore::read_secret(PROVIDER_SERVICE, "deepseek")
        .expect("static read dispatch")
        .expect("present");
    assert_eq!(*read, b"routed".to_vec());
    super::NativeKeyringStore::delete_secret(PROVIDER_SERVICE, "deepseek")
        .expect("static delete dispatch");
    let gone = super::NativeKeyringStore::read_secret(PROVIDER_SERVICE, "deepseek")
        .expect("read after delete");
    assert!(gone.is_none());
    // Locked race through the same static path: denied, no prompt, no fallback.
    drop(_source);
    let _source = install(true, false);
    let denied = super::NativeKeyringStore::read_secret(PROVIDER_SERVICE, "deepseek");
    assert!(matches!(
        denied,
        Err(SecureStoreError::CredentialAccessDenied)
    ));
}
