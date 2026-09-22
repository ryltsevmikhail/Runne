//! REAL Linux provider-credential store source: routes the provider/version
//! keyring entries through the M1 DH-encrypted unique-name Secret Service
//! combo (SS authoritative + keyutils cache accelerator). NO Prompt/Unlock:
//! a locked collection, missing/invalid/lost owner, or unavailable bus is a
//! typed closed failure — never an automatic keyring fallback or unlock
//! prompt. Anchor/journal keys keep their existing platform path.

use std::sync::{Mutex, OnceLock};

use zeroize::Zeroizing;

use super::linux_secret_service::{
    ComboError, KernelKeyutilsCache, LibdbusSecretServiceBus, LinuxComboPersistentStore,
    ProcProcessFacts, SsFacadeError, SsVerifiedWrite,
};
use super::linux_secret_service::{EntryIdentity, derived_session_bus_address};
use crate::SecureStoreError;

const VERSION_SERVICE_PREFIX: &str = crate::PROVIDER_CREDENTIAL_SERVICE;

/// Object port over the combo so the static provider paths can reach a
/// lazily-created production source (or a test-injected fake).
pub trait LinuxProviderSourceOps: Send {
    fn read(&mut self, identity: &EntryIdentity) -> Result<Option<Zeroizing<Vec<u8>>>, ComboError>;
    fn write_ss_verified(
        &mut self,
        identity: &EntryIdentity,
        secret: &[u8],
    ) -> Result<SsVerifiedWrite, ComboError>;
    fn delete(&mut self, identity: &EntryIdentity) -> Result<(), ComboError>;
}

struct ProductionSource {
    combo:
        LinuxComboPersistentStore<LibdbusSecretServiceBus, ProcProcessFacts, KernelKeyutilsCache>,
}

impl LinuxProviderSourceOps for ProductionSource {
    fn read(&mut self, identity: &EntryIdentity) -> Result<Option<Zeroizing<Vec<u8>>>, ComboError> {
        self.combo.read_dispatch(identity)
    }

    fn write_ss_verified(
        &mut self,
        identity: &EntryIdentity,
        secret: &[u8],
    ) -> Result<SsVerifiedWrite, ComboError> {
        self.combo.write_persisted_ss_verified(identity, secret)
    }

    fn delete(&mut self, identity: &EntryIdentity) -> Result<(), ComboError> {
        self.combo.revoke_dual_half(identity)?;
        self.combo.invalidate_cache_half(identity)?;
        Ok(())
    }
}

static SOURCE: OnceLock<Mutex<SourceState>> = OnceLock::new();

enum SourceState {
    Uninitialized,
    Failed(&'static str),
    Ready(Box<dyn LinuxProviderSourceOps>),
}

fn with_source<T>(
    operation: impl FnOnce(&mut dyn LinuxProviderSourceOps) -> Result<T, SecureStoreError>,
) -> Result<T, SecureStoreError> {
    // A fresh explicit operation may re-attempt initialization: Failed is
    // not a permanent state (accepted recovery semantics), and there is no
    // owner fallback or automatic retry.
    let mut guard = source_lock_global();
    if matches!(*guard, SourceState::Uninitialized | SourceState::Failed(_)) {
        *guard = production_combo().map_or_else(
            |_| SourceState::Failed("provider Secret Service unavailable"),
            |combo| SourceState::Ready(Box::new(ProductionSource { combo })),
        );
    }
    match *guard {
        SourceState::Failed(reason) => Err(SecureStoreError::OperationFailed(reason.into())),
        SourceState::Ready(ref mut source) => operation(source.as_mut()),
        SourceState::Uninitialized => unreachable!("initialized above"),
    }
}

fn source_lock_global() -> std::sync::MutexGuard<'static, SourceState> {
    let global = SOURCE.get_or_init(|| Mutex::new(SourceState::Uninitialized));
    global
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn production_combo() -> Result<
    LinuxComboPersistentStore<LibdbusSecretServiceBus, ProcProcessFacts, KernelKeyutilsCache>,
    SsFacadeError,
> {
    let address = derived_session_bus_address();
    let bus = LibdbusSecretServiceBus::connect(&address).map_err(|_| SsFacadeError::Unavailable)?;
    let cache = KernelKeyutilsCache::attach().map_err(|_| SsFacadeError::Unavailable)?;
    LinuxComboPersistentStore::new(bus, ProcProcessFacts, cache)
}

/// True when the entry belongs to the provider-credential domain routed
/// through the combo (provider accounts + per-version references).
#[must_use]
pub(super) fn is_provider_entry(service: &str) -> bool {
    service == VERSION_SERVICE_PREFIX || service.starts_with(&format!("{VERSION_SERVICE_PREFIX}."))
}

pub(super) fn read_provider_entry(
    service: &str,
    account: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, SecureStoreError> {
    with_source(|source| {
        source
            .read(&EntryIdentity::new(service, account))
            .map_err(map_combo)
    })
}

pub(super) fn write_provider_entry(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), SecureStoreError> {
    with_source(|source| {
        source
            .write_ss_verified(&EntryIdentity::new(service, account), secret)
            .map(|SsVerifiedWrite::Verified| ())
            .map_err(map_combo)
    })
}

pub(super) fn delete_provider_entry(service: &str, account: &str) -> Result<(), SecureStoreError> {
    with_source(|source| {
        source
            .delete(&EntryIdentity::new(service, account))
            .map_err(map_combo)
    })
}

fn map_combo(error: ComboError) -> SecureStoreError {
    match error {
        ComboError::Ss(SsFacadeError::Locked) => SecureStoreError::CredentialAccessDenied,
        ComboError::Ss(SsFacadeError::OwnerLost | SsFacadeError::OwnerInvalid) => {
            SecureStoreError::CredentialAccessDenied
        }
        ComboError::Ss(_) => SecureStoreError::Unavailable,
        other => SecureStoreError::OperationFailed(other.description().into()),
    }
}

/// Scoped test-only install: swaps the global source to `fake` and restores
/// the previous state on drop, so concurrently running tests outside this
/// scope cannot observe fake contamination.
#[cfg(any(test, feature = "test-support"))]
pub struct ScopedTestSource {
    previous: SourceState,
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for ScopedTestSource {
    fn drop(&mut self) {
        let mut guard = source_lock();
        *guard = std::mem::replace(&mut self.previous, SourceState::Uninitialized);
    }
}

#[cfg(any(test, feature = "test-support"))]
fn source_lock() -> std::sync::MutexGuard<'static, SourceState> {
    let global = SOURCE.get_or_init(|| Mutex::new(SourceState::Uninitialized));
    global
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn install_test_source(fake: Box<dyn LinuxProviderSourceOps>) -> ScopedTestSource {
    let mut guard = source_lock();
    let previous = std::mem::replace(&mut *guard, SourceState::Ready(fake));
    drop(guard);
    ScopedTestSource { previous }
}

#[cfg(any(test, feature = "test-support"))]
pub use counting_fake::CountingFakeSource;

#[cfg(any(test, feature = "test-support"))]
mod counting_fake {
    use super::{
        ComboError, EntryIdentity, LinuxProviderSourceOps, SsFacadeError, SsVerifiedWrite,
        Zeroizing,
    };
    use std::sync::atomic::AtomicUsize;

    pub struct CountingFakeSource {
        pub locked: bool,
        pub entries: std::collections::BTreeMap<(String, String), Vec<u8>>,
        pub unlock_prompts: AtomicUsize,
        pub fail_delete_cache: bool,
    }

    impl LinuxProviderSourceOps for CountingFakeSource {
        fn read(
            &mut self,
            identity: &EntryIdentity,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, ComboError> {
            if self.locked {
                return Err(ComboError::Ss(SsFacadeError::Locked));
            }
            Ok(self
                .entries
                .get(&(identity.service.clone(), identity.account.clone()))
                .map(|bytes| Zeroizing::new(bytes.clone())))
        }

        fn write_ss_verified(
            &mut self,
            identity: &EntryIdentity,
            secret: &[u8],
        ) -> Result<SsVerifiedWrite, ComboError> {
            if self.locked {
                return Err(ComboError::Ss(SsFacadeError::Locked));
            }
            self.entries.insert(
                (identity.service.clone(), identity.account.clone()),
                secret.to_vec(),
            );
            Ok(SsVerifiedWrite::Verified)
        }

        fn delete(&mut self, identity: &EntryIdentity) -> Result<(), ComboError> {
            let key = (identity.service.clone(), identity.account.clone());
            self.entries.remove(&key);
            if self.fail_delete_cache {
                return Err(ComboError::RevokeIncomplete);
            }
            Ok(())
        }
    }

    impl CountingFakeSource {
        #[must_use]
        pub fn unlocked() -> Self {
            Self {
                locked: false,
                entries: std::collections::BTreeMap::default(),
                unlock_prompts: AtomicUsize::new(0),
                fail_delete_cache: false,
            }
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[path = "linux_directory_fake.rs"]
mod directory_fake;
#[cfg(any(test, feature = "test-support"))]
pub use directory_fake::DirectoryFakeSource;
