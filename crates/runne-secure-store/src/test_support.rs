use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use sha2::{Digest, Sha256};

use crate::{
    SealedTransactionTag, SecureStore, SecureStoreError, SecurityAnchorV1, SecurityProfileLock,
    StoredSecurityAnchor,
};

mod test_support_lock;
use test_support_lock::TestLock;

mod provider_credential;
pub use provider_credential::prove_current_reader_can_load_exact;

#[cfg(target_os = "linux")]
mod persistent_test_secure_store;
#[cfg(target_os = "linux")]
pub use persistent_test_secure_store::PersistentDeterministicSecureStore;

/// Returns true only for the exact disposable real-writer released-edge case.
#[must_use]
pub fn local_writer_death_after_release_enabled() -> bool {
    runne_api::test_support::local_native_enrollment_case()
        == Some(runne_api::test_support::LocalNativeEnrollmentCase::DeathReleased)
}

/// Deterministic test double only; it is not an OS-backed production secure store.
pub struct DeterministicSecureStore {
    profile_identity_digest: [u8; 32],
    anchor: Mutex<StoredSecurityAnchor>,
    profile_lock: Mutex<()>,
    fail_advance: Mutex<bool>,
    fail_read_after: Mutex<Option<usize>>,
    fail_legacy_migration: Mutex<bool>,
    payload_encryption_enabled: AtomicBool,
}

impl DeterministicSecureStore {
    #[must_use]
    pub const fn new(profile_identity_digest: [u8; 32]) -> Self {
        Self {
            profile_identity_digest,
            anchor: Mutex::new(StoredSecurityAnchor::Missing),
            profile_lock: Mutex::new(()),
            fail_advance: Mutex::new(false),
            fail_read_after: Mutex::new(None),
            fail_legacy_migration: Mutex::new(false),
            payload_encryption_enabled: AtomicBool::new(true),
        }
    }

    /// Test double for a platform backend that cannot encrypt ledger payloads.
    #[must_use]
    pub fn without_mutation_payload_encryption(profile_identity_digest: [u8; 32]) -> Self {
        let store = Self::new(profile_identity_digest);
        store
            .payload_encryption_enabled
            .store(false, Ordering::Relaxed);
        store
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn disable_mutation_payload_encryption(&self) {
        self.payload_encryption_enabled
            .store(false, Ordering::Relaxed);
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn fail_next_advance(&self) {
        *self.fail_advance.lock().expect("test lock") = true;
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn fail_read_after(&self, successful_reads: usize) {
        *self.fail_read_after.lock().expect("test lock") = Some(successful_reads);
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn set_legacy_generation(&self, generation: u64) {
        *self.anchor.lock().expect("test lock") =
            StoredSecurityAnchor::LegacyGeneration(generation);
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn fail_next_legacy_migration(&self) {
        *self.fail_legacy_migration.lock().expect("test lock") = true;
    }
}

impl SecureStore for DeterministicSecureStore {
    fn acquire_security_profile_lock(
        &self,
        profile_identity_digest: [u8; 32],
    ) -> Result<SecurityProfileLock<'_>, SecureStoreError> {
        if profile_identity_digest != self.profile_identity_digest {
            return Err(SecureStoreError::LockMismatch);
        }
        let guard = self
            .profile_lock
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        Ok(SecurityProfileLock::new(
            profile_identity_digest,
            TestLock {
                profile: profile_identity_digest,
                _guard: guard,
                payload_encryption_enabled: self.payload_encryption_enabled.load(Ordering::Relaxed),
            },
        ))
    }

    fn read_security_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
    ) -> Result<StoredSecurityAnchor, SecureStoreError> {
        let mut fail = self
            .fail_read_after
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        if matches!(*fail, Some(0)) {
            *fail = None;
            return Err(SecureStoreError::Unavailable);
        }
        if let Some(remaining) = fail.as_mut() {
            *remaining -= 1;
        }
        drop(fail);
        let anchor = self
            .anchor
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?
            .clone();
        if matches!(&anchor, StoredSecurityAnchor::V1(value) if !lock.matches(value.profile_identity_digest))
        {
            return Err(SecureStoreError::CorruptAnchor);
        }
        Ok(anchor)
    }

    fn compare_and_advance_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
        expected: &SecurityAnchorV1,
        next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        if !lock.matches(next.profile_identity_digest) {
            return Err(SecureStoreError::LockMismatch);
        }
        if !next.is_valid() || !valid_next(Some(expected), next) {
            return Err(SecureStoreError::InvalidTransition);
        }
        self.verify_security_transaction(lock, next)?;
        let current = self
            .anchor
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        if *current != StoredSecurityAnchor::V1(expected.clone()) {
            return Err(SecureStoreError::AnchorConflict);
        }
        drop(current);
        let mut fail = self
            .fail_advance
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        if std::mem::replace(&mut *fail, false) {
            return Err(SecureStoreError::AnchorConflict);
        }
        drop(fail);
        let mut current = self
            .anchor
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        *current = StoredSecurityAnchor::V1(next.clone());
        if *current != StoredSecurityAnchor::V1(next.clone()) {
            return Err(SecureStoreError::AnchorConflict);
        }
        drop(current);
        Ok(())
    }

    fn initialize_security_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
        next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        if !lock.matches(next.profile_identity_digest)
            || !next.is_valid()
            || next.generation != 1
            || next.previous_anchor_digest != [0; 32]
        {
            return Err(SecureStoreError::InvalidTransition);
        }
        self.verify_security_transaction(lock, next)?;
        let mut current = self
            .anchor
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        if *current != StoredSecurityAnchor::Missing {
            return Err(SecureStoreError::AnchorConflict);
        }
        *current = StoredSecurityAnchor::V1(next.clone());
        drop(current);
        Ok(())
    }

    fn compare_and_migrate_legacy_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
        expected_generation: u64,
        next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        if !lock.matches(next.profile_identity_digest)
            || !next.is_valid()
            || next.generation
                != expected_generation
                    .checked_add(1)
                    .ok_or(SecureStoreError::InvalidTransition)?
        {
            return Err(SecureStoreError::InvalidTransition);
        }
        self.verify_security_transaction(lock, next)?;
        let mut fail = self
            .fail_legacy_migration
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        if std::mem::replace(&mut *fail, false) {
            return Err(SecureStoreError::AnchorConflict);
        }
        drop(fail);
        let mut current = self
            .anchor
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        if *current != StoredSecurityAnchor::LegacyGeneration(expected_generation) {
            return Err(SecureStoreError::AnchorConflict);
        }
        *current = StoredSecurityAnchor::V1(next.clone());
        drop(current);
        Ok(())
    }

    fn seal_security_transaction(
        &self,
        lock: &SecurityProfileLock<'_>,
        database_identity: [u8; 32],
        generation: u64,
        transaction_digest: [u8; 32],
        previous_anchor_digest: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        lock.seal(
            database_identity,
            generation,
            transaction_digest,
            previous_anchor_digest,
        )
    }

    fn verify_security_transaction(
        &self,
        lock: &SecurityProfileLock<'_>,
        anchor: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        if !lock.matches(anchor.profile_identity_digest) {
            return Err(SecureStoreError::LockMismatch);
        }
        lock.verify(
            anchor.database_identity,
            anchor.generation,
            anchor.transaction_digest,
            anchor.previous_anchor_digest,
            anchor.sealed_transaction.bytes(),
        )
    }
}

include!("test_support_helpers.rs");
