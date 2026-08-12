use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::security_anchor::SecurityProfileLockBackend;
use crate::{
    SealedTransactionTag, SecureStore, SecureStoreError, SecurityAnchorV1, SecurityProfileLock,
    StoredSecurityAnchor,
};

struct TestLock<'a> {
    profile: [u8; 32],
    _guard: std::sync::MutexGuard<'a, ()>,
}

impl SecurityProfileLockBackend for TestLock<'_> {
    fn seal(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        SealedTransactionTag::from_test_bytes(test_tag(
            self.profile,
            database,
            generation,
            transaction,
            previous,
        ))
    }
    fn verify(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
        seal: &[u8],
    ) -> Result<(), SecureStoreError> {
        if seal == test_tag(self.profile, database, generation, transaction, previous) {
            Ok(())
        } else {
            Err(SecureStoreError::InvalidSeal)
        }
    }
}

/// Deterministic test double only; it is not an OS-backed production secure store.
pub struct DeterministicSecureStore {
    profile_identity_digest: [u8; 32],
    anchor: Mutex<StoredSecurityAnchor>,
    profile_lock: Mutex<()>,
    fail_advance: Mutex<bool>,
}

impl DeterministicSecureStore {
    #[must_use]
    pub const fn new(profile_identity_digest: [u8; 32]) -> Self {
        Self {
            profile_identity_digest,
            anchor: Mutex::new(StoredSecurityAnchor::Missing),
            profile_lock: Mutex::new(()),
            fail_advance: Mutex::new(false),
        }
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn fail_next_advance(&self) {
        *self.fail_advance.lock().expect("test lock") = true;
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn set_legacy_generation(&self, generation: u64) {
        *self.anchor.lock().expect("test lock") =
            StoredSecurityAnchor::LegacyGeneration(generation);
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
            },
        ))
    }

    fn read_security_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
    ) -> Result<StoredSecurityAnchor, SecureStoreError> {
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

fn valid_next(expected: Option<&SecurityAnchorV1>, next: &SecurityAnchorV1) -> bool {
    expected.map_or_else(
        || next.generation == 1 && next.previous_anchor_digest == [0; 32],
        |previous| {
            next.profile_identity_digest == previous.profile_identity_digest
                && next.database_identity == previous.database_identity
                && previous.generation.checked_add(1) == Some(next.generation)
                && next.previous_anchor_digest == previous.digest()
        },
    )
}

fn test_tag(
    profile: [u8; 32],
    database_identity: [u8; 32],
    generation: u64,
    transaction_digest: [u8; 32],
    previous_anchor_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"test-only/gocode/security-seal/v1\0");
    hasher.update(profile);
    hasher.update(database_identity);
    hasher.update(generation.to_be_bytes());
    hasher.update(transaction_digest);
    hasher.update(previous_anchor_digest);
    hasher.finalize().into()
}
