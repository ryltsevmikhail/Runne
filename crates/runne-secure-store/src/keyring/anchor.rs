use ring::hmac;
use zeroize::Zeroizing;

use crate::security_anchor::SecurityProfileLockBackend;
use crate::{
    SealedTransactionTag, SecureStore, SecureStoreError, SecurityAnchorV1, SecurityProfileLock,
    StoredSecurityAnchor,
};

use super::{ANCHOR_SERVICE, KEYRING_LOCK, MAX_PROFILE_KEY_BYTES, NativeKeyringStore};

mod codec;
use codec::{decode_anchor, encode_anchor, profile_key, seal_input};

struct NativeSecurityLock {
    profile: [u8; 32],
    key: Zeroizing<Vec<u8>>,
}

impl SecurityProfileLockBackend for NativeSecurityLock {
    fn seal(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        let tag = hmac::sign(
            &key,
            &seal_input(self.profile, database, generation, transaction, previous),
        );
        SealedTransactionTag::from_storage(tag.as_ref().to_vec())
    }

    fn verify(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
        seal: &[u8],
    ) -> Result<(), SecureStoreError> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        hmac::verify(
            &key,
            &seal_input(self.profile, database, generation, transaction, previous),
            seal,
        )
        .map_err(|_| SecureStoreError::InvalidSeal)
    }

    fn encrypt_mutation_payload(
        &self,
        database: [u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SecureStoreError> {
        crate::payload_crypto::encrypt(&self.key, self.profile, database, aad, plaintext)
    }

    fn decrypt_mutation_payload(
        &self,
        database: [u8; 32],
        aad: &[u8],
        envelope: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SecureStoreError> {
        crate::payload_crypto::decrypt(&self.key, self.profile, database, aad, envelope)
    }

    fn supports_mutation_payload_encryption(&self) -> bool {
        true
    }
}

impl SecureStore for NativeKeyringStore {
    fn acquire_security_profile_lock(
        &self,
        profile: [u8; 32],
    ) -> Result<SecurityProfileLock<'_>, SecureStoreError> {
        self.require_profile(profile)?;
        let account = self.lock_account();
        let key = match Self::read_secret(ANCHOR_SERVICE, &account)? {
            Some(key) if !key.is_empty() && key.len() <= MAX_PROFILE_KEY_BYTES => key,
            Some(_) => return Err(SecureStoreError::CorruptAnchor),
            None => {
                let key = Zeroizing::new(profile_key()?);
                Self::write_secret(ANCHOR_SERVICE, &account, &key)?;
                key
            }
        };
        Ok(SecurityProfileLock::new(
            profile,
            NativeSecurityLock { profile, key },
        ))
    }

    fn read_security_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
    ) -> Result<StoredSecurityAnchor, SecureStoreError> {
        self.require_lock(lock)?;
        let account = self.anchor_account();
        match Self::read_secret(ANCHOR_SERVICE, &account)? {
            None => Ok(StoredSecurityAnchor::Missing),
            Some(bytes) if bytes.len() == 8 => {
                Ok(StoredSecurityAnchor::LegacyGeneration(u64::from_le_bytes(
                    bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| SecureStoreError::CorruptAnchor)?,
                )))
            }
            Some(bytes) => decode_anchor(&bytes).map(StoredSecurityAnchor::V1),
        }
    }

    fn compare_and_advance_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
        expected: &SecurityAnchorV1,
        next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        self.require_lock(lock)?;
        if expected.profile_identity_digest != self.anchor_profile.unwrap_or_default()
            || next.profile_identity_digest != expected.profile_identity_digest
            || !next.is_valid()
            || next.database_identity != expected.database_identity
            || expected.generation.checked_add(1) != Some(next.generation)
            || next.previous_anchor_digest != expected.digest()
        {
            return Err(SecureStoreError::InvalidTransition);
        }
        lock.verify(
            next.database_identity,
            next.generation,
            next.transaction_digest,
            next.previous_anchor_digest,
            next.sealed_transaction.as_bytes(),
        )?;
        let _guard = KEYRING_LOCK
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        if self.read_security_anchor(lock)? != StoredSecurityAnchor::V1(expected.clone()) {
            return Err(SecureStoreError::AnchorConflict);
        }
        self.save_anchor(next)?;
        if self.read_security_anchor(lock)? != StoredSecurityAnchor::V1(next.clone()) {
            return Err(SecureStoreError::AnchorConflict);
        }
        Ok(())
    }

    fn initialize_security_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
        next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        self.require_lock(lock)?;
        let profile = self.anchor_profile.ok_or(SecureStoreError::LockMismatch)?;
        if next.profile_identity_digest != profile
            || !next.is_valid()
            || next.generation != 1
            || next.previous_anchor_digest != [0; 32]
        {
            return Err(SecureStoreError::InvalidTransition);
        }
        lock.verify(
            next.database_identity,
            next.generation,
            next.transaction_digest,
            next.previous_anchor_digest,
            next.sealed_transaction.as_bytes(),
        )?;
        let _guard = KEYRING_LOCK
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        if self.read_security_anchor(lock)? != StoredSecurityAnchor::Missing {
            return Err(SecureStoreError::AnchorConflict);
        }
        self.save_anchor(next)
    }

    fn compare_and_migrate_legacy_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
        expected_generation: u64,
        next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        self.require_lock(lock)?;
        let profile = self.anchor_profile.ok_or(SecureStoreError::LockMismatch)?;
        if next.profile_identity_digest != profile
            || !next.is_valid()
            || expected_generation.checked_add(1) != Some(next.generation)
        {
            return Err(SecureStoreError::InvalidTransition);
        }
        lock.verify(
            next.database_identity,
            next.generation,
            next.transaction_digest,
            next.previous_anchor_digest,
            next.sealed_transaction.as_bytes(),
        )?;
        let _guard = KEYRING_LOCK
            .lock()
            .map_err(|_| SecureStoreError::Unavailable)?;
        if self.read_security_anchor(lock)?
            != StoredSecurityAnchor::LegacyGeneration(expected_generation)
        {
            return Err(SecureStoreError::AnchorConflict);
        }
        self.save_anchor(next)
    }

    fn seal_security_transaction(
        &self,
        lock: &SecurityProfileLock<'_>,
        database_identity: [u8; 32],
        generation: u64,
        transaction_digest: [u8; 32],
        previous_anchor_digest: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        self.require_lock(lock)?;
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
        self.require_lock(lock)?;
        if !anchor.is_valid() {
            return Err(SecureStoreError::InvalidSeal);
        }
        lock.verify(
            anchor.database_identity,
            anchor.generation,
            anchor.transaction_digest,
            anchor.previous_anchor_digest,
            anchor.sealed_transaction.as_bytes(),
        )
    }
}

impl NativeKeyringStore {
    fn require_lock(&self, lock: &SecurityProfileLock<'_>) -> Result<(), SecureStoreError> {
        let profile = self.anchor_profile.ok_or(SecureStoreError::LockMismatch)?;
        if lock.matches(profile) {
            Ok(())
        } else {
            Err(SecureStoreError::LockMismatch)
        }
    }

    fn save_anchor(&self, anchor: &SecurityAnchorV1) -> Result<(), SecureStoreError> {
        Self::write_secret(
            ANCHOR_SERVICE,
            &self.anchor_account(),
            &encode_anchor(anchor),
        )
    }
}
