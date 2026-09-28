use std::sync::MutexGuard;

use crate::security_anchor::SecurityProfileLockBackend;
use crate::{SealedTransactionTag, SecureStoreError};

pub(super) struct TestLock<'a> {
    pub(super) profile: [u8; 32],
    pub(super) _guard: MutexGuard<'a, ()>,
    pub(super) payload_encryption_enabled: bool,
}

impl SecurityProfileLockBackend for TestLock<'_> {
    fn seal(
        &self,
        database: [u8; 32],
        generation: u64,
        transaction: [u8; 32],
        previous: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        SealedTransactionTag::from_test_bytes(super::test_tag(
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
        if seal == super::test_tag(self.profile, database, generation, transaction, previous) {
            Ok(())
        } else {
            Err(SecureStoreError::InvalidSeal)
        }
    }
    fn encrypt_mutation_payload(
        &self,
        database: [u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SecureStoreError> {
        if !self.payload_encryption_enabled {
            return Err(SecureStoreError::Unavailable);
        }
        crate::payload_crypto::encrypt(
            &super::test_payload_key(self.profile),
            self.profile,
            database,
            aad,
            plaintext,
        )
    }
    fn decrypt_mutation_payload(
        &self,
        database: [u8; 32],
        aad: &[u8],
        envelope: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SecureStoreError> {
        if !self.payload_encryption_enabled {
            return Err(SecureStoreError::Unavailable);
        }
        crate::payload_crypto::decrypt(
            &super::test_payload_key(self.profile),
            self.profile,
            database,
            aad,
            envelope,
        )
    }
    fn supports_mutation_payload_encryption(&self) -> bool {
        self.payload_encryption_enabled
    }
}
