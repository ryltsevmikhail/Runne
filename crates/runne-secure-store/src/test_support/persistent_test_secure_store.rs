use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    SealedTransactionTag, SecureStore, SecureStoreError, SecurityAnchorV1, SecurityProfileLock,
    StoredSecurityAnchor, security_anchor::SecurityProfileLockBackend,
};

mod codec;

#[cfg(test)]
#[path = "persistent_test_secure_store_tests.rs"]
mod tests;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// File-backed deterministic anchor fixture for real process-restart tests.
/// The directory must be private and disposable; this is never an OS keyring.
pub struct PersistentDeterministicSecureStore {
    directory: PathBuf,
    profile: [u8; 32],
}

impl PersistentDeterministicSecureStore {
    /// Opens a private fixture directory, creating it when absent.
    ///
    /// # Errors
    /// Returns an error if the directory is not private or cannot be accessed.
    pub fn open(directory: impl AsRef<Path>, profile: [u8; 32]) -> Result<Self, SecureStoreError> {
        if profile == [0; 32] {
            return Err(SecureStoreError::LockMismatch);
        }
        fs::create_dir_all(directory.as_ref()).map_err(|_| SecureStoreError::Unavailable)?;
        fs::set_permissions(directory.as_ref(), fs::Permissions::from_mode(0o700))
            .map_err(|_| SecureStoreError::Unavailable)?;
        let directory = fs::canonicalize(directory).map_err(|_| SecureStoreError::Unavailable)?;
        let metadata = fs::metadata(&directory).map_err(|_| SecureStoreError::Unavailable)?;
        if metadata.permissions().mode() & 0o077 != 0 || !metadata.is_dir() {
            return Err(SecureStoreError::Unavailable);
        }
        Ok(Self { directory, profile })
    }

    fn read_anchor(&self) -> Result<StoredSecurityAnchor, SecureStoreError> {
        let path = self.directory.join("anchor.v1");
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StoredSecurityAnchor::Missing);
            }
            Err(_) => return Err(SecureStoreError::Unavailable),
        };
        let mut bytes = Vec::new();
        file.take(512)
            .read_to_end(&mut bytes)
            .map_err(|_| SecureStoreError::Unavailable)?;
        codec::decode(&bytes)
    }

    fn write_anchor(&self, anchor: &SecurityAnchorV1) -> Result<(), SecureStoreError> {
        let bytes = codec::encode(anchor);
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary =
            self.directory
                .join(format!("anchor.{}.{}.tmp", std::process::id(), sequence));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|_| SecureStoreError::Unavailable)?;
            file.write_all(&bytes)
                .map_err(|_| SecureStoreError::Unavailable)?;
            file.sync_all().map_err(|_| SecureStoreError::Unavailable)?;
            fs::rename(&temporary, self.directory.join("anchor.v1"))
                .map_err(|_| SecureStoreError::Unavailable)?;
            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| SecureStoreError::Unavailable)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn lock_file(&self) -> Result<File, SecureStoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.directory.join("anchor.lock"))
            .map_err(|_| SecureStoreError::Unavailable)?;
        file.lock().map_err(|_| SecureStoreError::Unavailable)?;
        Ok(file)
    }
}

struct PersistentTestLock {
    profile: [u8; 32],
    _file: File,
}

impl SecurityProfileLockBackend for PersistentTestLock {
    fn seal(
        &self,
        db: [u8; 32],
        generation: u64,
        tx: [u8; 32],
        previous: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        SealedTransactionTag::from_test_bytes(super::test_tag(
            self.profile,
            db,
            generation,
            tx,
            previous,
        ))
    }
    fn verify(
        &self,
        db: [u8; 32],
        generation: u64,
        tx: [u8; 32],
        previous: [u8; 32],
        seal: &[u8],
    ) -> Result<(), SecureStoreError> {
        if seal == super::test_tag(self.profile, db, generation, tx, previous) {
            Ok(())
        } else {
            Err(SecureStoreError::InvalidSeal)
        }
    }
    fn encrypt_mutation_payload(
        &self,
        db: [u8; 32],
        aad: &[u8],
        bytes: &[u8],
    ) -> Result<Vec<u8>, SecureStoreError> {
        crate::payload_crypto::encrypt(
            &super::test_payload_key(self.profile),
            self.profile,
            db,
            aad,
            bytes,
        )
    }
    fn decrypt_mutation_payload(
        &self,
        db: [u8; 32],
        aad: &[u8],
        bytes: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SecureStoreError> {
        crate::payload_crypto::decrypt(
            &super::test_payload_key(self.profile),
            self.profile,
            db,
            aad,
            bytes,
        )
    }
    fn supports_mutation_payload_encryption(&self) -> bool {
        true
    }
}

impl SecureStore for PersistentDeterministicSecureStore {
    fn acquire_security_profile_lock(
        &self,
        profile: [u8; 32],
    ) -> Result<SecurityProfileLock<'_>, SecureStoreError> {
        if profile != self.profile {
            return Err(SecureStoreError::LockMismatch);
        }
        Ok(SecurityProfileLock::new(
            profile,
            PersistentTestLock {
                profile,
                _file: self.lock_file()?,
            },
        ))
    }
    fn read_security_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
    ) -> Result<StoredSecurityAnchor, SecureStoreError> {
        if !lock.matches(self.profile) {
            return Err(SecureStoreError::LockMismatch);
        }
        self.read_anchor()
    }
    fn compare_and_advance_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
        expected: &SecurityAnchorV1,
        next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        if !lock.matches(self.profile)
            || !next.is_valid()
            || next.profile_identity_digest != self.profile
            || !codec::valid_next(Some(expected), next)
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
        if self.read_anchor()? != StoredSecurityAnchor::V1(expected.clone()) {
            return Err(SecureStoreError::AnchorConflict);
        }
        self.write_anchor(next)
    }
    fn initialize_security_anchor(
        &self,
        lock: &SecurityProfileLock<'_>,
        next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        if !lock.matches(self.profile)
            || !next.is_valid()
            || next.profile_identity_digest != self.profile
            || !codec::valid_next(None, next)
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
        if self.read_anchor()? != StoredSecurityAnchor::Missing {
            return Err(SecureStoreError::AnchorConflict);
        }
        self.write_anchor(next)
    }
    fn compare_and_migrate_legacy_anchor(
        &self,
        _lock: &SecurityProfileLock<'_>,
        _generation: u64,
        _next: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }
    fn seal_security_transaction(
        &self,
        lock: &SecurityProfileLock<'_>,
        db: [u8; 32],
        generation: u64,
        tx: [u8; 32],
        previous: [u8; 32],
    ) -> Result<SealedTransactionTag, SecureStoreError> {
        if !lock.matches(self.profile) {
            return Err(SecureStoreError::LockMismatch);
        }
        lock.seal(db, generation, tx, previous)
    }
    fn verify_security_transaction(
        &self,
        lock: &SecurityProfileLock<'_>,
        anchor: &SecurityAnchorV1,
    ) -> Result<(), SecureStoreError> {
        if !lock.matches(self.profile) {
            return Err(SecureStoreError::LockMismatch);
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
