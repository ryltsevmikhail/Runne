use std::path::{Path, PathBuf};

use gocode_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};

#[cfg(unix)]
mod unix;

/// Synthetic retained key material owned solely by the fixture runtime root.
#[derive(Clone, PartialEq, Eq)]
pub struct FixtureJournalKey {
    bytes: [u8; 32],
    key_ref: ProviderJournalKeyRef,
    path: PathBuf,
}

impl FixtureJournalKey {
    pub fn bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn key_ref(&self) -> ProviderJournalKeyRef {
        self.key_ref
    }
}

#[cfg(unix)]
pub fn prepare_runtime_root(root: &Path) -> std::io::Result<FixtureJournalKey> {
    let directory = unix::open_runtime_root(root)?;
    unix::load_or_create(&directory, root)
}

#[cfg(not(unix))]
pub fn prepare_runtime_root(_: &Path) -> std::io::Result<FixtureJournalKey> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "fixture retained keys require Unix openat safeguards",
    ))
}

/// Fixture-only retained keyring backed by an authenticated directory handle.
pub struct RetainedFixtureKeyring {
    #[cfg(unix)]
    root: PathBuf,
    #[cfg(unix)]
    directory: std::fs::File,
}

impl RetainedFixtureKeyring {
    #[cfg(unix)]
    pub fn open(root: &Path) -> std::io::Result<Self> {
        let directory = unix::open_runtime_root(root)?;
        unix::load_or_create(&directory, root)?;
        Ok(Self {
            root: root.to_path_buf(),
            directory,
        })
    }

    #[cfg(not(unix))]
    pub fn open(_: &Path) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fixture retained keys require Unix openat safeguards",
        ))
    }

    #[cfg(unix)]
    fn key(&self) -> std::io::Result<FixtureJournalKey> {
        unix::load_key(&self.directory, &self.root)
    }
}

impl ProviderJournalKeyring for RetainedFixtureKeyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }

    fn provider_journal_key_status(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        #[cfg(unix)]
        {
            self.key()
                .map(|key| {
                    if key.key_ref == key_ref {
                        ProviderJournalKeyStatus::Available
                    } else {
                        ProviderJournalKeyStatus::Missing
                    }
                })
                .map_err(|_| SecureStoreError::OperationFailed("fixture key read failed".into()))
        }
        #[cfg(not(unix))]
        {
            let _ = key_ref;
            Ok(ProviderJournalKeyStatus::Unsupported)
        }
    }

    fn store_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        #[cfg(unix)]
        {
            let bytes = key.with_bytes(|bytes| *bytes);
            unix::store_key(&self.directory, &self.root, key.key_ref(), bytes)
                .map(|_| ())
                .map_err(|_| SecureStoreError::OperationFailed("fixture key write failed".into()))
        }
        #[cfg(not(unix))]
        {
            let _ = key;
            Err(SecureStoreError::UnsupportedSecureStoreBackend)
        }
    }

    fn load_provider_journal_key(
        &self,
        key_ref: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        #[cfg(unix)]
        {
            let key = self
                .key()
                .map_err(|_| SecureStoreError::ProviderJournalKeyNotFound)?;
            if key.key_ref != key_ref {
                return Err(SecureStoreError::ProviderJournalKeyNotFound);
            }
            ProviderJournalKeyMaterial::new(key_ref, key.bytes)
                .map_err(|_| SecureStoreError::CorruptProviderJournalKey)
        }
        #[cfg(not(unix))]
        {
            let _ = key_ref;
            Err(SecureStoreError::UnsupportedSecureStoreBackend)
        }
    }

    fn delete_provider_journal_key(
        &self,
        _: ProviderJournalKeyRef,
        _: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::DeletionDenied)
    }
}

#[cfg(unix)]
pub(super) fn encode_key_ref(key_ref: ProviderJournalKeyRef) -> [u8; 48] {
    let mut bytes = [0; 48];
    bytes[..16].copy_from_slice(&key_ref.key_id());
    bytes[16..24].copy_from_slice(&key_ref.version().to_le_bytes());
    bytes[24..40].copy_from_slice(&key_ref.runtime_authority_id());
    bytes[40..].copy_from_slice(&key_ref.database_generation().to_le_bytes());
    bytes
}

#[cfg(unix)]
pub(super) fn decode_key_ref(bytes: &[u8]) -> std::io::Result<ProviderJournalKeyRef> {
    let mut key_id = [0; 16];
    let mut authority = [0; 16];
    key_id.copy_from_slice(&bytes[..16]);
    authority.copy_from_slice(&bytes[24..40]);
    ProviderJournalKeyRef::new(
        key_id,
        u64::from_le_bytes(bytes[16..24].try_into().map_err(std::io::Error::other)?),
        authority,
        u64::from_le_bytes(bytes[40..48].try_into().map_err(std::io::Error::other)?),
    )
    .map_err(std::io::Error::other)
}
