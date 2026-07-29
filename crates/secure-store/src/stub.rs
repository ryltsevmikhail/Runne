use crate::{SecureStore, SecureStoreError};

/// Stub implementation for platforms where the secure store is not yet wired.
/// All operations return `Unavailable`.
#[derive(Default)]
pub struct StubStore;

impl StubStore {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SecureStore for StubStore {
    fn store_anchor(&self, _generation: u64) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    fn read_anchor(&self) -> Result<Option<u64>, SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }

    fn delete_anchor(&self) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::Unavailable)
    }
}
