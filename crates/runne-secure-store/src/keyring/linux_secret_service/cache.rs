//! Injected keyutils cache-half boundary for the Linux combo store.
//!
//! Mirrors the exact keyutils semantics of the locked `keyring 3.6.3`
//! dependency (`session.add_key`, `search` + `link_key`, `invalidate`,
//! description `keyring-rs:{account}@{service}`) so cache entries stay
//! byte-compatible with the combo store, while delete errors surface to the
//! caller instead of being swallowed (DESIGN v6 §6-F3). Kernel caveat from
//! the dependency: an invalidated key may still be found by a search within
//! milliseconds inside the SAME process; absence checks therefore treat a
//! post-invalidate hit as an incomplete revoke (fail-closed, retried later).

use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheDeletionOutcome {
    Deleted,
    Absent,
}

/// Injected keyutils cache half (production: kernel keyutils).
pub trait KeyutilsCache {
    fn set(&mut self, description: &str, secret: &[u8]) -> Result<(), CacheError>;
    fn get(&mut self, description: &str) -> Result<Option<Zeroizing<Vec<u8>>>, CacheError>;
    fn delete(&mut self, description: &str) -> Result<CacheDeletionOutcome, CacheError>;
}

/// Keyutils errors the keyring crate documents as "no such key" (the
/// invalidation-processing window); matched so cache semantics stay
/// compatible while every other kernel failure surfaces as a real error.
pub fn kernel_absent(error: linux_keyutils::KeyError) -> bool {
    matches!(
        error,
        linux_keyutils::KeyError::KeyDoesNotExist
            | linux_keyutils::KeyError::AccessDenied
            | linux_keyutils::KeyError::KeyRevoked
            | linux_keyutils::KeyError::KeyExpired
    )
}

/// Cache description byte-compatible with the keyring crate combo store.
pub fn entry_description(service: &str, account: &str) -> String {
    format!("keyring-rs:{account}@{service}")
}

/// Kernel keyutils cache half (session keyring + persistent link).
pub struct KernelKeyutilsCache {
    session: linux_keyutils::KeyRing,
    persistent: Option<linux_keyutils::KeyRing>,
}

impl KernelKeyutilsCache {
    /// Attaches to the current session keyring and its persistent link.
    /// A missing session keyring is a closed failure; it is never created.
    pub fn attach() -> Result<Self, CacheError> {
        let session = linux_keyutils::KeyRing::from_special_id(
            linux_keyutils::KeyRingIdentifier::Session,
            false,
        )
        .map_err(|_| CacheError::Unavailable)?;
        let persistent =
            linux_keyutils::KeyRing::get_persistent(linux_keyutils::KeyRingIdentifier::Session)
                .ok();
        Ok(Self {
            session,
            persistent,
        })
    }
}

impl KeyutilsCache for KernelKeyutilsCache {
    fn set(&mut self, description: &str, secret: &[u8]) -> Result<(), CacheError> {
        if secret.is_empty() {
            return Err(CacheError::Unavailable);
        }
        let key = self
            .session
            .add_key(description, secret)
            .map_err(|_| CacheError::Unavailable)?;
        if let Some(persistent) = self.persistent {
            persistent
                .link_key(key)
                .map_err(|_| CacheError::Unavailable)?;
        }
        Ok(())
    }

    fn get(&mut self, description: &str) -> Result<Option<Zeroizing<Vec<u8>>>, CacheError> {
        let key = match self.session.search(description) {
            Ok(key) => key,
            Err(error) if kernel_absent(error) => return Ok(None),
            Err(_) => return Err(CacheError::Unavailable),
        };
        self.session
            .link_key(key)
            .map_err(|_| CacheError::Unavailable)?;
        if let Some(persistent) = self.persistent {
            persistent
                .link_key(key)
                .map_err(|_| CacheError::Unavailable)?;
        }
        let buffer = key.read_to_vec().map_err(|_| CacheError::Unavailable)?;
        Ok(Some(Zeroizing::new(buffer)))
    }

    fn delete(&mut self, description: &str) -> Result<CacheDeletionOutcome, CacheError> {
        let key = match self.session.search(description) {
            Ok(key) => key,
            Err(linux_keyutils::KeyError::KeyDoesNotExist) => {
                return Ok(CacheDeletionOutcome::Absent);
            }
            Err(_) => return Err(CacheError::Unavailable),
        };
        key.invalidate().map_err(|_| CacheError::Unavailable)?;
        Ok(CacheDeletionOutcome::Deleted)
    }
}
