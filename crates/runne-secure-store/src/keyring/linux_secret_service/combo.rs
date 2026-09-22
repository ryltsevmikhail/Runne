//! Linux combo persistent store: keyutils cache half + owner-bound SS half.
//!
//! DESIGN v6 §6 F1′/F2/F3/F4: dispatch reads never prompt (facade half has no
//! prompt/unlock surface; cache half is kernel syscalls); persisted writes
//! follow the combo semantics of the locked keyring dependency (cache first,
//! SS second, rollback on SS failure); completion is verified ONLY through the
//! SS half with the cache half invalidated (cache-only success never counts);
//! revoke deletes both halves with cache errors surfaced and absence checked
//! on both halves before completion.

use zeroize::Zeroizing;

use super::cache::{CacheDeletionOutcome, CacheError, KeyutilsCache, entry_description};
use super::facade::{BoundSecretService, EntryLockState, SsFacadeError};
use super::item_layout::EntryIdentity;
use super::owner::ProcessFacts;
use super::port::SecretServiceBus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComboError {
    /// Secret Service half failed (owner, transport, or lock).
    Ss(SsFacadeError),
    /// Cache half failed.
    Cache(CacheError),
    /// SS readback after a verified write did not match the written bytes.
    VerificationFailed,
    /// Revoke could not prove absence of both halves.
    RevokeIncomplete,
    /// SS write failed AND restoring the previous cache value failed.
    RollbackRestoreFailed,
    /// SS write failed AND removing the cache insertion failed.
    RollbackDeleteFailed,
    /// Mismatched readback cleanup could not remove or prove absence.
    CleanupIncomplete,
}

impl ComboError {
    pub fn description(self) -> &'static str {
        match self {
            Self::Ss(error) => error.description(),
            Self::Cache(_) => "keyutils cache unavailable",
            Self::VerificationFailed => "persistent-half readback mismatch",
            Self::RevokeIncomplete => "dual-half revoke incomplete",
            Self::RollbackRestoreFailed => "cache rollback could not restore prior value",
            Self::RollbackDeleteFailed => "cache rollback could not remove insertion",
            Self::CleanupIncomplete => "mismatch cleanup left a half present",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsVerifiedWrite {
    Verified,
}

pub struct LinuxComboPersistentStore<B: SecretServiceBus, F: ProcessFacts, K: KeyutilsCache> {
    facade: BoundSecretService<B, F>,
    cache: K,
}

impl<B: SecretServiceBus, F: ProcessFacts, K: KeyutilsCache> LinuxComboPersistentStore<B, F, K> {
    pub fn new(bus: B, facts: F, cache: K) -> Result<Self, SsFacadeError> {
        Ok(Self {
            facade: BoundSecretService::bind(bus, facts)?,
            cache,
        })
    }

    /// Dispatch read. Justified cache policy: the keyutils half accelerates
    /// only the PAYLOAD, never the lock decision — every dispatch read first
    /// performs the facade's unlocked-only SS search, so a locked store fails
    /// closed even with a warm cache and no prompt/unlock can ever occur.
    /// Payload then comes from the cache when present, else from the SS half
    /// (which re-searches internally, closing the probe/read TOCTOU).
    pub fn read_dispatch(
        &mut self,
        identity: &EntryIdentity,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ComboError> {
        match self.facade.entry_lock_state(identity) {
            Ok(EntryLockState::PresentUnlocked) => {}
            Ok(EntryLockState::Locked) => return Err(ComboError::Ss(SsFacadeError::Locked)),
            Ok(EntryLockState::Missing) => return Ok(None),
            Err(SsFacadeError::Ambiguous) => {
                return Err(ComboError::Ss(SsFacadeError::Ambiguous));
            }
            Err(error) => return Err(ComboError::Ss(error)),
        }
        let description = entry_description(&identity.service, &identity.account);
        // Cache half is only an accelerator: any cache failure falls back to
        // the authoritative SS half instead of blocking the dispatch read.
        if let Some(cached) = self.cache.get(&description).unwrap_or(None) {
            return Ok(Some(cached));
        }
        self.facade.read_entry(identity).map_err(ComboError::Ss)
    }

    /// Combo write with rollback semantics identical to the keyring crate.
    pub fn write_persisted(
        &mut self,
        identity: &EntryIdentity,
        secret: &[u8],
    ) -> Result<(), ComboError> {
        let description = entry_description(&identity.service, &identity.account);
        let previous = self.cache.get(&description).unwrap_or(None);
        self.cache
            .set(&description, secret)
            .map_err(ComboError::Cache)?;
        if let Err(error) = self.facade.write_entry(identity, secret) {
            self.rollback_cache(&description, previous)?;
            return Err(ComboError::Ss(error));
        }
        Ok(())
    }

    /// F2 verified persistence: combo write, cache invalidation, then an
    /// SS-half readback that must return the exact written bytes; any
    /// mismatch removes both halves and fails closed.
    pub fn write_persisted_ss_verified(
        &mut self,
        identity: &EntryIdentity,
        secret: &[u8],
    ) -> Result<SsVerifiedWrite, ComboError> {
        self.write_persisted(identity, secret)?;
        let description = entry_description(&identity.service, &identity.account);
        self.cache.delete(&description).map_err(ComboError::Cache)?;
        match self.facade.read_entry(identity) {
            Ok(Some(readback)) if *readback == secret => Ok(SsVerifiedWrite::Verified),
            _ => {
                self.cleanup_after_mismatch(identity, &description)?;
                Err(ComboError::VerificationFailed)
            }
        }
    }

    /// Removes both halves after a mismatched readback and proves absence;
    /// any residue or cleanup failure is a distinct incomplete-cleanup error.
    fn cleanup_after_mismatch(
        &mut self,
        identity: &EntryIdentity,
        description: &str,
    ) -> Result<(), ComboError> {
        self.cache
            .delete(description)
            .map_err(|_| ComboError::CleanupIncomplete)?;
        self.facade
            .delete_entry(identity)
            .map_err(|_| ComboError::CleanupIncomplete)?;
        let cache_absent = matches!(self.cache.get(description), Ok(None));
        let ss_absent = matches!(
            self.facade.entry_lock_state(identity),
            Ok(EntryLockState::Missing)
        );
        if cache_absent && ss_absent {
            return Ok(());
        }
        Err(ComboError::CleanupIncomplete)
    }

    /// F3 dual-half revoke: SS half first, cache half with errors surfaced,
    /// then absence of BOTH halves before completion.
    pub fn revoke_dual_half(
        &mut self,
        identity: &EntryIdentity,
    ) -> Result<DualHalfRevoke, ComboError> {
        self.facade.delete_entry(identity).map_err(ComboError::Ss)?;
        let description = entry_description(&identity.service, &identity.account);
        self.cache.delete(&description).map_err(ComboError::Cache)?;
        let cache_absent = matches!(self.cache.get(&description), Ok(None));
        let ss_absent = matches!(self.facade.read_entry(identity), Ok(None));
        if cache_absent && ss_absent {
            return Ok(DualHalfRevoke::Revoked);
        }
        Err(ComboError::RevokeIncomplete)
    }

    /// F4 cache-half invalidation for unconfirmed versions.
    pub fn invalidate_cache_half(
        &mut self,
        identity: &EntryIdentity,
    ) -> Result<CacheDeletionOutcome, ComboError> {
        let description = entry_description(&identity.service, &identity.account);
        self.cache.delete(&description).map_err(ComboError::Cache)
    }

    fn rollback_cache(
        &mut self,
        description: &str,
        previous: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<(), ComboError> {
        match previous {
            Some(value) => self
                .cache
                .set(description, &value)
                .map_err(|_| ComboError::RollbackRestoreFailed),
            None => self
                .cache
                .delete(description)
                .map(|_| ())
                .map_err(|_| ComboError::RollbackDeleteFailed),
        }
    }

    /// Test-only access to the injected bus for fixture arming.
    #[cfg(test)]
    pub fn bus_mut(&mut self) -> &mut B {
        self.facade.bus_mut()
    }

    /// Test-only access to the injected cache for fixture arming.
    #[cfg(test)]
    pub fn cache_mut(&mut self) -> &mut K {
        &mut self.cache
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DualHalfRevoke {
    Revoked,
}

/// Provider-entry identity matching `provider_key` in `keyring/provider.rs`.
pub fn provider_identity(
    provider: crate::provider_credential::ProviderCredentialId,
) -> EntryIdentity {
    let (service, account) = super::super::provider::provider_key(provider);
    EntryIdentity::new(service, account)
}

/// Version-entry identity matching `version_key` in `keyring/provider.rs`.
pub fn version_identity(reference: &runne_provider::CredentialVersionRef) -> EntryIdentity {
    let (service, account) = super::super::provider::version_key(reference);
    EntryIdentity::new(service, account)
}
