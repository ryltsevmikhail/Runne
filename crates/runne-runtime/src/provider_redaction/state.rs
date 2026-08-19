use runne_provider::{
    CredentialMatcher, ScannerCheckpoint, ScannerError, ScannerTerminalDisposition,
    ScannerUncertainReason, WithheldTailStore,
};

use super::types::map_persistence_error;
use super::{ProviderRedactionError, ProviderRedactionRecovery, ScannerRecoveryPersistence};

impl<T, P, M> ProviderRedactionRecovery<'_, T, P, M>
where
    T: WithheldTailStore + ?Sized,
    P: ScannerRecoveryPersistence + ?Sized,
    M: CredentialMatcher + ?Sized,
{
    /// Returns the current opaque checkpoint.
    pub const fn checkpoint(&self) -> Option<ScannerCheckpoint> {
        self.checkpoint
    }

    /// Returns the committed terminal disposition, or `None` while scanning.
    pub const fn disposition(&self) -> Option<ScannerTerminalDisposition> {
        self.disposition
    }

    pub(super) fn fail(
        &mut self,
        reason: ScannerUncertainReason,
    ) -> Result<(), ProviderRedactionError> {
        self.commit_terminal(ScannerTerminalDisposition::Uncertain(reason))?;
        self.purge_all_tails()
    }

    pub(super) fn purge_all_tails(&self) -> Result<(), ProviderRedactionError> {
        self.tail_store
            .purge_orphaned_tails(self.binding, None)
            .map_err(|_| ProviderRedactionError::PersistenceUnavailable)
    }

    pub(super) fn terminate_scanner_error(
        &mut self,
        error: ScannerError,
    ) -> Result<(), ProviderRedactionError> {
        match error {
            ScannerError::OutputLimitExceeded => {
                self.commit_terminal(ScannerTerminalDisposition::OutputLimitExceeded)
            }
            ScannerError::MatcherUnavailable => {
                self.fail(ScannerUncertainReason::CredentialMatcherUnavailable)
            }
            ScannerError::ScannerUnavailable => {
                self.fail(ScannerUncertainReason::RedactionScannerUnavailable)
            }
            ScannerError::InvalidBinding | ScannerError::InvalidCheckpoint => {
                self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)
            }
        }
    }

    pub(super) fn inspect_atomic_surface(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), ProviderRedactionError> {
        if self.disposition.is_some() {
            return Ok(());
        }
        match self.matcher.epoch() {
            Ok(epoch) if epoch == self.binding.matcher_epoch() => {}
            Ok(_) => {
                return self.fail(ScannerUncertainReason::CredentialMatcherUnavailable);
            }
            Err(error) => return self.terminate_scanner_error(error),
        }
        match self.matcher.contains_match(bytes) {
            Ok(false) => Ok(()),
            Ok(true) => self.fail(ScannerUncertainReason::SecretDetected),
            Err(error) => self.terminate_scanner_error(error),
        }
    }

    pub(super) fn commit_terminal(
        &mut self,
        candidate: ScannerTerminalDisposition,
    ) -> Result<(), ProviderRedactionError> {
        let disposition = self
            .disposition
            .map_or(candidate, |current| current.dominant(candidate));
        let authoritative = self
            .persistence
            .commit_terminal(self.binding, disposition)
            .map_err(map_persistence_error)?;
        self.disposition = Some(authoritative);
        Ok(())
    }
}
