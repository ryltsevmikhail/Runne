use gocode_provider::{
    CredentialMatcher, ScannerCheckpoint, ScannerTerminalDisposition, ScannerUncertainReason,
    WithheldTailStore,
};
use zeroize::Zeroizing;

use super::{ProviderRedactionError, ProviderRedactionRecovery, ScannerRecoveryPersistence};

impl<T, P, M> ProviderRedactionRecovery<'_, T, P, M>
where
    T: WithheldTailStore + ?Sized,
    P: ScannerRecoveryPersistence + ?Sized,
    M: CredentialMatcher + ?Sized,
{
    /// Flushes a fully scanned tail, advances its empty checkpoint, then commits success.
    pub fn complete(
        &mut self,
        staged_safe_material: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderRedactionError> {
        if self.disposition.is_some() {
            return Ok(());
        }
        let previous = match self.checkpoint {
            Some(checkpoint) => match self
                .tail_store
                .load_tail(&checkpoint.tail_reference(), self.binding)
            {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                    return Ok(());
                }
            },
            None => Zeroizing::new(Vec::new()),
        };
        match self.matcher.epoch() {
            Ok(epoch) if epoch == self.binding.matcher_epoch() => {}
            Ok(_) => {
                self.fail(ScannerUncertainReason::CredentialMatcherUnavailable)?;
                return Ok(());
            }
            Err(error) => {
                self.terminate_scanner_error(error)?;
                return Ok(());
            }
        }
        match self.matcher.contains_match(&previous) {
            Ok(false) => {}
            Ok(true) => {
                self.fail(ScannerUncertainReason::SecretDetected)?;
                return Ok(());
            }
            Err(error) => {
                self.terminate_scanner_error(error)?;
                return Ok(());
            }
        }
        let released = previous;
        let reference = match self
            .tail_store
            .put_tail(self.binding, Zeroizing::new(Vec::new()))
        {
            Ok(reference) => reference,
            Err(_) => {
                self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Ok(());
            }
        };
        let sequence = self
            .checkpoint
            .map_or(1, |checkpoint| checkpoint.sequence() + 1);
        let checkpoint = match ScannerCheckpoint::new(
            reference,
            self.binding,
            sequence,
            self.binding.cursor(),
        ) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                let _ = self.tail_store.delete_tail(&reference);
                self.terminate_scanner_error(error)?;
                return Ok(());
            }
        };
        if self.persistence.persist_checkpoint(checkpoint).is_err() {
            let _ = self.tail_store.delete_tail(&reference);
            self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Err(ProviderRedactionError::PersistenceUnavailable);
        }
        if self.persistence.advance_checkpoint(checkpoint).is_err() {
            let terminal = self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable);
            let _ = self.tail_store.delete_tail(&reference);
            terminal?;
            return Err(ProviderRedactionError::PersistenceUnavailable);
        }
        self.checkpoint = Some(checkpoint);
        if self.purge_all_tails().is_err() {
            self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(());
        }
        self.commit_terminal(ScannerTerminalDisposition::Completed)?;
        if self.disposition == Some(ScannerTerminalDisposition::Completed) {
            staged_safe_material.extend_from_slice(&released);
        }
        Ok(())
    }
}
