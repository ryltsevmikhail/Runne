use runne_provider::{
    CredentialMatcher, ScannerCheckpoint, ScannerTerminalDisposition, ScannerUncertainReason,
    WithheldTailStore,
};
use zeroize::Zeroizing;

use super::diagnostics::{
    RedactionFailureSite, recovery_failure_kind, scanner_failure_kind, tail_failure_kind,
};
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
                Err(error) => {
                    self.observe_failure(
                        RedactionFailureSite::CompleteTailLoad,
                        tail_failure_kind(error),
                    );
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
                self.observe_failure(
                    RedactionFailureSite::CompleteScannerClassification,
                    scanner_failure_kind(error),
                );
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
                self.observe_failure(
                    RedactionFailureSite::CompleteScannerClassification,
                    scanner_failure_kind(error),
                );
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
            Err(error) => {
                self.observe_failure(
                    RedactionFailureSite::CompleteTailPut,
                    tail_failure_kind(error),
                );
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
                self.observe_failure(
                    RedactionFailureSite::CompleteCheckpointConstruction,
                    scanner_failure_kind(error),
                );
                let _ = self.tail_store.delete_tail(&reference);
                self.terminate_scanner_error(error)?;
                return Ok(());
            }
        };
        if let Err(error) = self.persistence.persist_checkpoint(checkpoint) {
            self.observe_failure(
                RedactionFailureSite::CompleteCheckpointPersist,
                recovery_failure_kind(error),
            );
            let _ = self.tail_store.delete_tail(&reference);
            self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Err(ProviderRedactionError::PersistenceUnavailable);
        }
        if let Err(error) = self.persistence.advance_final_checkpoint(checkpoint) {
            self.observe_failure(
                RedactionFailureSite::CompleteCheckpointAdvance,
                recovery_failure_kind(error),
            );
            let terminal = self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable);
            let _ = self.tail_store.delete_tail(&reference);
            terminal?;
            return Err(ProviderRedactionError::PersistenceUnavailable);
        }
        self.checkpoint = Some(checkpoint);
        if let Err(error) = self.tail_store.purge_orphaned_tails(self.binding, None) {
            self.observe_failure(
                RedactionFailureSite::CompleteTailPurge,
                tail_failure_kind(error),
            );
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
