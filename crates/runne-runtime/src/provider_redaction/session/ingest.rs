use runne_provider::{
    CredentialMatcher, ScannerCheckpoint, ScannerTerminalDisposition, ScannerUncertainReason,
    WithheldTailStore, scan_provider_chunk,
};
use zeroize::Zeroizing;

use super::super::diagnostics::{
    RedactionFailureKind, RedactionFailureSite, recovery_failure_kind, scanner_failure_kind,
    tail_failure_kind,
};
use super::super::types::{ProviderRedactionError, ScannerRecoveryPersistence};
use super::ProviderRedactionRecovery;

impl<'a, T, P, M> ProviderRedactionRecovery<'a, T, P, M>
where
    T: WithheldTailStore + ?Sized,
    P: ScannerRecoveryPersistence + ?Sized,
    M: CredentialMatcher + ?Sized,
{
    /// Scans provider bytes and stages only a proven-safe prefix before checkpointing.
    pub fn ingest(
        &mut self,
        provider_bytes: &[u8],
        staged_safe_material: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderRedactionError> {
        self.ingest_at(self.binding.cursor(), provider_bytes, staged_safe_material)
    }

    /// Scans bytes only at the exact next provider cursor; echoes fail closed.
    pub fn ingest_at(
        &mut self,
        provider_cursor: u64,
        provider_bytes: &[u8],
        staged_safe_material: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderRedactionError> {
        if self.disposition.is_some() {
            return Ok(());
        }
        if provider_cursor != self.binding.cursor() {
            self.observe_failure(
                RedactionFailureSite::IngestCursorValidation,
                RedactionFailureKind::CheckpointMismatch,
            );
            self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(());
        }
        let previous_tail = match self.checkpoint {
            Some(checkpoint) => match self
                .tail_store
                .load_tail(&checkpoint.tail_reference(), self.binding)
            {
                Ok(bytes) => bytes,
                Err(error) => {
                    self.observe_failure(
                        RedactionFailureSite::IngestTailLoad,
                        tail_failure_kind(error),
                    );
                    self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                    return Ok(());
                }
            },
            None => Zeroizing::new(Vec::new()),
        };
        let high_water = self
            .checkpoint
            .map_or(0, ScannerCheckpoint::safe_prefix_high_water);
        let step = match scan_provider_chunk(
            self.matcher,
            self.binding,
            previous_tail,
            provider_bytes,
            high_water,
        ) {
            Ok(step) => step,
            Err(error) => {
                self.observe_failure(
                    RedactionFailureSite::IngestScannerClassification,
                    scanner_failure_kind(error),
                );
                self.terminate_scanner_error(error)?;
                return Ok(());
            }
        };
        if let Some(disposition) = step.disposition() {
            match disposition {
                ScannerTerminalDisposition::Uncertain(reason) => self.fail(reason)?,
                ScannerTerminalDisposition::OutputLimitExceeded => {
                    self.commit_terminal(disposition)?;
                    self.purge_all_tails()?;
                }
                ScannerTerminalDisposition::Completed => {
                    self.fail(ScannerUncertainReason::RedactionScannerUnavailable)?;
                }
            }
            return Ok(());
        }
        let safe_prefix = Zeroizing::new(step.safe_prefix().to_vec());
        let previous_reference = self.checkpoint.map(|value| value.tail_reference());
        let next_binding = step.binding();
        let next_high_water = step.safe_prefix_high_water();
        let reference = match self
            .tail_store
            .put_tail(next_binding, step.into_withheld_tail())
        {
            Ok(reference) => reference,
            Err(error) => {
                self.observe_failure(
                    RedactionFailureSite::IngestTailPut,
                    tail_failure_kind(error),
                );
                self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Ok(());
            }
        };
        let sequence = self
            .checkpoint
            .map_or(1, |checkpoint| checkpoint.sequence() + 1);
        let checkpoint =
            match ScannerCheckpoint::new(reference, next_binding, sequence, next_high_water) {
                Ok(checkpoint) => checkpoint,
                Err(error) => {
                    self.observe_failure(
                        RedactionFailureSite::IngestCheckpointConstruction,
                        scanner_failure_kind(error),
                    );
                    let _ = self.tail_store.delete_tail(&reference);
                    self.terminate_scanner_error(error)?;
                    return Ok(());
                }
            };
        if let Err(error) = self.persistence.persist_checkpoint(checkpoint) {
            self.observe_failure(
                RedactionFailureSite::IngestCheckpointPersist,
                recovery_failure_kind(error),
            );
            let _ = self.tail_store.delete_tail(&reference);
            self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Err(ProviderRedactionError::PersistenceUnavailable);
        }
        self.binding = next_binding;
        if let Err(error) = self.persistence.advance_checkpoint(checkpoint) {
            self.observe_failure(
                RedactionFailureSite::IngestCheckpointAdvance,
                recovery_failure_kind(error),
            );
            let terminal = self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable);
            let _ = self.tail_store.delete_tail(&reference);
            terminal?;
            return Err(ProviderRedactionError::PersistenceUnavailable);
        }
        self.checkpoint = Some(checkpoint);
        staged_safe_material.extend_from_slice(&safe_prefix);
        if let Some(previous) = previous_reference {
            if let Err(error) = self.tail_store.delete_tail(&previous) {
                self.observe_failure(
                    RedactionFailureSite::IngestPreviousTailDelete,
                    tail_failure_kind(error),
                );
                self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            }
        }
        Ok(())
    }
}
