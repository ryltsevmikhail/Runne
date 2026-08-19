//! Pre-journal provider-byte withholding and fail-closed restart orchestration.
mod boundary;
mod completion;
mod state;
mod surfaces;
mod types;

pub use boundary::{
    PreJournalProviderEvent, ProhibitedContentCredentialMatcher, ProviderEventRedaction,
    ProviderEventRedactionBoundary,
};
pub use types::{
    ProviderRedactionError, ScannerRecoveryPersistence, ScannerRecoveryPersistenceError,
    ScannerRecoveryRecord,
};

use runne_provider::{
    CredentialMatcher, ScannerCheckpoint, ScannerTerminalDisposition, ScannerUncertainReason,
    TailBinding, WithheldTailStore, scan_provider_chunk,
};
use zeroize::Zeroizing;

/// Runtime-owned pre-journal scanner session.
pub struct ProviderRedactionRecovery<'a, T: ?Sized, P: ?Sized, M: ?Sized> {
    tail_store: &'a T,
    persistence: &'a P,
    matcher: &'a M,
    binding: TailBinding,
    checkpoint: Option<ScannerCheckpoint>,
    disposition: Option<ScannerTerminalDisposition>,
}

impl<'a, T, P, M> ProviderRedactionRecovery<'a, T, P, M>
where
    T: WithheldTailStore + ?Sized,
    P: ScannerRecoveryPersistence + ?Sized,
    M: CredentialMatcher + ?Sized,
{
    /// Starts a new scanner session and pins the exact matcher epoch.
    pub fn start(
        binding: TailBinding,
        tail_store: &'a T,
        persistence: &'a P,
        matcher: &'a M,
    ) -> Result<Self, ProviderRedactionError> {
        let mut session = Self {
            tail_store,
            persistence,
            matcher,
            binding,
            checkpoint: None,
            disposition: None,
        };
        match persistence.load(binding.attempt_id()) {
            Ok(None) => {
                if tail_store.purge_orphaned_tails(binding, None).is_err() {
                    session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                    return Ok(session);
                }
            }
            Ok(Some(_))
            | Err(
                ScannerRecoveryPersistenceError::Corrupt
                | ScannerRecoveryPersistenceError::Conflict,
            ) => {
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Ok(session);
            }
            Err(ScannerRecoveryPersistenceError::Unavailable) => {
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Err(ProviderRedactionError::PersistenceUnavailable);
            }
        }
        match matcher.epoch() {
            Ok(epoch) if epoch == binding.matcher_epoch() => {}
            Ok(_) => session.fail(ScannerUncertainReason::CredentialMatcherUnavailable)?,
            Err(error) => session.terminate_scanner_error(error)?,
        }
        Ok(session)
    }

    /// Restarts only from an exact checkpoint and matching native tail reference.
    pub fn restart(
        binding: TailBinding,
        tail_store: &'a T,
        persistence: &'a P,
        matcher: &'a M,
    ) -> Result<Self, ProviderRedactionError> {
        let mut session = Self {
            tail_store,
            persistence,
            matcher,
            binding,
            checkpoint: None,
            disposition: None,
        };
        let record = match persistence.load(binding.attempt_id()) {
            Ok(Some(record)) => record,
            Ok(None) | Err(ScannerRecoveryPersistenceError::Conflict) => {
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Ok(session);
            }
            Err(ScannerRecoveryPersistenceError::Corrupt) => {
                let disposition = persistence
                    .terminalize_corrupt_checkpoint(binding)
                    .map_err(types::map_persistence_error)?;
                session.disposition = Some(disposition);
                session.purge_all_tails()?;
                return Ok(session);
            }
            Err(ScannerRecoveryPersistenceError::Unavailable) => {
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Err(ProviderRedactionError::PersistenceUnavailable);
            }
        };
        let durable_binding = record.binding();
        session.binding = durable_binding;
        if !same_authority(binding, durable_binding) {
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        }
        if let Some(disposition) = record.disposition() {
            session.disposition = Some(disposition);
            if tail_store
                .purge_orphaned_tails(durable_binding, None)
                .is_err()
            {
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            }
            return Ok(session);
        }
        let Some(checkpoint) = record.checkpoint() else {
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        };
        let stored = checkpoint.binding();
        if durable_binding != stored
            || record.durable_cursor() != stored.cursor()
            || record.durable_safe_prefix_high_water() != checkpoint.safe_prefix_high_water()
            || record.durable_checkpoint_digest() != Some(checkpoint.digest())
        {
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        }
        match matcher.epoch() {
            Ok(epoch) if epoch == stored.matcher_epoch() => {}
            Ok(_) => {
                session.fail(ScannerUncertainReason::CredentialMatcherUnavailable)?;
                return Ok(session);
            }
            Err(error) => {
                session.terminate_scanner_error(error)?;
                return Ok(session);
            }
        }
        if tail_store
            .load_tail(&checkpoint.tail_reference(), stored)
            .is_err()
        {
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        }
        if tail_store
            .purge_orphaned_tails(stored, Some(checkpoint.tail_reference()))
            .is_err()
        {
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        }
        session.binding = stored;
        session.checkpoint = Some(checkpoint);
        Ok(session)
    }

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
            self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(());
        }
        let previous_tail = match self.checkpoint {
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
            Err(_) => {
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
        self.binding = next_binding;
        if self.persistence.advance_checkpoint(checkpoint).is_err() {
            let terminal = self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable);
            let _ = self.tail_store.delete_tail(&reference);
            terminal?;
            return Err(ProviderRedactionError::PersistenceUnavailable);
        }
        self.checkpoint = Some(checkpoint);
        staged_safe_material.extend_from_slice(&safe_prefix);
        if let Some(previous) = previous_reference {
            if self.tail_store.delete_tail(&previous).is_err() {
                self.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            }
        }
        Ok(())
    }
}

fn same_authority(expected: TailBinding, actual: TailBinding) -> bool {
    expected.attempt_id() == actual.attempt_id()
        && expected.fencing_token() == actual.fencing_token()
        && expected.policy_epoch() == actual.policy_epoch()
        && expected.matcher_epoch() == actual.matcher_epoch()
        && expected.algorithm_version() == actual.algorithm_version()
}
