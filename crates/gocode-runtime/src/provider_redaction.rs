//! Pre-journal provider-byte withholding and fail-closed restart orchestration.
mod types;

pub use types::{
    ProviderRedactionError, ScannerRecoveryPersistence, ScannerRecoveryPersistenceError,
    ScannerRecoveryRecord,
};

use gocode_provider::{
    CredentialMatcher, ScannerCheckpoint, ScannerError, ScannerTerminalDisposition,
    ScannerUncertainReason, TailBinding, WithheldTailStore, scan_provider_chunk,
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
        if matcher.epoch().ok() != Some(binding.matcher_epoch()) {
            session.fail(ScannerUncertainReason::CredentialMatcherUnavailable)?;
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
            Ok(None)
            | Err(
                ScannerRecoveryPersistenceError::Corrupt
                | ScannerRecoveryPersistenceError::Conflict,
            ) => {
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Ok(session);
            }
            Err(_) => return Err(ProviderRedactionError::PersistenceUnavailable),
        };
        let durable_binding = record.binding();
        session.binding = durable_binding;
        if !same_authority(binding, durable_binding) {
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        }
        if let Some(disposition) = record.disposition() {
            session.disposition = Some(disposition);
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
        {
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        }
        if matcher.epoch().ok() != Some(stored.matcher_epoch()) {
            session.fail(ScannerUncertainReason::CredentialMatcherUnavailable)?;
            return Ok(session);
        }
        if tail_store
            .load_tail(&checkpoint.tail_reference(), stored)
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
        let step = scan_provider_chunk(
            self.matcher,
            self.binding,
            previous_tail,
            provider_bytes,
            high_water,
        )
        .map_err(map_scanner_error)?;
        if let Some(disposition) = step.disposition() {
            self.commit_terminal(disposition)?;
            return Ok(());
        }
        staged_safe_material.extend_from_slice(step.safe_prefix());
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
        let checkpoint = ScannerCheckpoint::new(reference, next_binding, sequence, next_high_water)
            .map_err(map_scanner_error)?;
        self.persistence
            .persist_checkpoint(checkpoint)
            .map_err(map_persistence_error)?;
        self.persistence
            .advance_checkpoint(checkpoint)
            .map_err(map_persistence_error)?;
        self.binding = next_binding;
        self.checkpoint = Some(checkpoint);
        Ok(())
    }

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
        if self.matcher.epoch().ok() != Some(self.binding.matcher_epoch()) {
            self.fail(ScannerUncertainReason::CredentialMatcherUnavailable)?;
            return Ok(());
        }
        match self.matcher.contains_match(&previous) {
            Ok(false) => {}
            Ok(true) => {
                self.fail(ScannerUncertainReason::SecretDetected)?;
                return Ok(());
            }
            Err(ScannerError::MatcherUnavailable) => {
                self.fail(ScannerUncertainReason::CredentialMatcherUnavailable)?;
                return Ok(());
            }
            Err(_) => {
                self.fail(ScannerUncertainReason::RedactionScannerUnavailable)?;
                return Ok(());
            }
        }
        staged_safe_material.extend_from_slice(&previous);
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
        let checkpoint =
            ScannerCheckpoint::new(reference, self.binding, sequence, self.binding.cursor())
                .map_err(map_scanner_error)?;
        self.persistence
            .persist_checkpoint(checkpoint)
            .map_err(map_persistence_error)?;
        self.persistence
            .advance_checkpoint(checkpoint)
            .map_err(map_persistence_error)?;
        self.checkpoint = Some(checkpoint);
        self.commit_terminal(ScannerTerminalDisposition::Completed)
    }

    /// Returns the current opaque checkpoint.
    pub const fn checkpoint(&self) -> Option<ScannerCheckpoint> {
        self.checkpoint
    }
    /// Returns the committed terminal disposition, or `None` while scanning.
    pub const fn disposition(&self) -> Option<ScannerTerminalDisposition> {
        self.disposition
    }

    fn fail(&mut self, reason: ScannerUncertainReason) -> Result<(), ProviderRedactionError> {
        self.commit_terminal(ScannerTerminalDisposition::Uncertain(reason))
    }

    fn commit_terminal(
        &mut self,
        candidate: ScannerTerminalDisposition,
    ) -> Result<(), ProviderRedactionError> {
        let disposition = self
            .disposition
            .map_or(candidate, |current| current.dominant(candidate));
        self.persistence
            .commit_terminal(self.binding, disposition)
            .map_err(map_persistence_error)?;
        self.disposition = Some(disposition);
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

use types::{map_persistence_error, map_scanner_error};
