use runne_provider::{CredentialMatcher, ScannerUncertainReason, TailBinding, WithheldTailStore};

use super::super::diagnostics::{
    ProviderRedactionObserver, RedactionFailureKind, RedactionFailureSite, recovery_failure_kind,
    scanner_failure_kind, tail_failure_kind,
};
use super::super::types::{
    ProviderRedactionError, ScannerRecoveryPersistence, ScannerRecoveryPersistenceError,
    map_persistence_error,
};
use super::ProviderRedactionRecovery;

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
        Self::start_with_observer(binding, tail_store, persistence, matcher, None)
    }

    /// Starts a scanner session and reports only closed failure codes to an optional observer.
    pub fn start_with_observer(
        binding: TailBinding,
        tail_store: &'a T,
        persistence: &'a P,
        matcher: &'a M,
        observer: Option<&'a dyn ProviderRedactionObserver>,
    ) -> Result<Self, ProviderRedactionError> {
        let mut session = Self {
            tail_store,
            persistence,
            matcher,
            binding,
            checkpoint: None,
            disposition: None,
            observer,
        };
        match persistence.load(binding.attempt_id()) {
            Ok(None) => {
                if let Err(error) = tail_store.purge_orphaned_tails(binding, None) {
                    session.observe_failure(
                        RedactionFailureSite::StartPurge,
                        tail_failure_kind(error),
                    );
                    session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                    return Ok(session);
                }
            }
            Ok(Some(_)) => {
                session.observe_failure(
                    RedactionFailureSite::StartRecoveryLoad,
                    RedactionFailureKind::RecoveryConflict,
                );
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Ok(session);
            }
            Err(
                error @ (ScannerRecoveryPersistenceError::Corrupt
                | ScannerRecoveryPersistenceError::Conflict),
            ) => {
                session.observe_failure(
                    RedactionFailureSite::StartRecoveryLoad,
                    recovery_failure_kind(error),
                );
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Ok(session);
            }
            Err(error @ ScannerRecoveryPersistenceError::Unavailable) => {
                session.observe_failure(
                    RedactionFailureSite::StartRecoveryLoad,
                    recovery_failure_kind(error),
                );
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Err(ProviderRedactionError::PersistenceUnavailable);
            }
        }
        match matcher.epoch() {
            Ok(epoch) if epoch == binding.matcher_epoch() => {}
            Ok(_) => session.fail(ScannerUncertainReason::CredentialMatcherUnavailable)?,
            Err(error) => {
                session.observe_failure(
                    RedactionFailureSite::StartMatcherValidation,
                    scanner_failure_kind(error),
                );
                session.terminate_scanner_error(error)?;
            }
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
        Self::restart_with_observer(binding, tail_store, persistence, matcher, None)
    }

    /// Restarts a scanner session and reports only closed failure codes to an optional observer.
    pub fn restart_with_observer(
        binding: TailBinding,
        tail_store: &'a T,
        persistence: &'a P,
        matcher: &'a M,
        observer: Option<&'a dyn ProviderRedactionObserver>,
    ) -> Result<Self, ProviderRedactionError> {
        let mut session = Self {
            tail_store,
            persistence,
            matcher,
            binding,
            checkpoint: None,
            disposition: None,
            observer,
        };
        let record = match persistence.load(binding.attempt_id()) {
            Ok(Some(record)) => record,
            Ok(None) => {
                session.observe_failure(
                    RedactionFailureSite::RestartRecoveryLoad,
                    RedactionFailureKind::RecoveryMissing,
                );
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Ok(session);
            }
            Err(error @ ScannerRecoveryPersistenceError::Conflict) => {
                session.observe_failure(
                    RedactionFailureSite::RestartRecoveryLoad,
                    recovery_failure_kind(error),
                );
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Ok(session);
            }
            Err(error @ ScannerRecoveryPersistenceError::Corrupt) => {
                session.observe_failure(
                    RedactionFailureSite::RestartRecoveryLoad,
                    recovery_failure_kind(error),
                );
                let disposition = persistence
                    .terminalize_corrupt_checkpoint(binding)
                    .map_err(map_persistence_error)?;
                session.disposition = Some(disposition);
                session.purge_all_tails()?;
                return Ok(session);
            }
            Err(error @ ScannerRecoveryPersistenceError::Unavailable) => {
                session.observe_failure(
                    RedactionFailureSite::RestartRecoveryLoad,
                    recovery_failure_kind(error),
                );
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
                return Err(ProviderRedactionError::PersistenceUnavailable);
            }
        };
        let durable_binding = record.binding();
        session.binding = durable_binding;
        if !same_authority(binding, durable_binding) {
            session.observe_failure(
                RedactionFailureSite::RestartAuthorityBinding,
                RedactionFailureKind::BindingMismatch,
            );
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        }
        if let Some(disposition) = record.disposition() {
            session.disposition = Some(disposition);
            if let Err(error) = tail_store.purge_orphaned_tails(durable_binding, None) {
                session.observe_failure(
                    RedactionFailureSite::RestartTailPurge,
                    tail_failure_kind(error),
                );
                session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            }
            return Ok(session);
        }
        let Some(checkpoint) = record.checkpoint() else {
            session.observe_failure(
                RedactionFailureSite::RestartCheckpointValidation,
                RedactionFailureKind::CheckpointMismatch,
            );
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        };
        let stored = checkpoint.binding();
        if durable_binding != stored
            || record.durable_cursor() != stored.cursor()
            || record.durable_safe_prefix_high_water() != checkpoint.safe_prefix_high_water()
            || record.durable_checkpoint_digest() != Some(checkpoint.digest())
        {
            session.observe_failure(
                RedactionFailureSite::RestartCheckpointValidation,
                RedactionFailureKind::CheckpointMismatch,
            );
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
                session.observe_failure(
                    RedactionFailureSite::RestartMatcherValidation,
                    scanner_failure_kind(error),
                );
                session.terminate_scanner_error(error)?;
                return Ok(session);
            }
        }
        if let Err(error) = tail_store.load_tail(&checkpoint.tail_reference(), stored) {
            session.observe_failure(
                RedactionFailureSite::RestartTailLoad,
                tail_failure_kind(error),
            );
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        }
        if let Err(error) =
            tail_store.purge_orphaned_tails(stored, Some(checkpoint.tail_reference()))
        {
            session.observe_failure(
                RedactionFailureSite::RestartTailPurge,
                tail_failure_kind(error),
            );
            session.fail(ScannerUncertainReason::CheckpointSecretStateUnavailable)?;
            return Ok(session);
        }
        session.binding = stored;
        session.checkpoint = Some(checkpoint);
        Ok(session)
    }
}

fn same_authority(expected: TailBinding, actual: TailBinding) -> bool {
    expected.attempt_id() == actual.attempt_id()
        && expected.fencing_token() == actual.fencing_token()
        && expected.policy_epoch() == actual.policy_epoch()
        && expected.matcher_epoch() == actual.matcher_epoch()
        && expected.algorithm_version() == actual.algorithm_version()
}
