use super::{CredentialEnrollmentReadback, effect_authority::map_store, readback};
use rand::{RngCore, rngs::OsRng};
use readback::CredentialRecoveryReadback;
use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    BeginCredentialVerification, CompleteCredentialVerification, CredentialNativeEffectDisposition,
    CredentialOperationAction, CredentialOperationId, CredentialOperationState,
    CredentialVerificationKind, CredentialVerificationObservation, CredentialVerificationResult,
    CredentialVerifierRevision, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
};
use runne_secure_store::{ProviderCredentialVerificationReadback, SecureStoreError};

/// Safe writer outcome used only to initiate metadata-only reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 10 inherited broker reports only this diagnostic after its one-shot writer exits"
    )
)]
pub(super) enum WriterExitDiagnostic {
    Exited,
    TimedOut,
}

/// Reader-only gateway for durable enrollment recovery.
pub(crate) struct CredentialEnrollmentRecoveryGateway<'a, S: ?Sized, R: ?Sized> {
    store: &'a S,
    reader: &'a R,
    local_reader: Option<&'a dyn ProviderCredentialVerificationReadback>,
}

impl<'a, S: ?Sized, R: ?Sized> CredentialEnrollmentRecoveryGateway<'a, S, R> {
    pub(crate) const fn new(store: &'a S, reader: &'a R) -> Self {
        Self {
            store,
            reader,
            local_reader: None,
        }
    }

    // The only non-macOS caller is the real-store recovery test, which compiles
    // under the `test-support` feature.
    #[cfg(any(
        all(test, feature = "test-support"),
        all(target_os = "macos", feature = "desktop-protected")
    ))]
    pub(crate) const fn new_with_local(
        store: &'a S,
        reader: &'a R,
        local_reader: &'a dyn ProviderCredentialVerificationReadback,
    ) -> Self {
        Self {
            store,
            reader,
            local_reader: Some(local_reader),
        }
    }
}

impl<S, R> CredentialEnrollmentRecoveryGateway<'_, S, R>
where
    S: ProviderCredentialEnrollmentStore + ?Sized,
    R: CredentialEnrollmentReadback + ?Sized,
{
    /// Reconciles all store-selected work without issuing a ticket or writer authority.
    pub(crate) fn reconcile_online(
        &self,
        now_high_water: i64,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let work = self
            .store
            .reconcile_online(now_high_water)
            .map_err(map_store)?;
        for work in work {
            self.reconcile_work(&work, now_high_water)?;
        }
        Ok(())
    }

    /// Writer exit cannot determine success; it only enters the same readback path.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the Task 10 inherited broker invokes this after its one-shot writer exits"
        )
    )]
    pub(super) fn reconcile_after_writer_exit(
        &self,
        now_high_water: i64,
        _diagnostic: WriterExitDiagnostic,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        self.reconcile_online(now_high_water)
    }

    fn reconcile_work(
        &self,
        work: &runne_provider::CredentialRecoveryWork,
        now_high_water: i64,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let operation = work.operation();
        if !readback::supported(operation.action()) {
            return Err(ProviderCredentialEnrollmentHostError::Unsupported);
        }
        if operation.state() == CredentialOperationState::Claimed {
            self.store
                .mark_native_effect_observed(ObserveNativeEffect::new(
                    operation.operation_id(),
                    CredentialNativeEffectDisposition::PossibleEffect,
                ))
                .map_err(map_store)?;
        }
        let readback = match operation.state() {
            CredentialOperationState::Claimed | CredentialOperationState::NativeEffectObserved => {
                let command = work
                    .command()
                    .ok_or(ProviderCredentialEnrollmentHostError::InvariantViolation)?;
                match self.reader.observe_recovery(operation, command)? {
                    CredentialRecoveryReadback::Bound(readback) => {
                        let bound = self.store.bind_readback(readback).map_err(map_store)?;
                        if bound.state() == CredentialOperationState::Failed {
                            return Ok(());
                        }
                        readback::persisted(&bound)?
                    }
                    CredentialRecoveryReadback::VerifiedAbsence(absence) => {
                        self.store
                            .fail_with_verified_absence(absence)
                            .map_err(map_store)?;
                        return Ok(());
                    }
                }
            }
            CredentialOperationState::ReadbackVerified => readback::persisted(operation)?,
            _ => return Err(ProviderCredentialEnrollmentHostError::InvariantViolation),
        };
        let lifecycle = self
            .store
            .lifecycle_snapshot(operation.provider())
            .map_err(map_store)?;
        let completion = readback::completion(operation, readback, lifecycle, now_high_water)?;
        let completed = self
            .store
            .complete_with_receipt(completion)
            .map_err(map_store)?;
        if completed.action() == CredentialOperationAction::Pair
            && let Some(local_reader) = self.local_reader
        {
            self.verify_activated_version(operation.provider(), now_high_water, local_reader)?;
        }
        // Best-effort retirement marker for a verified legacy cleanup. The
        // receipt, consumed linkage and active destination are already durable
        // at this point, and COMPLETED stays an accepted terminal form, so a
        // lost race or a transient store failure here must not turn the
        // finished operation into a reported error.
        if completed.action() == runne_provider::CredentialOperationAction::LegacySourceCleanup
            && let Ok(tombstone) = runne_provider::TombstoneCredentialOperation::new(
                completed.operation_id(),
                CredentialOperationState::Completed,
            )
        {
            let _ = self.store.tombstone(tombstone);
        }
        Ok(())
    }

    fn verify_activated_version(
        &self,
        provider: &runne_provider::ProviderId,
        now_high_water: i64,
        local_reader: &dyn ProviderCredentialVerificationReadback,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let current = self
            .store
            .current_verification_context(provider)
            .map_err(map_store)?;
        let mut bytes = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        let observation_id = CredentialOperationId::from_bytes(bytes)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        let proof = current.active_binding_digest();
        let lease = self
            .store
            .begin_verification(
                BeginCredentialVerification::new(
                    observation_id,
                    None,
                    provider.clone(),
                    CredentialVerificationKind::Local,
                    current.lifecycle_revision(),
                    current.fence(),
                    current.readiness_revision(),
                    current.release_tuple_digest(),
                    proof,
                    CredentialVerifierRevision::new(1)
                        .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                    now_high_water,
                    now_high_water
                        .checked_add(30)
                        .ok_or(ProviderCredentialEnrollmentHostError::Unavailable)?,
                )
                .map_err(|_| ProviderCredentialEnrollmentHostError::InvalidRequest)?,
            )
            .map_err(map_store)?;
        let result = local_reader
            .verify_local(&lease)
            .unwrap_or_else(map_local_error);
        self.store
            .complete_verification(CompleteCredentialVerification::new(
                CredentialVerificationObservation::new(observation_id, result, now_high_water)
                    .map_err(|_| ProviderCredentialEnrollmentHostError::InvariantViolation)?,
                current.lifecycle_revision(),
                current.fence(),
            ))
            .map(|_| ())
            .map_err(map_store)
    }
}

fn map_local_error(error: SecureStoreError) -> CredentialVerificationResult {
    match error {
        SecureStoreError::CredentialAccessDenied
        | SecureStoreError::CredentialIdentityMismatch
        | SecureStoreError::CredentialAclMigrationRequired => {
            CredentialVerificationResult::AccessDenied
        }
        SecureStoreError::UnsupportedSecureStoreBackend => {
            CredentialVerificationResult::Unsupported
        }
        SecureStoreError::ProviderCredentialNotFound => CredentialVerificationResult::Failed,
        _ => CredentialVerificationResult::Unavailable,
    }
}
