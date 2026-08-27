use super::{CredentialEnrollmentReadback, effect_authority::map_store, readback};
use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    CredentialNativeEffectDisposition, CredentialOperationState, ObserveNativeEffect,
    ProviderCredentialEnrollmentStore,
};

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
}

impl<'a, S: ?Sized, R: ?Sized> CredentialEnrollmentRecoveryGateway<'a, S, R> {
    pub(crate) const fn new(store: &'a S, reader: &'a R) -> Self {
        Self { store, reader }
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
                let readback = self.reader.observe(operation, command)?;
                let bound = self.store.bind_readback(readback).map_err(map_store)?;
                readback::persisted(&bound)?
            }
            CredentialOperationState::ReadbackVerified => readback::persisted(operation)?,
            _ => return Err(ProviderCredentialEnrollmentHostError::InvariantViolation),
        };
        let lifecycle = self
            .store
            .lifecycle_snapshot(operation.provider())
            .map_err(map_store)?;
        let completion = readback::completion(operation, readback, lifecycle, now_high_water)?;
        self.store
            .complete_with_receipt(completion)
            .map_err(map_store)?;
        Ok(())
    }
}
