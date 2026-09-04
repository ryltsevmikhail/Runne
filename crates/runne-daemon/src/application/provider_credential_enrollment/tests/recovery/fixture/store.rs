use runne_provider::{
    AttachCredentialProcess, BeginCredentialOperation, BeginCredentialOperationOutcome,
    BeginCredentialVerification, BindCredentialReadback, ClaimCredentialOperation,
    ClosePreparedCredentialOperation, CompleteCredentialOperation, CompleteCredentialVerification,
    CredentialCompletionReceipt, CredentialLifecycleError, CredentialLifecycleSnapshot,
    CredentialNativeEffectDisposition, CredentialOperationId, CredentialOperationSnapshot,
    CredentialOperationState, CredentialReadinessDisposition, CredentialSafeSnapshot,
    CredentialVerificationLease, CredentialVerificationObservation, CredentialVerificationSnapshot,
    FailCredentialOperation, HardFenceProvider, IssueCredentialTicketDigest,
    IssuedCredentialTicketAttempt, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
    ProviderId, TombstoneCredentialOperation,
};

use super::{FailurePoint, Fixture};

impl ProviderCredentialEnrollmentStore for Fixture {
    fn begin(
        &self,
        _: BeginCredentialOperation,
    ) -> Result<BeginCredentialOperationOutcome, CredentialLifecycleError> {
        unreachable!()
    }

    fn attach_process(
        &self,
        _: AttachCredentialProcess,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn issue_ticket_attempt(
        &self,
        _: IssueCredentialTicketDigest,
    ) -> Result<IssuedCredentialTicketAttempt, CredentialLifecycleError> {
        unreachable!()
    }

    fn begin_admission_snapshot(
        &self,
        _: &ProviderId,
    ) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
        self.event("begin_admission_snapshot");
        Ok(self.lifecycle())
    }

    fn claim(
        &self,
        _: ClaimCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn mark_native_effect_observed(
        &self,
        input: ObserveNativeEffect,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        self.event("mark");
        if self.failure() == FailurePoint::Mark {
            return Err(CredentialLifecycleError::StoreUnavailable);
        }
        if self.state() != CredentialOperationState::Claimed
            || input.disposition() != CredentialNativeEffectDisposition::PossibleEffect
        {
            return Err(CredentialLifecycleError::Conflict);
        }
        self.transition(CredentialOperationState::NativeEffectObserved, None)
    }

    fn bind_readback(
        &self,
        input: BindCredentialReadback,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        self.event("bind");
        if self.failure() == FailurePoint::Bind {
            return Err(CredentialLifecycleError::StoreUnavailable);
        }
        if self.state() != CredentialOperationState::NativeEffectObserved {
            return Err(CredentialLifecycleError::Conflict);
        }
        self.transition(CredentialOperationState::ReadbackVerified, Some(input))
    }

    fn complete(
        &self,
        _: CompleteCredentialOperation,
    ) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn complete_with_receipt(
        &self,
        input: CompleteCredentialOperation,
    ) -> Result<CredentialCompletionReceipt, CredentialLifecycleError> {
        self.event("complete");
        if self.failure() == FailurePoint::Complete {
            return Err(CredentialLifecycleError::StoreUnavailable);
        }
        if self.state() != CredentialOperationState::ReadbackVerified {
            return Err(CredentialLifecycleError::Conflict);
        }
        let legacy = self.work().operation().action()
            == runne_provider::CredentialOperationAction::LegacySourceCleanup;
        if input.readiness_observation().is_none() != legacy {
            return Err(CredentialLifecycleError::Conflict);
        }
        let receipt = self.receipt_for(&input);
        let persisted = self.receipt_for(&input);
        self.transition(CredentialOperationState::Completed, None)?;
        *self.receipt.lock().unwrap() = Some(persisted);
        Ok(receipt)
    }

    fn cancel_before_claim(
        &self,
        _: ClosePreparedCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn expire_before_claim(
        &self,
        _: ClosePreparedCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn fail_with_verified_absence(
        &self,
        _: FailCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn tombstone(
        &self,
        input: TombstoneCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        self.event("tombstone");
        if self.state() != CredentialOperationState::Completed
            || input.terminal_state() != CredentialOperationState::Completed
        {
            return Err(CredentialLifecycleError::Conflict);
        }
        let current = self.operation.lock().unwrap().clone();
        let mut digest_bytes = [0u8; 32];
        digest_bytes[..16].copy_from_slice(&input.operation_id().as_bytes());
        let metadata = current.metadata().clone().with_tombstone(
            runne_provider::CredentialBindingDigest::from_measured(digest_bytes)
                .map_err(|_| CredentialLifecycleError::CorruptState)?,
        );
        let next = CredentialOperationSnapshot::new(
            current.operation_id(),
            current.provider().clone(),
            current.action(),
            CredentialOperationState::Tombstoned,
            current.allocated_credential_version().cloned(),
            current.target_credential_version().cloned(),
            metadata,
        )
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
        *self.operation.lock().unwrap() = next.clone();
        Ok(next)
    }

    fn load_operation(
        &self,
        _: CredentialOperationId,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn lifecycle_snapshot(
        &self,
        _: &ProviderId,
    ) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
        Ok(self.lifecycle())
    }

    fn safe_snapshot(
        &self,
        _: &ProviderId,
    ) -> Result<runne_provider::CredentialSafeSnapshot, CredentialLifecycleError> {
        self.event("safe_snapshot");
        CredentialSafeSnapshot::new(
            ProviderId::new("openai").unwrap(),
            false,
            runne_provider::CredentialLifecycleRevision::new(1).unwrap(),
            runne_provider::CredentialReadinessRevision::new(1).unwrap(),
            CredentialReadinessDisposition::Missing,
            100,
            CredentialVerificationSnapshot::not_verified(),
        )
        .map_err(|_| CredentialLifecycleError::CorruptState)
    }

    fn hard_fence_provider(
        &self,
        _: HardFenceProvider,
    ) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn begin_verification(
        &self,
        _: BeginCredentialVerification,
    ) -> Result<CredentialVerificationLease, CredentialLifecycleError> {
        unreachable!()
    }

    fn complete_verification(
        &self,
        _: CompleteCredentialVerification,
    ) -> Result<CredentialVerificationObservation, CredentialLifecycleError> {
        unreachable!()
    }

    fn reconcile_online(
        &self,
        _: i64,
    ) -> Result<Vec<runne_provider::CredentialRecoveryWork>, CredentialLifecycleError> {
        self.event("reconcile");
        Ok(vec![self.work()])
    }
}
