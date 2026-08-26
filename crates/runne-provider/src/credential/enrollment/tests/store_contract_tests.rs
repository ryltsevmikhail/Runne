use crate::{CredentialLifecycleError, ProviderId};

use super::super::{
    BeginCredentialOperation, BeginCredentialOperationOutcome, BeginCredentialVerification,
    BindCredentialReadback, ClaimCredentialOperation, ClosePreparedCredentialOperation,
    CompleteCredentialOperation, CompleteCredentialVerification, CredentialLifecycleSnapshot,
    CredentialOperationId, CredentialOperationSnapshot, CredentialRecoveryWork,
    CredentialVerificationLease, CredentialVerificationObservation, FailCredentialOperation,
    HardFenceProvider, IssueCredentialTicketDigest, IssuedCredentialTicketAttempt,
    ObserveNativeEffect, ProviderCredentialEnrollmentStore, TombstoneCredentialOperation,
};

struct PublicEnrollmentStore;

impl ProviderCredentialEnrollmentStore for PublicEnrollmentStore {
    fn begin(
        &self,
        _: BeginCredentialOperation,
    ) -> Result<BeginCredentialOperationOutcome, CredentialLifecycleError> {
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
        unreachable!()
    }

    fn claim(
        &self,
        _: ClaimCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn mark_native_effect_observed(
        &self,
        _: ObserveNativeEffect,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn bind_readback(
        &self,
        _: BindCredentialReadback,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
    }

    fn complete(
        &self,
        _: CompleteCredentialOperation,
    ) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError> {
        unreachable!()
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
        _: TombstoneCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        unreachable!()
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
        unreachable!()
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
    ) -> Result<Vec<CredentialRecoveryWork>, CredentialLifecycleError> {
        unreachable!()
    }
}

#[test]
fn credential_enrollment_store_exposes_the_approved_task_three_port() {
    fn accepts_store(_: &(impl ProviderCredentialEnrollmentStore + ?Sized)) {}

    accepts_store(&PublicEnrollmentStore);
}
