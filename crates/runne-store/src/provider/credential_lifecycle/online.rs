#[path = "online/begin.rs"]
mod begin;
#[path = "online/claim.rs"]
mod claim;
#[path = "online/compatibility_mirror.rs"]
mod compatibility_mirror;
#[path = "online/complete.rs"]
mod complete;
#[path = "online/completion_receipt.rs"]
mod completion_receipt;
#[path = "online/head.rs"]
mod head;
#[path = "online/readback.rs"]
mod readback;
#[path = "online/readiness_observation.rs"]
mod readiness_observation;
#[path = "online/recovery.rs"]
mod recovery;
#[path = "online/rows.rs"]
mod rows;
#[path = "online/verification.rs"]
mod verification;

use runne_provider::ProviderCredentialEnrollmentStore;

impl ProviderCredentialEnrollmentStore for SqliteProviderCredentialLifecycleStore {
    fn begin(
        &self,
        input: runne_provider::BeginCredentialOperation,
    ) -> Result<
        runne_provider::BeginCredentialOperationOutcome,
        runne_provider::CredentialLifecycleError,
    > {
        begin::begin(self, input)
    }
    fn issue_ticket_attempt(
        &self,
        input: runne_provider::IssueCredentialTicketDigest,
    ) -> Result<
        runne_provider::IssuedCredentialTicketAttempt,
        runne_provider::CredentialLifecycleError,
    > {
        claim::issue_ticket(self, input)
    }
    fn begin_admission_snapshot(
        &self,
        provider: &runne_provider::ProviderId,
    ) -> Result<runne_provider::CredentialLifecycleSnapshot, runne_provider::CredentialLifecycleError>
    {
        begin::admission_snapshot(self, provider)
    }
    fn claim(
        &self,
        input: runne_provider::ClaimCredentialOperation,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError>
    {
        claim::claim(self, input)
    }
    fn mark_native_effect_observed(
        &self,
        input: runne_provider::ObserveNativeEffect,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError>
    {
        readback::observe(self, input)
    }
    fn bind_readback(
        &self,
        input: runne_provider::BindCredentialReadback,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError>
    {
        readback::bind(self, input)
    }
    fn complete(
        &self,
        input: runne_provider::CompleteCredentialOperation,
    ) -> Result<runne_provider::CredentialLifecycleSnapshot, runne_provider::CredentialLifecycleError>
    {
        self.complete_with_receipt(input)
            .map(|receipt| receipt.successor())
    }
    fn complete_with_receipt(
        &self,
        input: runne_provider::CompleteCredentialOperation,
    ) -> Result<runne_provider::CredentialCompletionReceipt, runne_provider::CredentialLifecycleError>
    {
        complete::complete(self, input)
    }
    fn cancel_before_claim(
        &self,
        input: runne_provider::ClosePreparedCredentialOperation,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError>
    {
        readback::close(
            self,
            input,
            runne_provider::CredentialOperationState::Cancelled,
        )
    }
    fn expire_before_claim(
        &self,
        input: runne_provider::ClosePreparedCredentialOperation,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError>
    {
        readback::close(
            self,
            input,
            runne_provider::CredentialOperationState::Expired,
        )
    }
    fn fail_with_verified_absence(
        &self,
        input: runne_provider::FailCredentialOperation,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError>
    {
        readback::fail(self, input)
    }
    fn tombstone(
        &self,
        input: runne_provider::TombstoneCredentialOperation,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError>
    {
        readback::tombstone(self, input)
    }
    fn load_operation(
        &self,
        operation: runne_provider::CredentialOperationId,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError>
    {
        readback::load(self, operation)
    }
    fn lifecycle_snapshot(
        &self,
        provider: &runne_provider::ProviderId,
    ) -> Result<runne_provider::CredentialLifecycleSnapshot, runne_provider::CredentialLifecycleError>
    {
        complete::lifecycle(self, provider)
    }
    fn hard_fence_provider(
        &self,
        input: runne_provider::HardFenceProvider,
    ) -> Result<runne_provider::CredentialLifecycleSnapshot, runne_provider::CredentialLifecycleError>
    {
        complete::hard_fence(self, input)
    }
    fn begin_verification(
        &self,
        input: runne_provider::BeginCredentialVerification,
    ) -> Result<runne_provider::CredentialVerificationLease, runne_provider::CredentialLifecycleError>
    {
        verification::begin(self, input)
    }
    fn complete_verification(
        &self,
        input: runne_provider::CompleteCredentialVerification,
    ) -> Result<
        runne_provider::CredentialVerificationObservation,
        runne_provider::CredentialLifecycleError,
    > {
        verification::complete(self, input)
    }
    fn reconcile_online(
        &self,
        now: i64,
    ) -> Result<Vec<runne_provider::CredentialRecoveryWork>, runne_provider::CredentialLifecycleError>
    {
        recovery::reconcile(self, now)
    }
}

#[cfg(test)]
#[path = "online/admission_tests.rs"]
mod online_admission_tests;
#[cfg(test)]
#[path = "online/begin_admission_tests.rs"]
mod online_begin_admission_tests;
#[cfg(test)]
#[path = "online/claim_test_support.rs"]
pub(crate) mod online_claim_test_support;
#[cfg(test)]
#[path = "online/completion_tests.rs"]
mod online_completion_tests;
#[cfg(test)]
#[path = "online/head_decoder_tests.rs"]
mod online_head_decoder_tests;
#[cfg(test)]
#[path = "online/legacy_cleanup_tests.rs"]
mod online_legacy_cleanup_tests;
#[cfg(test)]
#[path = "online/provenance_tests.rs"]
mod online_provenance_tests;
#[cfg(test)]
#[path = "online/migration_provenance_tests.rs"]
mod online_migration_provenance_tests;
#[cfg(test)]
#[path = "online/readback_tests.rs"]
mod online_readback_tests;
#[cfg(test)]
#[path = "online/recovery_tests.rs"]
mod online_recovery_tests;
#[cfg(test)]
#[path = "online/retired_cleanup_tests.rs"]
mod online_retired_cleanup_tests;
#[cfg(test)]
#[path = "online/replay_tests.rs"]
mod online_replay_tests;
#[cfg(test)]
#[path = "online/revoke_tests.rs"]
mod online_revoke_tests;
#[cfg(test)]
#[path = "online/test_support.rs"]
pub(crate) mod online_test_support;
#[cfg(test)]
#[path = "online/tests.rs"]
mod online_tests;
#[cfg(test)]
#[path = "online/ticket_expiry_tests.rs"]
mod online_ticket_expiry_tests;
#[cfg(test)]
#[path = "online/verification_tests.rs"]
mod online_verification_tests;
#[cfg(test)]
#[path = "online/versionless_claim_tests.rs"]
mod online_versionless_claim_tests;
