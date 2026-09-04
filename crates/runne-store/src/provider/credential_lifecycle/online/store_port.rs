impl ProviderCredentialEnrollmentStore for SqliteProviderCredentialLifecycleStore {
    fn expired_cleanup_recovery_attempt(
        &self,
        owner: runne_provider::CredentialInstallationOwnerId,
        operation: runne_provider::CredentialOperationId,
    ) -> Result<Option<u64>, runne_provider::CredentialLifecycleError> {
        recovery_admission::expired_attempt(self, owner, operation)
    }
    fn supersede_cleanup_recovery(
        &self,
        request: runne_provider::CredentialCleanupRecoveryRequest,
        expected_attempt: u64,
    ) -> Result<runne_provider::AcceptedCredentialCleanupRecovery, runne_provider::CredentialLifecycleError> {
        recovery_admission::supersede(self, request, expected_attempt)
    }
    fn attach_cleanup_recovery(
        &self,
        accepted: runne_provider::AcceptedCredentialCleanupRecovery,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError> {
        attachment::attach_recovery(self, accepted)
    }
    fn accept_cleanup_recovery(
        &self,
        request: runne_provider::CredentialCleanupRecoveryRequest,
    ) -> Result<runne_provider::AcceptedCredentialCleanupRecovery, runne_provider::CredentialLifecycleError> {
        recovery_admission::accept(self, request)
    }
    fn prepared_cleanup_operations(
        &self,
        owner: runne_provider::CredentialInstallationOwnerId,
        provider: &runne_provider::ProviderId,
    ) -> Result<Vec<runne_provider::CredentialOperationSnapshot>, runne_provider::CredentialLifecycleError>
    {
        retired_cleanup::prepared(self, owner, provider)
    }
    fn begin(
        &self,
        input: runne_provider::BeginCredentialOperation,
    ) -> Result<
        runne_provider::BeginCredentialOperationOutcome,
        runne_provider::CredentialLifecycleError,
    > {
        begin::begin(self, input)
    }
    fn find_by_begin_proof(
        &self,
        proof: runne_provider::CredentialBindingDigest,
    ) -> Result<
        Option<runne_provider::CredentialOperationSnapshot>,
        runne_provider::CredentialLifecycleError,
    > {
        begin::find_by_begin_proof(self, proof)
    }
    fn find_by_command(
        &self,
        command: runne_domain::id::CommandId,
        idempotency_key: &runne_domain::id::IdempotencyKey,
    ) -> Result<
        Option<runne_provider::CredentialOperationSnapshot>,
        runne_provider::CredentialLifecycleError,
    > {
        begin::find_by_command(self, command, idempotency_key)
    }
    fn attach_process(
        &self,
        input: runne_provider::AttachCredentialProcess,
    ) -> Result<runne_provider::CredentialOperationSnapshot, runne_provider::CredentialLifecycleError>
    {
        attachment::attach(self, input)
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
    fn safe_snapshot(
        &self,
        provider: &runne_provider::ProviderId,
    ) -> Result<runne_provider::CredentialSafeSnapshot, runne_provider::CredentialLifecycleError>
    {
        safe_projection::load(self, provider)
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
    fn current_verification_context(
        &self,
        provider: &runne_provider::ProviderId,
    ) -> Result<runne_provider::CredentialVerificationContext, runne_provider::CredentialLifecycleError>
    {
        verification_context::load(self, provider)
    }
    fn reconcile_online(
        &self,
        now: i64,
    ) -> Result<Vec<runne_provider::CredentialRecoveryWork>, runne_provider::CredentialLifecycleError>
    {
        recovery::reconcile(self, now)
    }
}
