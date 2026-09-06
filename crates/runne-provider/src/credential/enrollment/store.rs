use crate::{CredentialLifecycleError, ProviderId};
use runne_domain::id::{CommandId, IdempotencyKey};

use super::{
    AttachCredentialProcess, BeginCredentialOperation, BeginCredentialOperationOutcome,
    BeginCredentialVerification, BindCredentialReadback, ClaimCredentialOperation,
    ClosePreparedCredentialOperation, CompleteCredentialOperation, CompleteCredentialVerification,
    CredentialBindingDigest, CredentialCompletionReceipt, CredentialLifecycleSnapshot,
    CredentialOperationId, CredentialOperationSnapshot, CredentialRecoveryWork,
    CredentialSafeSnapshot, CredentialVerificationContext, CredentialVerificationLease,
    CredentialVerificationObservation, FailCredentialOperation, HardFenceProvider,
    IssueCredentialTicketDigest, IssuedCredentialTicketAttempt, ObserveNativeEffect,
    TombstoneCredentialOperation,
};

/// Durable port for the authoritative online credential enrollment lifecycle.
pub trait ProviderCredentialEnrollmentStore: Send + Sync {
    /// Reads the latest expired, unconsumed cleanup attempt for an exact owner.
    /// Advisory metadata only: supersession must revalidate by exact attempt CAS.
    fn expired_cleanup_recovery_attempt(
        &self,
        _owner: super::CredentialInstallationOwnerId,
        _operation: CredentialOperationId,
    ) -> Result<Option<u64>, CredentialLifecycleError> {
        Err(CredentialLifecycleError::LifecycleClosed)
    }

    /// Replaces only the exact expired, unconsumed recovery attempt.
    /// A fresh sealed request is required; metadata alone grants no authority.
    fn supersede_cleanup_recovery(
        &self,
        _request: super::CredentialCleanupRecoveryRequest,
        _expected_attempt: u64,
    ) -> Result<super::AcceptedCredentialCleanupRecovery, CredentialLifecycleError> {
        Err(CredentialLifecycleError::LifecycleClosed)
    }

    /// Accepts a fresh internal recovery proof once, after fencing prior attempts.
    /// Metadata replay must never reissue the move-only witness.
    fn accept_cleanup_recovery(
        &self,
        _request: super::CredentialCleanupRecoveryRequest,
    ) -> Result<super::AcceptedCredentialCleanupRecovery, CredentialLifecycleError> {
        Err(CredentialLifecycleError::LifecycleClosed)
    }

    /// Reads at most 64 prepared delete operations for an exact owner/provider.
    ///
    /// This metadata query grants no writer or recovery authority. Callers must
    /// authenticate the owner and separately fence any previous writer attempt.
    fn prepared_cleanup_operations(
        &self,
        _owner: super::CredentialInstallationOwnerId,
        _provider: &ProviderId,
    ) -> Result<Vec<CredentialOperationSnapshot>, CredentialLifecycleError> {
        Err(CredentialLifecycleError::LifecycleClosed)
    }

    /// Consumes a store-sealed recovery witness to attach its exact continuation.
    fn attach_cleanup_recovery(
        &self,
        _accepted: super::AcceptedCredentialCleanupRecovery,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
        Err(CredentialLifecycleError::LifecycleClosed)
    }

    /// Begins or exactly replays one enrollment operation.
    fn begin(
        &self,
        input: BeginCredentialOperation,
    ) -> Result<BeginCredentialOperationOutcome, CredentialLifecycleError>;

    /// Returns the prior operation for an already authenticated begin proof.
    ///
    /// Implementations that cannot index this proof may safely return `None`.
    fn find_by_begin_proof(
        &self,
        _proof: CredentialBindingDigest,
    ) -> Result<Option<CredentialOperationSnapshot>, CredentialLifecycleError> {
        Ok(None)
    }

    /// Returns a prior operation for the same durable command identity.
    fn find_by_command(
        &self,
        _command: CommandId,
        _idempotency_key: &IdempotencyKey,
    ) -> Result<Option<CredentialOperationSnapshot>, CredentialLifecycleError> {
        Ok(None)
    }

    /// Attaches one protected writer continuation before broker ticket issuance.
    fn attach_process(
        &self,
        input: AttachCredentialProcess,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError>;

    /// Records one digest-only ticket attempt.
    fn issue_ticket_attempt(
        &self,
        input: IssueCredentialTicketDigest,
    ) -> Result<IssuedCredentialTicketAttempt, CredentialLifecycleError>;

    /// Atomically issues one real ticket attempt and consumes one qualification fence.
    /// Stores must opt in explicitly; ordinary implementations remain closed.
    fn issue_ticket_attempt_with_qualification_fence(
        &self,
        _ticket: IssueCredentialTicketDigest,
        _fence: super::ProviderQualificationAdmissionFence,
    ) -> Result<
        (
            IssuedCredentialTicketAttempt,
            super::ProviderQualificationAdmissionFenceReceipt,
        ),
        CredentialLifecycleError,
    > {
        Err(CredentialLifecycleError::LifecycleClosed)
    }

    /// Creates or loads the initial persisted provider authority snapshot.
    fn begin_admission_snapshot(
        &self,
        provider: &ProviderId,
    ) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError>;

    /// Atomically consumes the ticket and process/release claim binding.
    fn claim(
        &self,
        input: ClaimCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError>;

    /// Records that the bound native mutation may have occurred.
    fn mark_native_effect_observed(
        &self,
        input: ObserveNativeEffect,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError>;

    /// Binds one independent exact readback observation.
    fn bind_readback(
        &self,
        input: BindCredentialReadback,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError>;

    /// Completes one lifecycle transition by revision/fence CAS.
    fn complete(
        &self,
        input: CompleteCredentialOperation,
    ) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError>;

    /// Completes one lifecycle transition and returns its persisted receipt.
    fn complete_with_receipt(
        &self,
        input: CompleteCredentialOperation,
    ) -> Result<CredentialCompletionReceipt, CredentialLifecycleError>;

    /// Cancels an operation before ticket claim.
    fn cancel_before_claim(
        &self,
        input: ClosePreparedCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError>;

    /// Expires an operation before ticket claim.
    fn expire_before_claim(
        &self,
        input: ClosePreparedCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError>;

    /// Fails a claimed operation only with independently verified absence.
    fn fail_with_verified_absence(
        &self,
        input: FailCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError>;

    /// Permanently tombstones a terminal operation.
    fn tombstone(
        &self,
        input: TombstoneCredentialOperation,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError>;

    /// Loads one durable operation, including replay-safe terminal metadata.
    fn load_operation(
        &self,
        operation_id: CredentialOperationId,
    ) -> Result<CredentialOperationSnapshot, CredentialLifecycleError>;

    /// Loads the current provider lifecycle authority snapshot.
    fn lifecycle_snapshot(
        &self,
        provider: &ProviderId,
    ) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError>;

    /// Loads the current metadata-only lifecycle/readiness/verification projection.
    fn safe_snapshot(
        &self,
        provider: &ProviderId,
    ) -> Result<CredentialSafeSnapshot, CredentialLifecycleError>;

    /// Returns the exact current ready binding required to begin verification.
    ///
    /// Stores without durable current-readiness provenance fail closed.
    fn current_verification_context(
        &self,
        _provider: &ProviderId,
    ) -> Result<CredentialVerificationContext, CredentialLifecycleError> {
        Err(CredentialLifecycleError::Conflict)
    }

    /// Permanently fences a provider after a post-admission invariant failure.
    fn hard_fence_provider(
        &self,
        input: HardFenceProvider,
    ) -> Result<CredentialLifecycleSnapshot, CredentialLifecycleError>;

    /// Acquires one verification effect lease.
    fn begin_verification(
        &self,
        input: BeginCredentialVerification,
    ) -> Result<CredentialVerificationLease, CredentialLifecycleError>;

    /// Stores one safe verification observation.
    fn complete_verification(
        &self,
        input: CompleteCredentialVerification,
    ) -> Result<CredentialVerificationObservation, CredentialLifecycleError>;

    /// Returns durable work that must resume without retry-as-new.
    fn reconcile_online(
        &self,
        now_high_water: i64,
    ) -> Result<Vec<CredentialRecoveryWork>, CredentialLifecycleError>;
}
