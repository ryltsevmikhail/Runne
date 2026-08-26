use crate::{CredentialLifecycleError, ProviderId};

use super::{
    BeginCredentialOperation, BeginCredentialOperationOutcome, BeginCredentialVerification,
    BindCredentialReadback, ClaimCredentialOperation, ClosePreparedCredentialOperation,
    CompleteCredentialOperation, CompleteCredentialVerification, CredentialLifecycleSnapshot,
    CredentialOperationId, CredentialOperationSnapshot, CredentialRecoveryWork,
    CredentialVerificationLease, CredentialVerificationObservation, FailCredentialOperation,
    HardFenceProvider, IssueCredentialTicketDigest, IssuedCredentialTicketAttempt,
    ObserveNativeEffect, TombstoneCredentialOperation,
};

/// Durable port for the authoritative online credential enrollment lifecycle.
pub trait ProviderCredentialEnrollmentStore: Send + Sync {
    /// Begins or exactly replays one enrollment operation.
    fn begin(
        &self,
        input: BeginCredentialOperation,
    ) -> Result<BeginCredentialOperationOutcome, CredentialLifecycleError>;

    /// Records one digest-only ticket attempt.
    fn issue_ticket_attempt(
        &self,
        input: IssueCredentialTicketDigest,
    ) -> Result<IssuedCredentialTicketAttempt, CredentialLifecycleError>;

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
