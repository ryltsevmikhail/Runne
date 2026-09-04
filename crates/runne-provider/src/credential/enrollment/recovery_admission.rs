use std::sync::Arc;

use super::{
    ContinuationBindingDigest, CredentialBindingDigest, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialOperationId,
    CredentialOperationSnapshot, DesktopSupervisorGeneration, ProtectedSessionId,
    ReleaseManifestDigest, authority::EnrollmentAuthoritySeal,
};

/// Internal admission input. Possessing this value is not effect authority.
/// Session, release and continuation measurements must share the store's seal.
#[derive(Clone, Debug)]
pub struct CredentialCleanupRecoveryRequest {
    pub(crate) operation: CredentialOperationId,
    pub(crate) owner: CredentialInstallationOwnerId,
    pub(crate) release: ReleaseManifestDigest,
    pub(crate) session: ProtectedSessionId,
    pub(crate) supervisor: DesktopSupervisorGeneration,
    pub(crate) database_generation: u64,
    pub(crate) lifecycle: CredentialLifecycleRevision,
    pub(crate) fence: CredentialFence,
    pub(crate) continuation: ContinuationBindingDigest,
    pub(crate) ttl_seconds: u64,
}

impl CredentialCleanupRecoveryRequest {
    /// Packages admitted host evidence; the store validates it before any writes.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        operation: CredentialOperationId,
        owner: CredentialInstallationOwnerId,
        release: ReleaseManifestDigest,
        session: ProtectedSessionId,
        supervisor: DesktopSupervisorGeneration,
        database_generation: u64,
        lifecycle: CredentialLifecycleRevision,
        fence: CredentialFence,
        continuation: ContinuationBindingDigest,
        ttl_seconds: u64,
    ) -> Self {
        Self {
            operation,
            owner,
            release,
            session,
            supervisor,
            database_generation,
            lifecycle,
            fence,
            continuation,
            ttl_seconds,
        }
    }
    /// Exact durable operation to resume without retry-as-new.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation
    }
    /// Authenticated installation owner.
    pub const fn owner(&self) -> CredentialInstallationOwnerId {
        self.owner
    }
    /// Qualified installed release digest.
    pub fn release_digest(&self) -> CredentialBindingDigest {
        self.release.digest()
    }
    /// Current protected-session digest.
    pub fn session_digest(&self) -> CredentialBindingDigest {
        self.session.digest()
    }
    /// Current admitted supervisor generation.
    pub fn supervisor_generation(&self) -> u64 {
        self.supervisor.generation()
    }
    /// Current admitted database generation.
    pub const fn database_generation(&self) -> u64 {
        self.database_generation
    }
    /// Expected current lifecycle, including the already-committed revoke fence.
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.lifecycle
    }
    /// Expected current credential fence.
    pub const fn credential_fence(&self) -> CredentialFence {
        self.fence
    }
    /// Fresh daemon-generated proof digest, never derived from the operation ID.
    pub fn continuation_digest(&self) -> CredentialBindingDigest {
        self.continuation.digest()
    }
    /// Requested lease duration, validated and applied to the store clock.
    pub const fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }
}

/// Move-only witness issued after a committed recovery-admission transaction.
/// No replay or metadata query may reconstruct this value.
#[must_use]
pub struct AcceptedCredentialCleanupRecovery {
    pub(crate) seal: Arc<EnrollmentAuthoritySeal>,
    pub(crate) request: CredentialCleanupRecoveryRequest,
    pub(crate) operation: CredentialOperationSnapshot,
    pub(crate) attempt: u64,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
}

impl AcceptedCredentialCleanupRecovery {
    /// Exact accepted bindings; metadata alone cannot reproduce this witness.
    pub fn request(&self) -> &CredentialCleanupRecoveryRequest {
        &self.request
    }
    /// Snapshot bound to this admission.
    pub fn operation(&self) -> &CredentialOperationSnapshot {
        &self.operation
    }
    /// Durable accept-once sequence number.
    pub const fn attempt(&self) -> u64 {
        self.attempt
    }
    /// Store-clock admission high water.
    pub const fn issued_at(&self) -> i64 {
        self.issued_at
    }
    /// Exclusive store-clock deadline for the fresh recovery lease.
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }
}

#[cfg(test)]
#[path = "recovery_admission_tests.rs"]
mod tests;
