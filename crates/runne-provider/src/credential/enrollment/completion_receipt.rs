use std::{fmt, sync::Arc};

use crate::{CredentialVersionRef, ProviderId};

use super::{
    CredentialBindingDigest, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleRevision, CredentialLifecycleSnapshot, CredentialOperationAction,
    CredentialOperationId, CredentialQualifiedReleaseTuple, CredentialReadbackDisposition,
    CredentialReadinessRevision, CredentialTicketAttempt, authority::EnrollmentAuthoritySeal,
};

/// Sealed, metadata-only durable proof of one authoritative credential completion.
pub struct CredentialCompletionReceipt {
    operation_id: CredentialOperationId,
    installation_owner_id: CredentialInstallationOwnerId,
    provider_id: ProviderId,
    action: CredentialOperationAction,
    target: Option<CredentialVersionRef>,
    predecessor_lifecycle_revision: CredentialLifecycleRevision,
    predecessor_fence: CredentialFence,
    claimed_ticket_attempt: CredentialTicketAttempt,
    broker_migration_binding_digest: Option<CredentialBindingDigest>,
    qualified_release_tuple: CredentialQualifiedReleaseTuple,
    readback_disposition: CredentialReadbackDisposition,
    readback_observation_digest: CredentialBindingDigest,
    readiness_observation_id: Option<CredentialOperationId>,
    lifecycle: CredentialLifecycleSnapshot,
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl CredentialCompletionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        operation_id: CredentialOperationId,
        installation_owner_id: CredentialInstallationOwnerId,
        provider_id: ProviderId,
        action: CredentialOperationAction,
        target: Option<CredentialVersionRef>,
        predecessor_lifecycle_revision: CredentialLifecycleRevision,
        predecessor_fence: CredentialFence,
        claimed_ticket_attempt: CredentialTicketAttempt,
        broker_migration_binding_digest: Option<CredentialBindingDigest>,
        qualified_release_tuple: CredentialQualifiedReleaseTuple,
        readback_disposition: CredentialReadbackDisposition,
        readback_observation_digest: CredentialBindingDigest,
        readiness_observation_id: Option<CredentialOperationId>,
        lifecycle: CredentialLifecycleSnapshot,
    ) -> Self {
        Self {
            operation_id,
            installation_owner_id,
            provider_id,
            action,
            target,
            predecessor_lifecycle_revision,
            predecessor_fence,
            claimed_ticket_attempt,
            broker_migration_binding_digest,
            qualified_release_tuple,
            readback_disposition,
            readback_observation_digest,
            readiness_observation_id,
            lifecycle,
            seal,
        }
    }

    /// Returns the completed operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the immutable installation owner binding.
    pub const fn installation_owner_id(&self) -> CredentialInstallationOwnerId {
        self.installation_owner_id
    }
    /// Returns the completed provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Returns the closed operation action.
    pub const fn action(&self) -> CredentialOperationAction {
        self.action
    }
    /// Returns the closed broker target when the action has one.
    pub const fn target(&self) -> Option<&CredentialVersionRef> {
        self.target.as_ref()
    }
    /// Returns the predecessor lifecycle revision.
    pub const fn predecessor_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.predecessor_lifecycle_revision
    }
    /// Returns the predecessor provider fence.
    pub const fn predecessor_fence(&self) -> CredentialFence {
        self.predecessor_fence
    }
    /// Returns the claimed one-use ticket attempt.
    pub const fn claimed_ticket_attempt(&self) -> CredentialTicketAttempt {
        self.claimed_ticket_attempt
    }
    /// Returns linked migration provenance when the action requires it.
    pub const fn broker_migration_binding_digest(&self) -> Option<CredentialBindingDigest> {
        self.broker_migration_binding_digest
    }
    /// Returns the qualified release tuple digest.
    pub const fn qualified_release_tuple_digest(&self) -> CredentialBindingDigest {
        self.qualified_release_tuple.digest()
    }
    /// Returns the exact native readback disposition.
    pub const fn readback_disposition(&self) -> CredentialReadbackDisposition {
        self.readback_disposition
    }
    /// Returns the exact native readback observation digest.
    pub const fn readback_observation_digest(&self) -> CredentialBindingDigest {
        self.readback_observation_digest
    }
    /// Returns the exact durable readiness observation identity when completion changes readiness.
    pub const fn readiness_observation_id(&self) -> Option<CredentialOperationId> {
        self.readiness_observation_id
    }
    /// Returns the persisted successor lifecycle snapshot.
    pub const fn lifecycle_snapshot(&self) -> &CredentialLifecycleSnapshot {
        &self.lifecycle
    }
    /// Returns the persisted successor without reading mutable provider head state.
    pub fn successor(&self) -> CredentialLifecycleSnapshot {
        self.lifecycle.clone()
    }
    /// Returns the persisted successor lifecycle revision.
    pub const fn lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.lifecycle.lifecycle_revision()
    }
    /// Returns the persisted successor provider fence.
    pub const fn fence(&self) -> CredentialFence {
        self.lifecycle.fence()
    }
    /// Returns the persisted successor readiness revision.
    pub const fn readiness_revision(&self) -> CredentialReadinessRevision {
        self.lifecycle.readiness_revision()
    }
    /// Returns the persisted successor active credential identity.
    pub const fn active_version(&self) -> Option<&CredentialVersionRef> {
        self.lifecycle.active_version()
    }
    /// Returns the persisted successor next version allocation.
    pub const fn next_credential_version(&self) -> u64 {
        self.lifecycle.next_credential_version()
    }
}

impl fmt::Debug for CredentialCompletionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialCompletionReceipt")
            .field("operation_id", &self.operation_id)
            .field("provider_id", &self.provider_id)
            .field("action", &self.action)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

impl PartialEq for CredentialCompletionReceipt {
    fn eq(&self, other: &Self) -> bool {
        self.operation_id == other.operation_id
            && self.installation_owner_id == other.installation_owner_id
            && self.provider_id == other.provider_id
            && self.action == other.action
            && self.target == other.target
            && self.predecessor_lifecycle_revision == other.predecessor_lifecycle_revision
            && self.predecessor_fence == other.predecessor_fence
            && self.claimed_ticket_attempt == other.claimed_ticket_attempt
            && self.broker_migration_binding_digest == other.broker_migration_binding_digest
            && self.qualified_release_tuple == other.qualified_release_tuple
            && self.readback_disposition == other.readback_disposition
            && self.readback_observation_digest == other.readback_observation_digest
            && self.readiness_observation_id == other.readiness_observation_id
            && self.lifecycle == other.lifecycle
            && Arc::ptr_eq(&self.seal, &other.seal)
    }
}

impl Eq for CredentialCompletionReceipt {}
