use crate::{CredentialVersionRef, ProviderId};

use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt,
};

/// Protected user-authorized request to begin one public enrollment action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeginCredentialOperation {
    operation_id: CredentialOperationId,
    provider_id: ProviderId,
    action: CredentialOperationAction,
    credential_version: CredentialVersionRef,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
}

impl BeginCredentialOperation {
    /// Validates provider/version identity and the public begin action vocabulary.
    pub fn new(
        operation_id: CredentialOperationId,
        provider_id: ProviderId,
        action: CredentialOperationAction,
        credential_version: CredentialVersionRef,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
    ) -> Result<Self, CredentialEnrollmentError> {
        if credential_version.provider() != &provider_id
            || !matches!(
                action,
                CredentialOperationAction::Pair
                    | CredentialOperationAction::Revoke
                    | CredentialOperationAction::MigrateLegacy
            )
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            provider_id,
            action,
            credential_version,
            expected_lifecycle_revision,
            expected_prior_fence,
        })
    }

    /// Returns the durable operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the provider identity.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Returns the public operation action.
    pub const fn action(&self) -> CredentialOperationAction {
        self.action
    }
    /// Returns the exact target version.
    pub const fn credential_version(&self) -> &CredentialVersionRef {
        &self.credential_version
    }
    /// Returns the expected lifecycle revision.
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }
    /// Returns the expected provider fence.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
}

/// Validated operation data paired with independent measurements for claim hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimCredentialOperation {
    operation_id: CredentialOperationId,
    ticket_attempt: CredentialTicketAttempt,
    ticket_digest: CredentialBindingDigest,
    provider_id: ProviderId,
    action: CredentialOperationAction,
    credential_version: CredentialVersionRef,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    database_generation: u64,
    desktop_supervisor_generation: u64,
    issued_at_high_water: i64,
    expires_at_high_water: i64,
}

impl ClaimCredentialOperation {
    /// Validates the exact operation/ticket/lifecycle tuple before claim binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: CredentialOperationId,
        ticket_attempt: CredentialTicketAttempt,
        ticket_digest: CredentialBindingDigest,
        provider_id: ProviderId,
        action: CredentialOperationAction,
        credential_version: CredentialVersionRef,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
        database_generation: u64,
        desktop_supervisor_generation: u64,
        issued_at_high_water: i64,
        expires_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if credential_version.provider() != &provider_id
            || database_generation == 0
            || desktop_supervisor_generation == 0
            || issued_at_high_water < 0
            || expires_at_high_water <= issued_at_high_water
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            ticket_attempt,
            ticket_digest,
            provider_id,
            action,
            credential_version,
            expected_lifecycle_revision,
            expected_prior_fence,
            database_generation,
            desktop_supervisor_generation,
            issued_at_high_water,
            expires_at_high_water,
        })
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the ticket attempt.
    pub const fn ticket_attempt(&self) -> CredentialTicketAttempt {
        self.ticket_attempt
    }
    /// Returns the durable ticket digest.
    pub const fn ticket_digest(&self) -> CredentialBindingDigest {
        self.ticket_digest
    }
    /// Returns the provider identity.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Returns the action.
    pub const fn action(&self) -> CredentialOperationAction {
        self.action
    }
    /// Returns the target credential version.
    pub const fn credential_version(&self) -> &CredentialVersionRef {
        &self.credential_version
    }
    /// Returns the lifecycle revision.
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }
    /// Returns the prior fence.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
    /// Returns the database generation.
    pub const fn database_generation(&self) -> u64 {
        self.database_generation
    }
    /// Returns the desktop supervisor generation.
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.desktop_supervisor_generation
    }
    /// Returns the issue high-water timestamp.
    pub const fn issued_at_high_water(&self) -> i64 {
        self.issued_at_high_water
    }
    /// Returns the expiry high-water timestamp.
    pub const fn expires_at_high_water(&self) -> i64 {
        self.expires_at_high_water
    }
}
