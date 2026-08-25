use runne_domain::id::{CommandId, IdempotencyKey};

use crate::{CredentialVersionRef, ProviderId};

use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt,
};

/// Protected user-authorized request to begin one public enrollment action.
#[derive(Debug, PartialEq, Eq)]
pub struct BeginCredentialOperation {
    command_id: CommandId,
    idempotency_key: IdempotencyKey,
    operation_id: CredentialOperationId,
    provider_id: ProviderId,
    action: CredentialOperationAction,
    allocated_credential_version: Option<CredentialVersionRef>,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    begin_proof_digest: CredentialBindingDigest,
}

impl BeginCredentialOperation {
    /// Validates only public Pair or MigrateLegacy requests with a provider-owned allocation, or
    /// Revoke requests without one; raw proof bytes are never accepted.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command_id: CommandId,
        idempotency_key: IdempotencyKey,
        operation_id: CredentialOperationId,
        provider_id: ProviderId,
        action: CredentialOperationAction,
        allocated_credential_version: Option<CredentialVersionRef>,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
        begin_proof_digest: CredentialBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        let allocation_is_valid = match action {
            CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => {
                allocated_credential_version
                    .as_ref()
                    .is_some_and(|version| version.provider() == &provider_id)
            }
            CredentialOperationAction::Revoke => allocated_credential_version.is_none(),
            _ => false,
        };
        if !allocation_is_valid {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            command_id,
            idempotency_key,
            operation_id,
            provider_id,
            action,
            allocated_credential_version,
            expected_lifecycle_revision,
            expected_prior_fence,
            begin_proof_digest,
        })
    }

    /// Returns the canonical command replay identity.
    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }

    /// Returns the canonical bounded idempotency key.
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
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

    /// Returns the allocated version when the action creates one.
    pub const fn allocated_credential_version(&self) -> Option<&CredentialVersionRef> {
        self.allocated_credential_version.as_ref()
    }

    /// Returns the expected lifecycle revision.
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }

    /// Returns the expected provider fence.
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }

    /// Returns the accepted begin-proof digest.
    pub const fn begin_proof_digest(&self) -> CredentialBindingDigest {
        self.begin_proof_digest
    }
}

/// Digest-only claim input bound to one ticket, process, release, and expiry.
#[derive(Debug, PartialEq, Eq)]
pub struct ClaimCredentialOperation {
    operation_id: CredentialOperationId,
    ticket_attempt: CredentialTicketAttempt,
    ticket_digest: CredentialBindingDigest,
    continuation_binding_digest: CredentialBindingDigest,
    process_release_binding_digest: CredentialBindingDigest,
    provider_id: ProviderId,
    action: CredentialOperationAction,
    allocated_credential_version: Option<CredentialVersionRef>,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    database_generation: u64,
    desktop_supervisor_generation: u64,
    issued_at_high_water: i64,
    expires_at_high_water: i64,
}

impl ClaimCredentialOperation {
    /// Validates the exact operation/ticket/lifecycle tuple before claim CAS.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: CredentialOperationId,
        ticket_attempt: CredentialTicketAttempt,
        ticket_digest: CredentialBindingDigest,
        continuation_binding_digest: CredentialBindingDigest,
        process_release_binding_digest: CredentialBindingDigest,
        provider_id: ProviderId,
        action: CredentialOperationAction,
        allocated_credential_version: Option<CredentialVersionRef>,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
        database_generation: u64,
        desktop_supervisor_generation: u64,
        issued_at_high_water: i64,
        expires_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if allocated_credential_version
            .as_ref()
            .is_some_and(|version| version.provider() != &provider_id)
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
            continuation_binding_digest,
            process_release_binding_digest,
            provider_id,
            action,
            allocated_credential_version,
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
    /// Returns the accepted continuation binding digest.
    pub const fn continuation_binding_digest(&self) -> CredentialBindingDigest {
        self.continuation_binding_digest
    }
    /// Returns the complete process/release claim binding digest.
    pub const fn process_release_binding_digest(&self) -> CredentialBindingDigest {
        self.process_release_binding_digest
    }
    /// Returns the provider identity.
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    /// Returns the action.
    pub const fn action(&self) -> CredentialOperationAction {
        self.action
    }
    /// Returns the allocated version, when this action allocates one.
    pub const fn allocated_credential_version(&self) -> Option<&CredentialVersionRef> {
        self.allocated_credential_version.as_ref()
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
