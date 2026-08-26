use runne_domain::id::{CommandId, IdempotencyKey};

use crate::{CredentialVersionRef, ProviderId};

use super::super::CredentialOperationSnapshot;
use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialOperationAction,
    CredentialOperationId,
};

/// Protected user-authorized request to begin one public enrollment action.
#[derive(Debug, PartialEq, Eq)]
pub struct BeginCredentialOperation {
    command_id: CommandId,
    idempotency_key: IdempotencyKey,
    operation_id: CredentialOperationId,
    installation_owner_id: CredentialInstallationOwnerId,
    provider_id: ProviderId,
    action: CredentialOperationAction,
    allocated_credential_version: Option<CredentialVersionRef>,
    target_credential_version: Option<CredentialVersionRef>,
    expected_lifecycle_revision: CredentialLifecycleRevision,
    expected_prior_fence: CredentialFence,
    begin_proof_digest: CredentialBindingDigest,
    begin_proof_expires_at_high_water: u64,
}

#[allow(missing_docs)]
impl BeginCredentialOperation {
    /// Validates one owner-bound Pair/MigrateLegacy allocation or exact Revoke target.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command_id: CommandId,
        idempotency_key: IdempotencyKey,
        operation_id: CredentialOperationId,
        installation_owner_id: CredentialInstallationOwnerId,
        provider_id: ProviderId,
        action: CredentialOperationAction,
        allocated_credential_version: Option<CredentialVersionRef>,
        target_credential_version: Option<CredentialVersionRef>,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
        begin_proof_digest: CredentialBindingDigest,
        begin_proof_expires_at_high_water: u64,
    ) -> Result<Self, CredentialEnrollmentError> {
        let valid = match action {
            CredentialOperationAction::Pair | CredentialOperationAction::MigrateLegacy => {
                allocated_credential_version
                    .as_ref()
                    .is_some_and(|version| version.provider() == &provider_id)
                    && target_credential_version.is_none()
            }
            CredentialOperationAction::Revoke => {
                allocated_credential_version.is_none()
                    && target_credential_version
                        .as_ref()
                        .is_some_and(|version| version.provider() == &provider_id)
            }
            _ => false,
        };
        if !valid
            || begin_proof_expires_at_high_water == 0
            || begin_proof_expires_at_high_water > i64::MAX as u64
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            command_id,
            idempotency_key,
            operation_id,
            installation_owner_id,
            provider_id,
            action,
            allocated_credential_version,
            target_credential_version,
            expected_lifecycle_revision,
            expected_prior_fence,
            begin_proof_digest,
            begin_proof_expires_at_high_water,
        })
    }

    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    pub const fn installation_owner_id(&self) -> CredentialInstallationOwnerId {
        self.installation_owner_id
    }
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    pub const fn action(&self) -> CredentialOperationAction {
        self.action
    }
    pub const fn allocated_credential_version(&self) -> Option<&CredentialVersionRef> {
        self.allocated_credential_version.as_ref()
    }
    pub const fn target_credential_version(&self) -> Option<&CredentialVersionRef> {
        self.target_credential_version.as_ref()
    }
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.expected_lifecycle_revision
    }
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.expected_prior_fence
    }
    pub const fn begin_proof_digest(&self) -> CredentialBindingDigest {
        self.begin_proof_digest
    }
    pub const fn begin_proof_expires_at_high_water(&self) -> u64 {
        self.begin_proof_expires_at_high_water
    }
}

/// Durable disposition of one proof-bound begin admission.
#[derive(Debug, PartialEq, Eq)]
pub enum BeginCredentialOperationOutcome {
    /// This transaction created the sole durable operation and may mint an effect authority.
    FreshWinner(CredentialOperationSnapshot),
    /// This request exactly projects an already committed durable operation.
    ExactReplay(CredentialOperationSnapshot),
}

impl BeginCredentialOperationOutcome {
    /// Returns the durable projection without exposing effect authority.
    pub const fn snapshot(&self) -> &CredentialOperationSnapshot {
        match self {
            Self::FreshWinner(snapshot) | Self::ExactReplay(snapshot) => snapshot,
        }
    }

    /// Consumes the disposition into its durable projection.
    pub fn into_snapshot(self) -> CredentialOperationSnapshot {
        match self {
            Self::FreshWinner(snapshot) | Self::ExactReplay(snapshot) => snapshot,
        }
    }

    /// Whether this call durably admitted the unique begin effect.
    pub const fn is_fresh_winner(&self) -> bool {
        matches!(self, Self::FreshWinner(_))
    }
}
