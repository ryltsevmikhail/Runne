use runne_domain::id::{CommandId, IdempotencyKey};

use crate::{CredentialVersionRef, ProviderId};

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
        if !valid {
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
}
