use super::super::{
    CredentialBindingDigest, CredentialCompletionReceipt, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialLifecycleSnapshot,
    CredentialMigrationMetadata, CredentialOperationAction, CredentialOperationId,
    CredentialOperationMetadata, CredentialQualifiedReleaseTuple, CredentialReadbackDisposition,
    CredentialTicketAttempt, WriterIdentityMigrationPhase,
};
use super::CredentialEnrollmentStoreAuthority;
use crate::{CredentialVersionRef, ProviderId};
use runne_domain::id::{CommandId, IdempotencyKey};

impl CredentialEnrollmentStoreAuthority {
    /// Hydrates operation metadata only after the store has validated the durable row.
    #[allow(clippy::too_many_arguments)]
    pub fn hydrate_persisted_credential_operation_metadata(
        &self,
        command_id: CommandId,
        idempotency_key: IdempotencyKey,
        installation_owner_id: CredentialInstallationOwnerId,
        expected_lifecycle_revision: CredentialLifecycleRevision,
        expected_prior_fence: CredentialFence,
        begin_proof_digest: CredentialBindingDigest,
        created_at_high_water: i64,
        updated_at_high_water: i64,
        qualified_release_tuple_digest: Option<CredentialBindingDigest>,
        claimed_ticket_attempt: Option<CredentialTicketAttempt>,
    ) -> Result<CredentialOperationMetadata, super::super::CredentialEnrollmentError> {
        let mut metadata = CredentialOperationMetadata::new(
            command_id,
            idempotency_key,
            installation_owner_id,
            expected_lifecycle_revision,
            expected_prior_fence,
            begin_proof_digest,
            created_at_high_water,
            updated_at_high_water,
        )?;
        if let Some(digest) = qualified_release_tuple_digest {
            metadata = metadata.with_qualified_release_tuple(
                CredentialQualifiedReleaseTuple::from_persisted(self.seal.clone(), digest)?,
            );
        }
        if let Some(attempt) = claimed_ticket_attempt {
            metadata = metadata.with_claimed_ticket_attempt(attempt);
        }
        Ok(metadata)
    }

    /// Hydrates one validated, persisted completion receipt under this store authority.
    #[allow(clippy::too_many_arguments)]
    pub fn hydrate_persisted_credential_completion_receipt(
        &self,
        operation_id: CredentialOperationId,
        installation_owner_id: CredentialInstallationOwnerId,
        provider_id: ProviderId,
        action: CredentialOperationAction,
        target: Option<CredentialVersionRef>,
        predecessor_lifecycle_revision: CredentialLifecycleRevision,
        predecessor_fence: CredentialFence,
        claimed_ticket_attempt: CredentialTicketAttempt,
        broker_migration_binding_digest: Option<CredentialBindingDigest>,
        qualified_release_tuple_digest: CredentialBindingDigest,
        readback_disposition: CredentialReadbackDisposition,
        readback_observation_digest: CredentialBindingDigest,
        readiness_observation_id: Option<CredentialOperationId>,
        lifecycle: CredentialLifecycleSnapshot,
    ) -> CredentialCompletionReceipt {
        let tuple = CredentialQualifiedReleaseTuple::from_persisted(
            self.seal.clone(),
            qualified_release_tuple_digest,
        )
        .expect("validated credential binding digest");
        CredentialCompletionReceipt::issue(
            self.seal.clone(),
            operation_id,
            installation_owner_id,
            provider_id,
            action,
            target,
            predecessor_lifecycle_revision,
            predecessor_fence,
            claimed_ticket_attempt,
            broker_migration_binding_digest,
            tuple,
            readback_disposition,
            readback_observation_digest,
            readiness_observation_id,
            lifecycle,
        )
    }

    /// Rehydrates metadata only after the store validates the immutable durable row.
    pub fn hydrate_persisted_credential_migration_metadata(
        &self,
        migration_id: CredentialOperationId,
        phase: WriterIdentityMigrationPhase,
        old_tuple_digest: CredentialBindingDigest,
        new_tuple_digest: CredentialBindingDigest,
        binding_digest: CredentialBindingDigest,
    ) -> CredentialMigrationMetadata {
        CredentialMigrationMetadata::issue(
            self.seal.clone(),
            migration_id,
            phase,
            old_tuple_digest,
            new_tuple_digest,
            binding_digest,
        )
    }
}
