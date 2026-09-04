use crate::CredentialVersionRef;

use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialOperationSnapshot, CredentialOperationState, CredentialReadbackDisposition,
    CredentialTerminalDisposition,
};

/// Non-secret identity of the consumed import whose legacy source may be cleaned up.
///
/// These facts alone grant no native authority. The durable store must validate
/// the head/cleanup linkage before including them in an authenticated command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialLegacyCleanupBinding {
    import_operation_id: CredentialOperationId,
    import_lifecycle_revision: CredentialLifecycleRevision,
    import_fence: CredentialFence,
    destination: CredentialVersionRef,
    observation_digest: CredentialBindingDigest,
}

impl CredentialLegacyCleanupBinding {
    /// Decodes typed non-secret linkage facts; does not establish durable provenance or authority.
    pub const fn from_parts(
        import_operation_id: CredentialOperationId,
        import_lifecycle_revision: CredentialLifecycleRevision,
        import_fence: CredentialFence,
        destination: CredentialVersionRef,
        observation_digest: CredentialBindingDigest,
    ) -> Self {
        Self {
            import_operation_id,
            import_lifecycle_revision,
            import_fence,
            destination,
            observation_digest,
        }
    }
    /// Extracts immutable source evidence from a successfully completed import.
    ///
    /// # Errors
    /// Rejects any other action, incomplete import, or missing exact readback.
    pub fn from_completed_import(
        import: &CredentialOperationSnapshot,
    ) -> Result<Self, CredentialEnrollmentError> {
        if import.action() != CredentialOperationAction::MigrateLegacy
            || !matches!(
                import.state(),
                CredentialOperationState::Completed | CredentialOperationState::Tombstoned
            )
            || import.terminal_disposition() != Some(CredentialTerminalDisposition::Completed)
            || import.metadata().readback_disposition()
                != Some(CredentialReadbackDisposition::ExactVersion)
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            import_operation_id: import.operation_id(),
            import_lifecycle_revision: import.lifecycle_revision(),
            import_fence: import.fence(),
            destination: import
                .allocated_credential_version()
                .ok_or(CredentialEnrollmentError::InvalidInput)?
                .clone(),
            observation_digest: import
                .metadata()
                .readback_observation_digest()
                .ok_or(CredentialEnrollmentError::InvalidInput)?,
        })
    }
    /// Returns the original import identity.
    pub const fn import_operation_id(&self) -> CredentialOperationId {
        self.import_operation_id
    }
    /// Returns the original expected lifecycle revision.
    pub const fn import_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.import_lifecycle_revision
    }
    /// Returns the original expected provider fence.
    pub const fn import_fence(&self) -> CredentialFence {
        self.import_fence
    }
    /// Returns the immutable destination of the original import.
    pub const fn destination(&self) -> &CredentialVersionRef {
        &self.destination
    }
    /// Returns the persisted source-bound import observation.
    pub const fn observation_digest(&self) -> CredentialBindingDigest {
        self.observation_digest
    }
}
