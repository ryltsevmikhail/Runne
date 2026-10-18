use crate::store::StoreTransaction;
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::EventStoreError,
    project_trust::{ProjectTrustEffectLease, ProjectTrustProjectId},
};

impl StoreTransaction {
    /// Holds a current registered trust snapshot after validating this capture.
    pub fn observe_local_command_permission_trust(
        &self,
        binding: &LocalCommandPermissionBindingV1,
    ) -> Result<Box<dyn ProjectTrustEffectLease>, EventStoreError> {
        let assignment = binding.assignment();
        if binding.selection().scope.runtime_authority_id != self.runtime_authority_id {
            return Err(EventStoreError::CorruptData);
        }
        let capture = self
            .load_local_command_permission_capture(assignment.taskrun_id)?
            .ok_or(EventStoreError::CorruptData)?;
        if capture.taskrun_id != assignment.taskrun_id
            || capture.attempt_id != assignment.attempt_id
            || capture.fence != assignment.fence.0
            || capture.invocation_id != binding.invocation_id()
            || capture.canonical_binding_digest != *binding.digest().as_bytes()
        {
            return Err(EventStoreError::CorruptData);
        }
        let project = ProjectTrustProjectId::from_bytes(*binding.project_id().as_bytes());
        let owner = self
            .inner
            .permission_owner
            .as_ref()
            .ok_or(EventStoreError::Unavailable)?;
        let lease = owner
            .acquire_effect_lease(&self.runtime_authority_id, project)
            .map_err(|_| EventStoreError::Unavailable)?;
        if !lease
            .snapshot()
            .map_err(|_| EventStoreError::Unavailable)?
            .is_valid()
        {
            return Err(EventStoreError::CorruptData);
        }
        Ok(lease)
    }
}
