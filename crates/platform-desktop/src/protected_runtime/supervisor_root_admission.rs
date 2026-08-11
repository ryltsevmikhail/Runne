use gocode_api::{RootHandleAdmission, WorkspaceId};

use crate::VerifiedRootHandle;

impl ProtectedBundledRuntimeSupervisor {
    /// Transfers a root only through the current exact protected daemon child.
    ///
    /// # Errors
    ///
    /// Returns a closed error unless the current owned child is fully ready.
    pub fn prepare_root_admission(
        &mut self,
        root: &VerifiedRootHandle,
        workspace_id: WorkspaceId,
        expected_version: u64,
    ) -> Result<RootHandleAdmission, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        self.process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?
            .prepare_root_admission(root, workspace_id, expected_version)
    }
}
