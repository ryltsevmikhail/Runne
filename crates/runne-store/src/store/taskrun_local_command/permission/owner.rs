use std::fs::File;

/// Exact canonical values loaded by Store before asking its registered root owner.
pub struct PermissionRootFenceRequestV1 {
    workspace_id: runne_domain::id::WorkspaceId,
    workspace_version: u64,
    broker_root_version: u64,
    broker_root_identity: [u8; 32],
}

impl PermissionRootFenceRequestV1 {
    pub(crate) const fn new(
        workspace_id: runne_domain::id::WorkspaceId,
        workspace_version: u64,
        broker_root_version: u64,
        broker_root_identity: [u8; 32],
    ) -> Self {
        Self {
            workspace_id,
            workspace_version,
            broker_root_version,
            broker_root_identity,
        }
    }
    pub const fn workspace_id(&self) -> runne_domain::id::WorkspaceId {
        self.workspace_id
    }
    pub const fn workspace_version(&self) -> u64 {
        self.workspace_version
    }
    pub const fn broker_root_version(&self) -> u64 {
        self.broker_root_version
    }
    pub const fn broker_root_identity(&self) -> &[u8; 32] {
        &self.broker_root_identity
    }
}

/// Live exact-root guard retained through the native owner release boundary.
pub trait PermissionRootFenceGuardV1 {
    fn workspace(&self) -> &File;
    fn broker_root_version(&self) -> u64;
    fn broker_root_identity(&self) -> &[u8; 32];
}

/// Trusted startup adapter over the same in-memory state as root admission.
pub trait PermissionRootFenceOwnerV1: Send + Sync {
    fn acquire<'a>(
        &'a self,
        request: &PermissionRootFenceRequestV1,
    ) -> Result<Box<dyn PermissionRootFenceGuardV1 + 'a>, runne_application::ports::EventStoreError>;
}
