use super::super::taskrun_local_command::{PermissionRootFenceGuardV1, PermissionRootFenceOwnerV1};
use super::super::*;

/// Immutable startup registration shared by every clone of the canonical Store.
pub(in crate::store) struct RegisteredPermissionOwnerPair {
    pub(super) trust_store: Arc<crate::ProjectTrustStore>,
    trust_identity: ([u8; 16], u64),
    #[cfg(target_os = "linux")]
    pub(super) native_owner: Arc<runne_platform::local_command_linux::LinuxPermissionOwnerV1>,
    pub(super) root_fence: Arc<dyn PermissionRootFenceOwnerV1>,
}

impl RegisteredPermissionOwnerPair {
    /// Registers the retained Linux native owner; other platforms have no producer.
    #[cfg(target_os = "linux")]
    pub(super) fn checked(
        authority: RuntimeAuthorityId,
        trust_store: Arc<crate::ProjectTrustStore>,
        native_owner: Arc<runne_platform::local_command_linux::LinuxPermissionOwnerV1>,
        root_fence: Arc<dyn PermissionRootFenceOwnerV1>,
    ) -> Result<Self, CommitError> {
        let trust_identity = trust_store.registration_identity();
        let (trust_authority, epoch) = trust_identity;
        if epoch == 0 || authority_id_hex(&trust_authority) != authority.0 {
            return Err(CommitError::StorageFailure(
                StorageFailureKind::IntegrityViolation,
            ));
        }
        Ok(Self {
            trust_store,
            trust_identity,
            native_owner,
            root_fence,
        })
    }

    pub(super) fn validate_retained_owner(&self, authority: &RuntimeAuthorityId) -> bool {
        self.trust_store.registration_identity() == self.trust_identity
            && authority_id_hex(&self.trust_identity.0) == authority.0
            && Arc::strong_count(&self.root_fence) > 0
    }

    pub(in crate::store) fn acquire_effect_lease(
        &self,
        authority: &RuntimeAuthorityId,
        project: runne_application::project_trust::ProjectTrustProjectId,
    ) -> Result<Box<dyn runne_application::project_trust::ProjectTrustEffectLease>, ()> {
        if !self.validate_retained_owner(authority) {
            return Err(());
        }
        runne_application::project_trust::ProjectTrustPersistence::acquire_effect_lease(
            self.trust_store.as_ref(),
            project,
        )
        .map_err(|_| ())
    }

    pub(in crate::store) fn acquire_root_fence<'a>(
        &'a self,
        authority: &RuntimeAuthorityId,
        request: &PermissionRootFenceRequestV1,
    ) -> Result<Box<dyn super::super::taskrun_local_command::PermissionRootFenceGuardV1 + 'a>, ()>
    {
        if !self.validate_retained_owner(authority) {
            return Err(());
        }
        let guard = self.root_fence.acquire(request).map_err(|_| ())?;
        if guard.broker_root_version() != request.broker_root_version()
            || guard.broker_root_identity() != request.broker_root_identity()
        {
            return Err(());
        }
        Ok(guard)
    }

    #[cfg(target_os = "linux")]
    pub(in crate::store) fn release_helper_child(
        &self,
        authority: &RuntimeAuthorityId,
        request: &PermissionRootFenceRequestV1,
        child: &mut runne_platform::local_command_linux::PermissionHelperChildV1<'_>,
    ) -> Result<(), ()> {
        if !self.validate_retained_owner(authority) {
            return Err(());
        }
        let guard = self.root_fence.acquire(request).map_err(|_| ())?;
        if guard.broker_root_version() != request.broker_root_version()
            || guard.broker_root_identity() != request.broker_root_identity()
        {
            return Err(());
        }
        self.native_owner
            .release_helper_child(child, guard.workspace())
            .map_err(|_| ())
    }

    #[cfg(target_os = "linux")]
    pub(in crate::store) fn release_permission_child_under_guard(
        &self,
        authority: &RuntimeAuthorityId,
        guard: &dyn PermissionRootFenceGuardV1,
        child: &mut runne_platform::local_command_linux::PermissionChildV1<'_>,
    ) -> Result<(), ()> {
        if !self.validate_retained_owner(authority) {
            return Err(());
        }
        self.native_owner
            .release_child(child, guard.workspace())
            .map_err(|_| ())
    }
}

fn authority_id_hex(authority_id: &[u8; 16]) -> String {
    let mut encoded = String::with_capacity(32);
    for byte in authority_id {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
