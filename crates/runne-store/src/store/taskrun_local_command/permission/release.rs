use super::{
    owner::PermissionRootFenceRequestV1,
    release_guard::{ReleaseObservation, with_release_preconditions},
};
use crate::store::StoreTransaction;
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::{EventStoreError, TaskRunAssignmentIdentity},
};
use runne_platform::local_command_linux::PermissionChildV1;
use rusqlite::TransactionBehavior;

impl StoreTransaction {
    #[expect(
        clippy::too_many_arguments,
        reason = "release needs the immutable permission proof, launched child, and verified owner snapshot together"
    )]
    pub(super) fn release_burned_child(
        &self,
        identity: &TaskRunAssignmentIdentity,
        version: u64,
        binding: &LocalCommandPermissionBindingV1,
        area: &[u8; 100],
        digest: [u8; 32],
        request: &PermissionRootFenceRequestV1,
        lease: &dyn runne_application::project_trust::ProjectTrustEffectLease,
        child: &mut PermissionChildV1<'_>,
    ) -> Result<(), EventStoreError> {
        let owner = self
            .inner
            .permission_owner
            .as_ref()
            .ok_or(EventStoreError::Unavailable)?;
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        let root = owner
            .acquire_root_fence(&self.runtime_authority_id, request)
            .map_err(|_| EventStoreError::CorruptData)?;
        let observed = ReleaseObservation::from_prepared(child.observation());
        with_release_preconditions(
            &tx,
            self,
            identity,
            version,
            binding,
            area,
            digest,
            lease,
            root.as_ref(),
            &observed,
            || {
                owner
                    .release_permission_child_under_guard(
                        &self.runtime_authority_id,
                        root.as_ref(),
                        child,
                    )
                    .map_err(|_| EventStoreError::CorruptData)
            },
        )?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}
