#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected V2 host composes authenticated resume after Task 8 admission wiring"
    )
)]

use runne_api::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialEnrollmentHostError,
    ProviderCredentialOperationHandleV2, ProviderCredentialOperationSnapshotV2,
};
use runne_provider::{CredentialInstallationOwnerId, ProviderCredentialEnrollmentStore};

use super::{
    CredentialEnrollmentReadback, CredentialEnrollmentRecoveryGateway, ProviderCredentialAdmission,
    broker::pending::PendingBrokerRendezvousRegistry,
    operation_handle::ProviderCredentialOperationHandleIssuer, operation_projection,
};

/// Authenticated, recovery-first resume projection with no writer authority.
pub(crate) struct ProviderCredentialEnrollmentResume<'a, S: ?Sized, R: ?Sized> {
    admission: ProviderCredentialAdmission,
    handles: ProviderCredentialOperationHandleIssuer,
    store: &'a S,
    reader: &'a R,
    rendezvous: PendingBrokerRendezvousRegistry,
}

impl<'a, S: ?Sized, R: ?Sized> ProviderCredentialEnrollmentResume<'a, S, R> {
    /// Retains only metadata reader and the daemon-owned opaque handle key.
    pub(crate) const fn new(
        admission: ProviderCredentialAdmission,
        handles: ProviderCredentialOperationHandleIssuer,
        store: &'a S,
        reader: &'a R,
        rendezvous: PendingBrokerRendezvousRegistry,
    ) -> Self {
        Self {
            admission,
            handles,
            store,
            reader,
            rendezvous,
        }
    }
}

impl<S, R> ProviderCredentialEnrollmentResume<'_, S, R>
where
    S: ProviderCredentialEnrollmentStore + ?Sized,
    R: CredentialEnrollmentReadback + ?Sized,
{
    /// Resolves a caller-owned operation after recovery, never issuing a ticket.
    pub(crate) fn load(
        &self,
        authority: &ProviderCredentialBaseRequestAuthority,
        handle: ProviderCredentialOperationHandleV2,
        now_high_water: i64,
    ) -> Result<ProviderCredentialOperationSnapshotV2, ProviderCredentialEnrollmentHostError> {
        self.admission.require_base(authority)?;
        let operation_id = self.handles.resolve(handle)?;
        let operation = self.store.load_operation(operation_id).map_err(map_store)?;
        require_owner(authority, &operation)?;
        CredentialEnrollmentRecoveryGateway::new(self.store, self.reader)
            .reconcile_online(now_high_water)?;
        let operation = self.store.load_operation(operation_id).map_err(map_store)?;
        require_owner(authority, &operation)?;
        let lifecycle = self
            .store
            .lifecycle_snapshot(operation.provider())
            .map_err(map_store)?;
        operation_projection::snapshot(
            operation,
            &self.handles,
            lifecycle.readiness_revision().get(),
            &self.rendezvous,
            now_high_water,
        )
    }
}

fn require_owner(
    authority: &ProviderCredentialBaseRequestAuthority,
    operation: &runne_provider::CredentialOperationSnapshot,
) -> Result<(), ProviderCredentialEnrollmentHostError> {
    let owner = CredentialInstallationOwnerId::from_bytes(*authority.installation_identity())
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
    if operation.installation_owner_id() == owner {
        Ok(())
    } else {
        Err(ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

fn map_store(
    error: runne_provider::CredentialLifecycleError,
) -> ProviderCredentialEnrollmentHostError {
    super::effect_authority::map_store(error)
}
