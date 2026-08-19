use std::sync::{Arc, Mutex};

use runne_application::local_session::LocalSessionService;
use runne_runtime::{RuntimeCommandReconciliationHost, RuntimeProjectWorkspaceHost};
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};

#[cfg(not(feature = "desktop-protected"))]
use super::super::root_admission_unavailable::UnavailableRootAdmission;
#[cfg(feature = "desktop-protected")]
use {
    super::super::root_handle_admission::{RootAdmissionGateway, RootHandleAdmissionAuthority},
    crate::protected_activation::ProtectedRootControl,
};

#[cfg(feature = "desktop-protected")]
pub(super) struct CommandHosts {
    pub(super) project_workspace: RuntimeProjectWorkspaceHost<
        ProjectWorkspaceStore,
        RootAdmissionGateway,
        RootAdmissionGateway,
    >,
    pub(super) reconciliation: RuntimeCommandReconciliationHost<ProjectWorkspaceStore>,
    pub(super) root_control: Option<Arc<ProtectedRootControl>>,
}

#[cfg(not(feature = "desktop-protected"))]
pub(super) struct CommandHosts {
    pub(super) project_workspace: RuntimeProjectWorkspaceHost<
        ProjectWorkspaceStore,
        UnavailableRootAdmission,
        UnavailableRootAdmission,
    >,
    pub(super) reconciliation: RuntimeCommandReconciliationHost<ProjectWorkspaceStore>,
}

#[cfg(feature = "desktop-protected")]
pub(super) fn compose(
    store: &StoreTransaction,
    root_admission_keys: Option<runne_api::ProtectedActivationKeys>,
    protected_activation: bool,
    sessions: Arc<Mutex<LocalSessionService>>,
) -> CommandHosts {
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let authority = root_admission_keys
        .filter(|_| protected_activation)
        .map(|keys| {
            RootHandleAdmissionAuthority::new(
                &keys,
                repository.clone(),
                store.runtime_authority_id().0.clone(),
                sessions,
            )
        });
    let gateway = authority
        .as_ref()
        .map_or_else(RootAdmissionGateway::unavailable, |value| {
            RootAdmissionGateway::protected(Arc::clone(value))
        });
    CommandHosts {
        project_workspace: RuntimeProjectWorkspaceHost::new(
            repository.clone(),
            gateway.clone(),
            gateway,
        ),
        reconciliation: RuntimeCommandReconciliationHost::new(repository),
        root_control: authority.map(ProtectedRootControl::new),
    }
}

#[cfg(not(feature = "desktop-protected"))]
pub(super) fn compose(
    store: &StoreTransaction,
    _root_admission_keys: Option<runne_api::ProtectedActivationKeys>,
    _protected_activation: bool,
    _sessions: Arc<Mutex<LocalSessionService>>,
) -> CommandHosts {
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    CommandHosts {
        project_workspace: RuntimeProjectWorkspaceHost::new(
            repository.clone(),
            UnavailableRootAdmission,
            UnavailableRootAdmission,
        ),
        reconciliation: RuntimeCommandReconciliationHost::new(repository),
    }
}
