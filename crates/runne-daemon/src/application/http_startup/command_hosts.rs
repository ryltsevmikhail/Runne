use std::path::Path;
use std::sync::{Arc, Mutex};

use runne_application::local_session::LocalSessionService;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_runtime::{
    RuntimeApprovalHost, RuntimeCommandReconciliationHost, RuntimeProcessHost,
    RuntimeProjectWorkspaceHost, RuntimeWorkspaceDiffHost, RuntimeWorkspaceEditorHost,
    RuntimeWorkspaceFileHost,
};
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::{ProjectTrustStore, ProjectWorkspaceStore, store::StoreTransaction};

#[cfg(not(feature = "desktop-protected"))]
use super::super::process_unavailable::UnavailableProcessProvider;
#[cfg(not(feature = "desktop-protected"))]
use super::super::root_admission_unavailable::UnavailableRootAdmission;
#[cfg(feature = "desktop-protected")]
use {
    super::super::native_process_provider::{
        AuthoritativeProcessInvocationRegistry, NativeProcessProvider,
    },
    super::super::root_handle_admission::{
        RootAdmissionGateway, RootHandleAdmissionAuthority, TrustGate,
    },
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
    pub(super) approval: RuntimeApprovalHost<ProjectWorkspaceStore>,
    pub(super) workspace_files: RuntimeWorkspaceFileHost<RootAdmissionGateway>,
    pub(super) workspace_diffs: RuntimeWorkspaceDiffHost<RootAdmissionGateway>,
    pub(super) workspace_editor: RuntimeWorkspaceEditorHost<RootAdmissionGateway>,
    pub(super) process:
        RuntimeProcessHost<NativeProcessProvider<AuthoritativeProcessInvocationRegistry>>,
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
    pub(super) approval: RuntimeApprovalHost<ProjectWorkspaceStore>,
    pub(super) workspace_files: RuntimeWorkspaceFileHost<UnavailableRootAdmission>,
    pub(super) workspace_diffs: RuntimeWorkspaceDiffHost<UnavailableRootAdmission>,
    pub(super) workspace_editor: RuntimeWorkspaceEditorHost<UnavailableRootAdmission>,
    pub(super) process: RuntimeProcessHost<UnavailableProcessProvider>,
}

#[cfg(feature = "desktop-protected")]
pub(super) fn compose(
    store: &StoreTransaction,
    canonical_db_path: &Path,
    runtime_authority_id: [u8; 16],
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    root_admission_keys: Option<runne_api::ProtectedActivationKeys>,
    protected_activation: bool,
    sessions: Arc<Mutex<LocalSessionService>>,
) -> CommandHosts {
    let trust_gate =
        compose_trust_gate(canonical_db_path, runtime_authority_id, &prohibited_content);
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let authority = root_admission_keys
        .filter(|_| protected_activation)
        .map(|keys| {
            RootHandleAdmissionAuthority::new(
                &keys,
                repository.clone(),
                store.runtime_authority_id().0.clone(),
                sessions,
                trust_gate,
            )
        });
    let gateway = authority
        .as_ref()
        .map_or_else(RootAdmissionGateway::unavailable, |value| {
            RootAdmissionGateway::protected(Arc::clone(value))
        });
    let workspace_files = RuntimeWorkspaceFileHost::new(gateway.clone());
    let workspace_diffs = RuntimeWorkspaceDiffHost::new(gateway.clone());
    let workspace_editor = RuntimeWorkspaceEditorHost::new(gateway.clone());
    let process_invocations = AuthoritativeProcessInvocationRegistry::default();
    let process = RuntimeProcessHost::new(NativeProcessProvider::new(
        process_invocations.clone(),
        gateway.clone(),
        store.clone(),
    ));
    CommandHosts {
        project_workspace: RuntimeProjectWorkspaceHost::new(
            repository.clone(),
            gateway.clone(),
            gateway,
        ),
        reconciliation: RuntimeCommandReconciliationHost::new(repository),
        approval: RuntimeApprovalHost::new(ProjectWorkspaceStore::from_store(store.clone())),
        workspace_files,
        workspace_diffs,
        workspace_editor,
        process,
        root_control: authority.map(ProtectedRootControl::new),
    }
}

#[cfg(feature = "desktop-protected")]
/// Opens the durable trust sidecar next to the canonical store and installs
/// the single runtime-owned policy authority over the store ports (T1).
/// Any open failure stays fail-closed: without the authority no project
/// source is admitted.
fn compose_trust_gate(
    canonical_db_path: &Path,
    runtime_authority_id: [u8; 16],
    prohibited_content: &Arc<dyn ProhibitedContentPort>,
) -> TrustGate {
    ProjectTrustStore::open(canonical_db_path, runtime_authority_id)
        .ok()
        .map(|trust_store| {
            Arc::new(
                ProjectTrustPolicyAuthority::new(Arc::new(trust_store))
                    .with_byte_inspection(Arc::clone(prohibited_content)),
            )
        })
        .map_or_else(TrustGate::closed, TrustGate::open)
}

#[cfg(not(feature = "desktop-protected"))]
pub(super) fn compose(
    store: &StoreTransaction,
    _canonical_db_path: &Path,
    _runtime_authority_id: [u8; 16],
    _prohibited_content: Arc<dyn ProhibitedContentPort>,
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
        approval: RuntimeApprovalHost::new(ProjectWorkspaceStore::from_store(store.clone())),
        workspace_files: RuntimeWorkspaceFileHost::new(UnavailableRootAdmission),
        workspace_diffs: RuntimeWorkspaceDiffHost::new(UnavailableRootAdmission),
        workspace_editor: RuntimeWorkspaceEditorHost::new(UnavailableRootAdmission),
        process: RuntimeProcessHost::new(UnavailableProcessProvider),
    }
}
