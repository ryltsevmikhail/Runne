use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::canonical_provider::DaemonCanonicalProviderService;

use runne_application::local_session::LocalSessionService;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_runtime::{
    RuntimeApprovalHost, RuntimeCommandReconciliationHost, RuntimeProcessHost,
    RuntimeProjectWorkspaceHost, RuntimeWorkspaceDiffHost, RuntimeWorkspaceEditorHost,
    RuntimeWorkspaceFileHost,
};
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::{ProjectWorkspaceStore, store::StoreTransaction};

#[cfg(feature = "desktop-protected")]
mod trust_control;

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
    pub(super) trust_control_routes: Option<axum::Router>,
    pub(super) root_admission: RootAdmissionGateway,
    #[cfg(target_os = "linux")]
    pub(super) permission_admission:
        Option<Arc<runne_platform::local_command_linux::LinuxCompositeScopeAdmission>>,
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
    pub(super) trust_control_routes: Option<axum::Router>,
}

#[cfg(feature = "desktop-protected")]
#[allow(clippy::too_many_arguments)]
pub(super) fn compose(
    store: &StoreTransaction,
    canonical_db_path: &Path,
    replay_integrity_key_path: &Path,
    runtime_authority_id: [u8; 16],
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    trust_authority: Option<Arc<ProjectTrustPolicyAuthority>>,
    root_admission_keys: Option<runne_api::ProtectedActivationKeys>,
    protected_activation: bool,
    sessions: Arc<Mutex<LocalSessionService>>,
) -> CommandHosts {
    let _ = (
        canonical_db_path,
        replay_integrity_key_path,
        runtime_authority_id,
        prohibited_content,
    );
    // T1/NM-06: the shared process-wide authority (opened once in the
    // bootstrap flow). A missing authority keeps the gate closed.
    let trust_gate = match trust_authority.as_ref() {
        Some(authority) => TrustGate::open(Arc::clone(authority)),
        None => TrustGate::closed(),
    };
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
    let trust_control_routes = trust_authority.as_ref().map(|trust| {
        runne_http::project_trust_control::project_trust_control_router(
            runne_http::project_trust_control::ProjectTrustControlHttpState::new(
                trust_control::TrustControlHost::new(
                    repository.clone(),
                    Arc::clone(trust),
                    gateway.clone(),
                ),
            ),
        )
    });
    let workspace_files = RuntimeWorkspaceFileHost::new(gateway.clone());
    let workspace_diffs = RuntimeWorkspaceDiffHost::new(gateway.clone());
    let workspace_editor = RuntimeWorkspaceEditorHost::new(gateway.clone());
    let process_invocations = AuthoritativeProcessInvocationRegistry::default();
    #[cfg(target_os = "linux")]
    let permission_admission = open_protected_roots(canonical_db_path, replay_integrity_key_path)
        .and_then(|roots| {
            let references = roots.iter().collect::<Vec<_>>();
            runne_platform::local_command_linux::LinuxCompositeScopeAdmission::new(&references).ok()
        })
        .map(Arc::new);
    let process = RuntimeProcessHost::new(NativeProcessProvider::new(
        process_invocations.clone(),
        gateway.clone(),
        store.clone(),
    ));
    CommandHosts {
        project_workspace: RuntimeProjectWorkspaceHost::new(
            repository.clone(),
            gateway.clone(),
            gateway.clone(),
        ),
        reconciliation: RuntimeCommandReconciliationHost::new(repository),
        approval: RuntimeApprovalHost::new(ProjectWorkspaceStore::from_store(store.clone())),
        workspace_files,
        workspace_diffs,
        workspace_editor,
        process,
        root_control: authority.map(ProtectedRootControl::new),
        trust_control_routes,
        root_admission: gateway,
        #[cfg(target_os = "linux")]
        permission_admission,
    }
}

fn open_protected_roots(db_path: &Path, replay_key_path: &Path) -> Option<Vec<std::fs::File>> {
    [db_path.parent(), replay_key_path.parent()]
        .into_iter()
        .flatten()
        .filter(|path| *path != std::path::Path::new("/"))
        .map(|path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
        .fold(Vec::<PathBuf>::new(), |mut roots, root| {
            if !roots.contains(&root) {
                roots.push(root);
            }
            roots
        })
        .iter()
        .map(|root| std::fs::File::open(root).ok())
        .collect()
}

#[cfg(not(feature = "desktop-protected"))]
#[allow(clippy::too_many_arguments)]
pub(super) fn compose(
    store: &StoreTransaction,
    _canonical_db_path: &Path,
    _replay_integrity_key_path: &Path,
    _runtime_authority_id: [u8; 16],
    _prohibited_content: Arc<dyn ProhibitedContentPort>,
    _trust_authority: Option<Arc<ProjectTrustPolicyAuthority>>,
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
        trust_control_routes: None,
    }
}

/// The exact provider model pinned by the canonical provider composition, for
/// TaskRun exact-model admission (D1.4b); `None` without a provider service.
pub(super) fn pinned_task_run_model(
    provider_service: &Option<Arc<DaemonCanonicalProviderService>>,
) -> Option<&str> {
    provider_service
        .as_ref()
        .map(|service| service.pinned_model_id())
}

pub(super) fn writer_lease_routes(store: &runne_store::store::StoreTransaction) -> axum::Router {
    runne_http::conversation_writer_lease::conversation_writer_lease_router(
        runne_http::conversation_writer_lease::ConversationWriterLeaseHttpState::new(
            std::sync::Arc::new(
                runne_http::conversation_writer_lease::StoreConversationWriterLeaseHost::new(
                    store.clone(),
                ),
            ),
        ),
    )
}
