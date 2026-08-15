use gocode_api::{
    RootAdmissionVerificationContext, RootHandleAdmission, VerifiedRootAdmissionClaims,
};
use gocode_application::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, RootAdmissionLease,
    RootAdmissionVerifier, RootAdmissionVerifierError, RuntimeAuthorityId,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_runtime::RuntimeProjectWorkspaceHost;
use gocode_security::SecretBroker;
use gocode_store::{ProjectWorkspaceStore, store::StoreTransaction};
use std::{path::Path, sync::Arc};

pub struct UnavailableAdmission;
impl CurrentRootAdmissionContext for UnavailableAdmission {
    type Lease = Self;
    fn acquire_root_admission_lease(&self) -> Result<Self::Lease, RootAdmissionVerifierError> {
        Err(RootAdmissionVerifierError::Unavailable)
    }
}
impl RootAdmissionLease for UnavailableAdmission {
    fn current_root_admission_context(
        &self,
    ) -> Result<RootAdmissionVerificationContext, RootAdmissionVerifierError> {
        Err(RootAdmissionVerifierError::Unavailable)
    }
}
impl RootAdmissionVerifier for UnavailableAdmission {
    fn verify_root_admission(
        &self,
        _: RootHandleAdmission,
    ) -> Result<VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        Err(RootAdmissionVerifierError::Unavailable)
    }
}

pub fn test_host() -> (
    tempfile::TempDir,
    RuntimeProjectWorkspaceHost<ProjectWorkspaceStore, UnavailableAdmission, UnavailableAdmission>,
) {
    let (directory, repository) = test_repository();
    (directory, host_for(repository))
}

pub fn test_repository() -> (tempfile::TempDir, ProjectWorkspaceStore) {
    let directory = tempfile::tempdir().unwrap();
    let runtime_root = directory.path().join("runtime");
    let daemon = runtime_root.join("gocode-daemon");
    std::fs::create_dir_all(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = database_path(&directory);
    let repository = repository_at(&path);
    (directory, repository)
}

pub fn database_path(directory: &tempfile::TempDir) -> std::path::PathBuf {
    directory
        .path()
        .join("runtime/gocode-daemon/project-workspace.sqlite")
}

pub fn repository_at(path: &Path) -> ProjectWorkspaceStore {
    let guard: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let authority = RuntimeAuthorityId("project-workspace-host-test".into());
    let store = if path.exists() {
        let writer = gocode_store::schema::reopen_managed_connection_validated(
            path,
            gocode_store::schema::ConnectionMode::ValidatedReopen,
            |_| Ok(()),
        )
        .unwrap();
        let reader = gocode_store::schema::reopen_managed_connection_validated(
            path,
            gocode_store::schema::ConnectionMode::Reader,
            |_| Ok(()),
        )
        .unwrap();
        StoreTransaction::open_with_connections(
            path.to_str().unwrap(),
            writer,
            reader,
            authority,
            guard,
        )
        .unwrap()
    } else {
        StoreTransaction::open(path.to_str().unwrap(), authority, guard).unwrap()
    };
    ProjectWorkspaceStore::from_store(store)
}

pub fn host_for<R: ProjectWorkspaceRepository>(
    repository: R,
) -> RuntimeProjectWorkspaceHost<R, UnavailableAdmission, UnavailableAdmission> {
    RuntimeProjectWorkspaceHost::new(repository, UnavailableAdmission, UnavailableAdmission)
}
