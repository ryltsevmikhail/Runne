use gocode_api::{
    RootAdmissionVerificationContext, RootHandleAdmission, VerifiedRootAdmissionClaims,
};
use gocode_application::ports::{
    CurrentRootAdmissionContext, RootAdmissionLease, RootAdmissionVerifier,
    RootAdmissionVerifierError, RuntimeAuthorityId,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_runtime::RuntimeProjectWorkspaceHost;
use gocode_security::SecretBroker;
use gocode_store::{ProjectWorkspaceStore, store::StoreTransaction};
use std::sync::Arc;

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
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("project-workspace.sqlite");
    let guard: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = StoreTransaction::open(
        path.to_str().unwrap(),
        RuntimeAuthorityId("project-workspace-host-test".into()),
        guard,
    )
    .unwrap();
    (
        directory,
        RuntimeProjectWorkspaceHost::new(
            ProjectWorkspaceStore::from_store(store),
            UnavailableAdmission,
            UnavailableAdmission,
        ),
    )
}
