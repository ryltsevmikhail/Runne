//! Provider-neutral fail-closed root-admission adapter.

use runne_api::{
    RootAdmissionVerificationContext, RootHandleAdmission, VerifiedRootAdmissionClaims,
};
use runne_api::{
    WorkspaceFileContent, WorkspaceFileHostError, WorkspaceFileListRequest, WorkspaceFilePage,
    WorkspaceFileReadRequest,
};
use runne_application::ports::{
    CurrentRootAdmissionContext, RootAdmissionLease, RootAdmissionVerifier,
    RootAdmissionVerifierError, WorkspaceDiffProvider, WorkspaceEditorProvider,
    WorkspaceFileProvider,
};

#[derive(Clone)]
pub(super) struct UnavailableRootAdmission;

impl CurrentRootAdmissionContext for UnavailableRootAdmission {
    type Lease = Self;
    fn acquire_root_admission_lease(&self) -> Result<Self::Lease, RootAdmissionVerifierError> {
        Err(RootAdmissionVerifierError::Unavailable)
    }
}

impl RootAdmissionLease for UnavailableRootAdmission {
    fn current_root_admission_context(
        &self,
    ) -> Result<RootAdmissionVerificationContext, RootAdmissionVerifierError> {
        Err(RootAdmissionVerifierError::Unavailable)
    }
}

impl RootAdmissionVerifier for UnavailableRootAdmission {
    fn verify_root_admission(
        &self,
        _: RootHandleAdmission,
    ) -> Result<VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        Err(RootAdmissionVerifierError::Unavailable)
    }
}

impl WorkspaceFileProvider for UnavailableRootAdmission {
    fn list_files(
        &self,
        _: &str,
        _: &WorkspaceFileListRequest,
    ) -> Result<WorkspaceFilePage, WorkspaceFileHostError> {
        Err(WorkspaceFileHostError::Unavailable)
    }

    fn read_file(
        &self,
        _: &str,
        _: &WorkspaceFileReadRequest,
    ) -> Result<WorkspaceFileContent, WorkspaceFileHostError> {
        Err(WorkspaceFileHostError::Unavailable)
    }
}

impl WorkspaceDiffProvider for UnavailableRootAdmission {
    fn list_changes(
        &self,
        _: &str,
        _: &runne_api::WorkspaceChangeListRequest,
    ) -> Result<runne_api::WorkspaceChangeSet, runne_api::WorkspaceDiffHostError> {
        Err(runne_api::WorkspaceDiffHostError::Unavailable)
    }

    fn read_diff(
        &self,
        _: &str,
        _: &runne_api::WorkspaceDiffReadRequest,
    ) -> Result<runne_api::WorkspaceDiff, runne_api::WorkspaceDiffHostError> {
        Err(runne_api::WorkspaceDiffHostError::Unavailable)
    }
}

impl WorkspaceEditorProvider for UnavailableRootAdmission {
    fn open_editor(
        &self,
        _: &str,
        _: &runne_api::OpenEditorRequest,
    ) -> Result<runne_api::EditorLaunchReceipt, runne_api::WorkspaceEditorHostError> {
        Err(runne_api::WorkspaceEditorHostError::Unavailable)
    }
}
