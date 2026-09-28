//! Runtime-owned, non-canonical Project Trust control contract.

use crate::ApiPrincipalId;
use runne_domain::id::{ProjectId, WorkspaceId};

/// Closed user decision. Managed policy fields never cross this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectTrustDecision {
    /// Trust the project and its attached folders after native confirmation.
    ConfirmProject,
    /// Revoke user trust for the project.
    RevokeProject,
}

/// Runtime-owned safe metadata for the selected project/workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectTrustControlSnapshot {
    pub project_id: ProjectId,
    pub project_name: String,
    pub project_version: u64,
    pub workspace_id: WorkspaceId,
    pub workspace_name: String,
    pub workspace_version: u64,
    pub status: ProjectTrustControlStatus,
    pub managed_deny_mask: u32,
    pub provenance: ProjectTrustControlProvenance,
    pub epoch: u64,
    pub revision: u64,
    pub root_admission_version: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectTrustControlStatus {
    Untrusted,
    Trusted,
    Managed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectTrustControlProvenance {
    Default,
    User,
    Managed,
}

/// Exact compare-and-set selection observed before native confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectTrustControlRequest {
    pub decision: ProjectTrustDecision,
    pub expected_epoch: u64,
    pub expected_revision: u64,
    pub expected_project_version: u64,
    pub expected_workspace_version: u64,
    pub expected_root_admission_version: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectTrustControlError {
    NotFound,
    Conflict,
    ManagedPolicy,
    RootUnavailable,
    Unavailable,
}

/// Protected server-side trust metadata and decision port.
pub trait ProjectTrustControlHostPort: Send + Sync {
    fn get_project_trust(
        &self,
        principal: ApiPrincipalId,
        project: ProjectId,
        workspace: WorkspaceId,
    ) -> impl std::future::Future<
        Output = Result<ProjectTrustControlSnapshot, ProjectTrustControlError>,
    > + Send;

    fn decide_project_trust(
        &self,
        principal: ApiPrincipalId,
        project: ProjectId,
        workspace: WorkspaceId,
        request: ProjectTrustControlRequest,
    ) -> impl std::future::Future<
        Output = Result<ProjectTrustControlSnapshot, ProjectTrustControlError>,
    > + Send;
}
