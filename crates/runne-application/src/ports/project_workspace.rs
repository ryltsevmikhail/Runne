use runne_api::{
    ProjectWorkspacePageSize, RootAdmissionVerificationContext, RootHandleAdmission,
    VerifiedRootAdmissionClaims,
};
use runne_domain::id::ProjectId;
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};

/// Closed storage failures for Project and Workspace authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectWorkspaceRepositoryError {
    NotFound,
    Conflict,
    Forbidden,
    Unavailable,
    InvariantViolation,
}

/// Closed error from root-admission context retrieval or verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootAdmissionVerifierError {
    Rejected,
    Unavailable,
}

/// Provides the authoritative current protected-runtime bindings.
pub trait CurrentRootAdmissionContext: Send + Sync + 'static {
    type Lease: RootAdmissionLease;
    fn acquire_root_admission_lease(&self) -> Result<Self::Lease, RootAdmissionVerifierError>;
}

/// Authority rotation/revocation is blocked or rejected while this lease exists.
pub trait RootAdmissionLease: Send {
    fn current_root_admission_context(
        &self,
    ) -> Result<RootAdmissionVerificationContext, RootAdmissionVerifierError>;
}

/// Verifies opaque root admissions without consuming their durable nonce.
pub trait RootAdmissionVerifier: Send + Sync + 'static {
    fn verify_root_admission(
        &self,
        admission: RootHandleAdmission,
    ) -> Result<VerifiedRootAdmissionClaims, RootAdmissionVerifierError>;

    /// Promotes the verified admission's retained root to the serving state.
    ///
    /// Called only after the workspace command that consumed the admission
    /// durably committed; a failed command must never promote its root.
    /// `Ok(())` means "no older root may be promoted": for a superseded
    /// admission (receipt replay) it acks idempotently while the newer
    /// already-serving root stays in place.
    fn confirm_root_admission(
        &self,
        claims: &VerifiedRootAdmissionClaims,
    ) -> Result<(), RootAdmissionVerifierError>;
}

/// Authorizes a root binding after the repository owns its SQLite writer.
pub trait RootAdmissionAuthorizer {
    fn authorize_root_admission(
        &mut self,
    ) -> Result<RootAdmissionConsumption, ProjectWorkspaceRepositoryError>;
}

/// Opaque durable single-use values derived exclusively from verified claims.
pub struct RootAdmissionConsumption {
    authority_digest: [u8; 32],
    nonce: [u8; 16],
    admission_digest: [u8; 32],
}

impl RootAdmissionConsumption {
    pub(crate) fn from_claims(claims: &VerifiedRootAdmissionClaims) -> Self {
        Self {
            authority_digest: claims.context().authority_digest(),
            nonce: claims.nonce(),
            admission_digest: claims.admission_digest(),
        }
    }
    pub fn into_store_binding(self, authority: &str) -> Option<RootAdmissionStoreBinding> {
        (self.authority_digest == RootAdmissionVerificationContext::authority_digest_for(authority))
            .then_some(RootAdmissionStoreBinding {
                nonce: self.nonce,
                admission_digest: self.admission_digest,
            })
    }
}

/// Store-only nonce binding produced by an opaque verified consumption token.
pub struct RootAdmissionStoreBinding {
    nonce: [u8; 16],
    admission_digest: [u8; 32],
}
impl RootAdmissionStoreBinding {
    pub fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
    pub fn admission_digest(&self) -> &[u8; 32] {
        &self.admission_digest
    }
}

/// Principal-bound, versioned repository for canonical Project and Workspace state.
pub trait ProjectWorkspaceRepository: Clone + Send + Sync + 'static {
    fn create_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        project: Project,
    ) -> Result<Project, ProjectWorkspaceRepositoryError>;
    fn archive_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        expected_version: u64,
    ) -> Result<Project, ProjectWorkspaceRepositoryError>;
    fn restore_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        expected_version: u64,
    ) -> Result<Project, ProjectWorkspaceRepositoryError>;
    fn rename_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        expected_version: u64,
        display_name: ProjectWorkspaceDisplayName,
    ) -> Result<Project, ProjectWorkspaceRepositoryError>;
    fn delete_project(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: ProjectId,
        expected_version: u64,
    ) -> Result<u64, ProjectWorkspaceRepositoryError>;
    fn create_workspace(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        workspace: Workspace,
    ) -> Result<Workspace, ProjectWorkspaceRepositoryError>;
    fn open_workspace(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: WorkspaceId,
        expected_version: u64,
    ) -> Result<Workspace, ProjectWorkspaceRepositoryError>;
    fn bind_workspace_root(
        &self,
        principal: &str,
        command_id: CommandId,
        key: &IdempotencyKey,
        id: WorkspaceId,
        expected_version: u64,
        authorizer: &mut dyn RootAdmissionAuthorizer,
    ) -> Result<Workspace, ProjectWorkspaceRepositoryError>;
    fn list_projects(
        &self,
        principal: &str,
        limit: ProjectWorkspacePageSize,
        after: Option<ProjectId>,
    ) -> Result<(Vec<Project>, Option<ProjectId>), ProjectWorkspaceRepositoryError>;
    fn get_project(
        &self,
        principal: &str,
        id: ProjectId,
    ) -> Result<Project, ProjectWorkspaceRepositoryError>;
    fn list_workspaces(
        &self,
        principal: &str,
        project_id: ProjectId,
        limit: ProjectWorkspacePageSize,
        after: Option<WorkspaceId>,
    ) -> Result<(Vec<Workspace>, Option<WorkspaceId>), ProjectWorkspaceRepositoryError>;
    fn get_workspace(
        &self,
        principal: &str,
        id: WorkspaceId,
    ) -> Result<Workspace, ProjectWorkspaceRepositoryError>;
}
