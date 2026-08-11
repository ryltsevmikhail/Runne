//! Principal-bound Project and Workspace application service.
use crate::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError,
    RootAdmissionConsumption, RootAdmissionVerifier, RootAdmissionVerifierError,
};
use gocode_api::{
    BindWorkspaceRootCommand, CreateProjectCommand, CreateWorkspaceCommand, ExistingProjectCommand,
    ExistingWorkspaceCommand, ProjectCommandAck, ProjectCommandContext, ProjectQueryContext,
    ProjectSnapshot, RootAdmissionAction, RootAdmissionVerificationContext,
    VerifiedRootAdmissionClaims, WorkspaceCommandAck, WorkspaceSnapshot,
};
use gocode_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectWorkspaceServiceError {
    NotFound,
    Conflict,
    Forbidden,
    Unavailable,
    InvariantViolation,
}
pub struct ProjectWorkspaceService<R, C, V> {
    repository: R,
    current_admission: C,
    admission_verifier: V,
}
impl<R: ProjectWorkspaceRepository, C: CurrentRootAdmissionContext, V: RootAdmissionVerifier>
    ProjectWorkspaceService<R, C, V>
{
    pub fn new(repository: R, current_admission: C, admission_verifier: V) -> Self {
        Self {
            repository,
            current_admission,
            admission_verifier,
        }
    }
    pub fn create_project(
        &self,
        context: ProjectCommandContext,
        command: CreateProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceServiceError> {
        let name = ProjectWorkspaceDisplayName::new(command.display_name)
            .map_err(|_| ProjectWorkspaceServiceError::Conflict)?;
        let project = self
            .repository
            .create_project(
                context.principal.as_str(),
                context.command_id,
                &context.idempotency_key,
                Project::create(command.project_id, name),
            )
            .map_err(map_error)?;
        Ok(ProjectCommandAck {
            project_id: project.id(),
            new_version: project.version(),
        })
    }
    pub fn archive_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceServiceError> {
        let project = self
            .repository
            .archive_project(
                context.principal.as_str(),
                context.command_id,
                &context.idempotency_key,
                command.project_id,
                command.expected_version,
            )
            .map_err(map_error)?;
        Ok(ProjectCommandAck {
            project_id: project.id(),
            new_version: project.version(),
        })
    }
    pub fn restore_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceServiceError> {
        let project = self
            .repository
            .restore_project(
                context.principal.as_str(),
                context.command_id,
                &context.idempotency_key,
                command.project_id,
                command.expected_version,
            )
            .map_err(map_error)?;
        Ok(ProjectCommandAck {
            project_id: project.id(),
            new_version: project.version(),
        })
    }
    pub fn delete_project(
        &self,
        context: ProjectCommandContext,
        command: ExistingProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceServiceError> {
        let version = self
            .repository
            .delete_project(
                context.principal.as_str(),
                context.command_id,
                &context.idempotency_key,
                command.project_id,
                command.expected_version,
            )
            .map_err(map_error)?;
        Ok(ProjectCommandAck {
            project_id: command.project_id,
            new_version: version,
        })
    }
    pub fn create_workspace(
        &self,
        context: ProjectCommandContext,
        command: CreateWorkspaceCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceServiceError> {
        let name = ProjectWorkspaceDisplayName::new(command.display_name)
            .map_err(|_| ProjectWorkspaceServiceError::Conflict)?;
        let workspace = self
            .repository
            .create_workspace(
                context.principal.as_str(),
                context.command_id,
                &context.idempotency_key,
                Workspace::create(command.workspace_id, command.project_id, name),
            )
            .map_err(map_error)?;
        Ok(workspace_ack(workspace))
    }
    pub fn open_workspace(
        &self,
        context: ProjectCommandContext,
        command: ExistingWorkspaceCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceServiceError> {
        let workspace = self
            .repository
            .open_workspace(
                context.principal.as_str(),
                context.command_id,
                &context.idempotency_key,
                command.workspace_id,
                command.expected_version,
            )
            .map_err(map_error)?;
        Ok(workspace_ack(workspace))
    }
    pub fn bind_workspace_root(
        &self,
        context: ProjectCommandContext,
        command: BindWorkspaceRootCommand,
    ) -> Result<WorkspaceCommandAck, ProjectWorkspaceServiceError> {
        let current = self
            .current_admission
            .current_root_admission_context()
            .map_err(map_admission_error)?;
        let claims = self
            .admission_verifier
            .verify_root_admission(command.root_admission)
            .map_err(map_admission_error)?;
        validate_root_claims(
            &current,
            &context,
            command.workspace_id,
            command.expected_version,
            &claims,
        )?;
        let workspace = self
            .repository
            .bind_workspace_root(
                context.principal.as_str(),
                context.command_id,
                &context.idempotency_key,
                command.workspace_id,
                command.expected_version,
                RootAdmissionConsumption {
                    nonce: claims.nonce(),
                    admission_digest: claims.admission_digest(),
                },
            )
            .map_err(map_error)?;
        Ok(workspace_ack(workspace))
    }
    pub fn list_projects(
        &self,
        context: ProjectQueryContext,
    ) -> Result<Vec<ProjectSnapshot>, ProjectWorkspaceServiceError> {
        self.repository
            .list_projects(context.principal.as_str())
            .map_err(map_error)
            .map(|items| items.into_iter().map(project_snapshot).collect())
    }
    pub fn get_project(
        &self,
        context: ProjectQueryContext,
        id: gocode_domain::id::ProjectId,
    ) -> Result<ProjectSnapshot, ProjectWorkspaceServiceError> {
        self.repository
            .get_project(context.principal.as_str(), id)
            .map_err(map_error)
            .map(project_snapshot)
    }
    pub fn list_workspaces(
        &self,
        context: ProjectQueryContext,
        id: gocode_domain::id::ProjectId,
    ) -> Result<Vec<WorkspaceSnapshot>, ProjectWorkspaceServiceError> {
        self.repository
            .list_workspaces(context.principal.as_str(), id)
            .map_err(map_error)
            .map(|items| items.into_iter().map(workspace_snapshot).collect())
    }
    pub fn get_workspace(
        &self,
        context: ProjectQueryContext,
        id: gocode_domain::id::WorkspaceId,
    ) -> Result<WorkspaceSnapshot, ProjectWorkspaceServiceError> {
        self.repository
            .get_workspace(context.principal.as_str(), id)
            .map_err(map_error)
            .map(workspace_snapshot)
    }
}
fn validate_root_claims(
    current: &RootAdmissionVerificationContext,
    command: &ProjectCommandContext,
    workspace_id: gocode_domain::id::WorkspaceId,
    expected_version: u64,
    claims: &VerifiedRootAdmissionClaims,
) -> Result<(), ProjectWorkspaceServiceError> {
    let claim_context = claims.context();
    let principal_digest =
        RootAdmissionVerificationContext::principal_digest_for(command.principal.as_str());
    let exact_context = claim_context.authority_digest() == current.authority_digest()
        && claim_context.session_id() == current.session_id()
        && claim_context.launch_generation() == current.launch_generation()
        && claim_context.principal_digest() == current.principal_digest()
        && claim_context.capability_version() == current.capability_version()
        && claim_context.policy_version() == current.policy_version()
        && claim_context.gate_epoch() == current.gate_epoch()
        && claim_context.now_unix_millis() == current.now_unix_millis();
    if !exact_context
        || claim_context.principal_digest() != principal_digest
        || claims.action() != RootAdmissionAction::WorkspaceBindRoot
        || claims.workspace_id() != workspace_id
        || claims.expected_version() != expected_version
        || claims.expires_at_unix_millis() <= current.now_unix_millis()
    {
        return Err(ProjectWorkspaceServiceError::Forbidden);
    }
    Ok(())
}

fn map_error(error: ProjectWorkspaceRepositoryError) -> ProjectWorkspaceServiceError {
    match error {
        ProjectWorkspaceRepositoryError::NotFound => ProjectWorkspaceServiceError::NotFound,
        ProjectWorkspaceRepositoryError::Conflict => ProjectWorkspaceServiceError::Conflict,
        ProjectWorkspaceRepositoryError::Forbidden => ProjectWorkspaceServiceError::Forbidden,
        ProjectWorkspaceRepositoryError::Unavailable => ProjectWorkspaceServiceError::Unavailable,
        ProjectWorkspaceRepositoryError::InvariantViolation => {
            ProjectWorkspaceServiceError::InvariantViolation
        }
    }
}
fn map_admission_error(error: RootAdmissionVerifierError) -> ProjectWorkspaceServiceError {
    match error {
        RootAdmissionVerifierError::Rejected => ProjectWorkspaceServiceError::Forbidden,
        RootAdmissionVerifierError::Unavailable => ProjectWorkspaceServiceError::Unavailable,
    }
}
fn project_snapshot(project: Project) -> ProjectSnapshot {
    ProjectSnapshot {
        project_id: project.id(),
        display_name: project.display_name().into(),
        version: project.version(),
        archived: project.archived(),
    }
}
fn workspace_snapshot(workspace: Workspace) -> WorkspaceSnapshot {
    WorkspaceSnapshot {
        workspace_id: workspace.id(),
        project_id: workspace.project_id(),
        display_name: workspace.display_name().into(),
        version: workspace.version(),
        open: workspace.open_state(),
    }
}
fn workspace_ack(workspace: Workspace) -> WorkspaceCommandAck {
    WorkspaceCommandAck {
        workspace_id: workspace.id(),
        new_version: workspace.version(),
    }
}
