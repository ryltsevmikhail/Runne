//! Principal-bound Project and Workspace application service.
use crate::ports::{
    CurrentRootAdmissionContext, ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError,
    RootAdmissionVerifier, RootAdmissionVerifierError,
};
use runne_api::{
    BindWorkspaceRootCommand, CreateProjectCommand, CreateWorkspaceCommand, ExistingProjectCommand,
    ExistingWorkspaceCommand, ProjectCommandAck, ProjectCommandContext, ProjectPage,
    ProjectPageRequest, ProjectQueryContext, ProjectSnapshot, RenameProjectCommand,
    WorkspaceCommandAck, WorkspacePage, WorkspacePageRequest, WorkspaceSnapshot,
};
use runne_domain::project_workspace::{Project, Workspace};
mod root_admission;
use root_admission::VerifiedRootAdmissionAuthorizer;
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
        let name = command.display_name.into_domain();
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
    pub fn rename_project(
        &self,
        context: ProjectCommandContext,
        command: RenameProjectCommand,
    ) -> Result<ProjectCommandAck, ProjectWorkspaceServiceError> {
        let project = self
            .repository
            .rename_project(
                context.principal.as_str(),
                context.command_id,
                &context.idempotency_key,
                command.project_id,
                command.expected_version,
                command.display_name.into_domain(),
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
        let name = command.display_name.into_domain();
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
        // Normalize absent and foreign Workspace identities before touching the
        // protected admission authority. The transaction below rechecks the
        // same ownership and version, so this is only a nondisclosure preflight.
        self.repository
            .get_workspace(context.principal.as_str(), command.workspace_id)
            .map_err(map_error)?;
        // Global lock order: authority lease, then SQLite writer. The lease is
        // retained by `authorizer` until the repository has committed or rolled back.
        let lease = self
            .current_admission
            .acquire_root_admission_lease()
            .map_err(map_admission_error)?;
        let claims = self
            .admission_verifier
            .verify_root_admission(command.root_admission)
            .map_err(map_admission_error)?;
        let mut authorizer = VerifiedRootAdmissionAuthorizer::new(
            lease,
            claims,
            &context,
            command.workspace_id,
            command.expected_version,
        );
        let workspace = self
            .repository
            .bind_workspace_root(
                context.principal.as_str(),
                context.command_id,
                &context.idempotency_key,
                command.workspace_id,
                command.expected_version,
                &mut authorizer,
            )
            .map_err(map_error)?;
        Ok(workspace_ack(workspace))
    }
}
include!("project_workspace_queries.rs");
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
