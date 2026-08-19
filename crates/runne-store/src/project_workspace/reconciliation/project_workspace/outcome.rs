use runne_api::{
    AuthoritativeCommandOutcome, CommandReconciliationWitness, CommandReconciliationWitnessRef,
    ProjectCommandAck, WorkspaceCommandAck,
};
use runne_application::command_reconciliation::CommandReconciliationRepositoryError as Error;

use crate::codec::ProjectWorkspaceReceipt;

pub(super) fn outcome_for(
    witness: &CommandReconciliationWitness,
    receipt: ProjectWorkspaceReceipt,
) -> Result<AuthoritativeCommandOutcome, Error> {
    match (witness.view(), receipt) {
        (
            CommandReconciliationWitnessRef::CreateProject { project_id, .. },
            ProjectWorkspaceReceipt::Project(project),
        ) if project.id() == project_id && project.version() == 1 => Ok(
            AuthoritativeCommandOutcome::project_created(ProjectCommandAck {
                project_id,
                new_version: 1,
            }),
        ),
        (
            CommandReconciliationWitnessRef::ArchiveProject {
                project_id,
                expected_version,
            },
            ProjectWorkspaceReceipt::Project(project),
        ) if project.id() == project_id
            && project.version() == next_version(expected_version)?
            && project.archived() =>
        {
            Ok(AuthoritativeCommandOutcome::project_archived(
                ProjectCommandAck {
                    project_id,
                    new_version: project.version(),
                },
            ))
        }
        (
            CommandReconciliationWitnessRef::DeleteProject {
                project_id,
                expected_version,
            },
            ProjectWorkspaceReceipt::ProjectDeleted {
                project_id: stored,
                new_version,
            },
        ) if stored == project_id && new_version == next_version(expected_version)? => Ok(
            AuthoritativeCommandOutcome::project_deleted(ProjectCommandAck {
                project_id,
                new_version,
            }),
        ),
        (
            CommandReconciliationWitnessRef::CreateWorkspace {
                workspace_id,
                project_id,
                ..
            },
            ProjectWorkspaceReceipt::Workspace(workspace),
        ) if workspace.id() == workspace_id
            && workspace.project_id() == project_id
            && workspace.version() == 1 =>
        {
            Ok(AuthoritativeCommandOutcome::workspace_created(
                WorkspaceCommandAck {
                    workspace_id,
                    new_version: 1,
                },
            ))
        }
        (
            CommandReconciliationWitnessRef::BindWorkspaceRoot {
                workspace_id,
                expected_version,
                ..
            },
            ProjectWorkspaceReceipt::Workspace(workspace),
        ) if workspace.id() == workspace_id
            && workspace.version() == next_version(expected_version)? =>
        {
            Ok(AuthoritativeCommandOutcome::workspace_root_bound(
                WorkspaceCommandAck {
                    workspace_id,
                    new_version: workspace.version(),
                },
            ))
        }
        (
            CommandReconciliationWitnessRef::OpenWorkspace {
                workspace_id,
                expected_version,
            },
            ProjectWorkspaceReceipt::Workspace(workspace),
        ) if workspace.id() == workspace_id
            && workspace.version() == next_version(expected_version)?
            && workspace.open_state() =>
        {
            Ok(AuthoritativeCommandOutcome::workspace_opened(
                WorkspaceCommandAck {
                    workspace_id,
                    new_version: workspace.version(),
                },
            ))
        }
        _ => Err(Error::InvariantViolation),
    }
}

fn next_version(expected_version: u64) -> Result<u64, Error> {
    expected_version
        .checked_add(1)
        .ok_or(Error::InvariantViolation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_domain::id::{ProjectId, WorkspaceId};
    use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};

    fn project() -> ProjectId {
        "018f47a2-4f8c-7b52-8c35-7a3a14c2d902".parse().unwrap()
    }
    fn workspace() -> WorkspaceId {
        "018f47a2-4f8c-7b52-8c35-7a3a14c2d903".parse().unwrap()
    }
    fn name() -> ProjectWorkspaceDisplayName {
        ProjectWorkspaceDisplayName::new("Name".into()).unwrap()
    }

    #[test]
    fn maximum_expected_version_is_an_invariant_violation_without_panicking() {
        let version = u64::MAX;
        let project_receipt =
            || ProjectWorkspaceReceipt::Project(Project::create(project(), name()));
        let workspace_receipt = || {
            ProjectWorkspaceReceipt::Workspace(Workspace::create(workspace(), project(), name()))
        };
        for (witness, receipt) in [
            (
                CommandReconciliationWitness::archive_project(project(), version),
                project_receipt(),
            ),
            (
                CommandReconciliationWitness::delete_project(project(), version),
                ProjectWorkspaceReceipt::ProjectDeleted {
                    project_id: project(),
                    new_version: 1,
                },
            ),
            (
                CommandReconciliationWitness::bind_workspace_root(workspace(), version, [0; 32]),
                workspace_receipt(),
            ),
            (
                CommandReconciliationWitness::open_workspace(workspace(), version),
                workspace_receipt(),
            ),
        ] {
            assert_eq!(
                outcome_for(&witness, receipt),
                Err(Error::InvariantViolation)
            );
        }
    }
}
