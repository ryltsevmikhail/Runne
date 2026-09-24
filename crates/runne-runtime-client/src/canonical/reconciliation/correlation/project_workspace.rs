use super::super::reconciliation_wire::OutcomeWire;
use super::super::{
    CommandReconciliationOutcome, CommandReconciliationWitness, ProjectCommandAcknowledgement,
    RuntimeApiError, WorkspaceCommandAcknowledgement, invalid_response,
};

pub(super) fn correlate_project(
    witness: &CommandReconciliationWitness,
    outcome: OutcomeWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    let next = |value: u64| value.checked_add(1).ok_or_else(invalid_response);
    match (witness, outcome) {
        (
            CommandReconciliationWitness::CreateProject { project_id, .. },
            OutcomeWire::CreateProject {
                project_id: id,
                new_version: 1,
            },
        ) if *project_id == id => Ok(CommandReconciliationOutcome::ProjectCreated(
            ProjectCommandAcknowledgement::observed(id, 1),
        )),
        (
            CommandReconciliationWitness::ArchiveProject {
                project_id,
                expected_version,
            },
            OutcomeWire::ArchiveProject {
                project_id: id,
                new_version,
            },
        ) if *project_id == id && next(*expected_version)? == new_version => {
            Ok(CommandReconciliationOutcome::ProjectArchived(
                ProjectCommandAcknowledgement::observed(id, new_version),
            ))
        }
        (
            CommandReconciliationWitness::DeleteProject {
                project_id,
                expected_version,
            },
            OutcomeWire::DeleteProject {
                project_id: id,
                new_version,
            },
        ) if *project_id == id && next(*expected_version)? == new_version => {
            Ok(CommandReconciliationOutcome::ProjectDeleted(
                ProjectCommandAcknowledgement::observed(id, new_version),
            ))
        }
        (
            CommandReconciliationWitness::RenameProject {
                project_id,
                expected_version,
                ..
            },
            OutcomeWire::RenameProject {
                project_id: id,
                new_version,
            },
        ) if *project_id == id && next(*expected_version)? == new_version => {
            Ok(CommandReconciliationOutcome::ProjectRenamed(
                ProjectCommandAcknowledgement::observed(id, new_version),
            ))
        }
        _ => Err(invalid_response()),
    }
}

pub(super) fn correlate_workspace(
    witness: &CommandReconciliationWitness,
    outcome: OutcomeWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    let next = |value: u64| value.checked_add(1).ok_or_else(invalid_response);
    match (witness, outcome) {
        (
            CommandReconciliationWitness::CreateWorkspace { workspace_id, .. },
            OutcomeWire::CreateWorkspace {
                workspace_id: id,
                new_version: 1,
            },
        ) if *workspace_id == id => Ok(CommandReconciliationOutcome::WorkspaceCreated(
            WorkspaceCommandAcknowledgement::observed(id, 1),
        )),
        (
            CommandReconciliationWitness::BindWorkspaceRoot {
                workspace_id,
                expected_version,
                ..
            },
            OutcomeWire::BindWorkspaceRoot {
                workspace_id: id,
                new_version,
            },
        ) if *workspace_id == id && next(*expected_version)? == new_version => {
            Ok(CommandReconciliationOutcome::WorkspaceRootBound(
                WorkspaceCommandAcknowledgement::observed(id, new_version),
            ))
        }
        (
            CommandReconciliationWitness::OpenWorkspace {
                workspace_id,
                expected_version,
            },
            OutcomeWire::OpenWorkspace {
                workspace_id: id,
                new_version,
            },
        ) if *workspace_id == id && next(*expected_version)? == new_version => {
            Ok(CommandReconciliationOutcome::WorkspaceOpened(
                WorkspaceCommandAcknowledgement::observed(id, new_version),
            ))
        }
        _ => Err(invalid_response()),
    }
}
