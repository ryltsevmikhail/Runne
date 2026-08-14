use gocode_application::ports::ProjectWorkspaceRepositoryError as Error;
use gocode_domain::id::{CommandId, IdempotencyKey, ProjectId};
use gocode_domain::project_workspace::Project;
use rusqlite::{Transaction, params};

use crate::codec::{MAX_REHYDRATED_VERSION, ProjectWorkspaceReceipt};
use crate::store::StoreTransaction;

use super::mutation_support::{load_project, map_state_insert, receipt_project, request};
use super::receipts::{self, Operation, Scope};
use super::taskrun_fence::ensure_project_task_runs_terminal;

pub(super) fn create_project(
    store: &StoreTransaction,
    principal: &str,
    command_id: CommandId,
    key: &IdempotencyKey,
    project: Project,
) -> Result<Project, Error> {
    if project.version() != 1 || project.archived() {
        return Err(Error::Conflict);
    }
    let scope = Scope::project(Operation::CreateProject, project.id().into_bytes());
    store.with_project_workspace_transaction(|transaction| {
        let request = request(
            store,
            principal,
            command_id,
            key,
            scope,
            None,
            None,
            Some(project.display_name()),
            None,
        );
        if let Some(receipt) = receipts::lookup(transaction, &request)? {
            return receipt_project(receipt, project.id());
        }
        transaction
            .execute(
                "INSERT INTO projects
                 (project_id, principal_id, display_name, version, archived)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    project.id().as_bytes(),
                    principal,
                    project.display_name(),
                    project.version() as i64,
                    i64::from(project.archived()),
                ],
            )
            .map_err(map_state_insert)?;
        receipts::insert(
            transaction,
            &request,
            ProjectWorkspaceReceipt::Project(project.clone()),
        )?;
        Ok(project.clone())
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn change_project(
    store: &StoreTransaction,
    principal: &str,
    command_id: CommandId,
    key: &IdempotencyKey,
    id: ProjectId,
    expected_version: u64,
    operation: Operation,
) -> Result<Project, Error> {
    if expected_version >= MAX_REHYDRATED_VERSION {
        return Err(Error::InvariantViolation);
    }
    let scope = Scope::project(operation, id.into_bytes());
    store.with_project_workspace_transaction(|transaction| {
        let request = request(
            store,
            principal,
            command_id,
            key,
            scope,
            None,
            Some(expected_version),
            None,
            None,
        );
        if let Some(receipt) = receipts::lookup(transaction, &request)? {
            return receipt_project(receipt, id);
        }
        let mut project = load_project(transaction, principal, id)?;
        if project.version() != expected_version {
            return Err(Error::Conflict);
        }
        match operation {
            Operation::ArchiveProject => project.archive(),
            Operation::RestoreProject => project.restore(),
            _ => return Err(Error::InvariantViolation),
        }
        .map_err(|_| Error::Conflict)?;
        update_project(transaction, principal, expected_version, &project)?;
        receipts::insert(
            transaction,
            &request,
            ProjectWorkspaceReceipt::Project(project.clone()),
        )?;
        Ok(project)
    })
}

pub(super) fn delete_project(
    store: &StoreTransaction,
    principal: &str,
    command_id: CommandId,
    key: &IdempotencyKey,
    id: ProjectId,
    expected_version: u64,
) -> Result<u64, Error> {
    if expected_version >= MAX_REHYDRATED_VERSION {
        return Err(Error::InvariantViolation);
    }
    let scope = Scope::project(Operation::DeleteProject, id.into_bytes());
    store.with_project_workspace_transaction(|transaction| {
        let request = request(
            store,
            principal,
            command_id,
            key,
            scope,
            None,
            Some(expected_version),
            None,
            None,
        );
        if let Some(receipt) = receipts::lookup(transaction, &request)? {
            return receipt_delete(receipt, id);
        }
        let project = load_project(transaction, principal, id)?;
        if project.version() != expected_version {
            return Err(Error::Conflict);
        }
        ensure_project_task_runs_terminal(transaction, id)?;
        let live: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM workspaces WHERE project_id = ?1 AND live = 1",
                [id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| Error::Unavailable)?;
        if live != 0 {
            return Err(Error::Conflict);
        }
        let new_version = expected_version
            .checked_add(1)
            .ok_or(Error::InvariantViolation)?;
        let deleted = transaction
            .execute(
                "DELETE FROM projects WHERE project_id = ?1 AND principal_id = ?2
                 AND version = ?3",
                params![id.as_bytes(), principal, expected_version as i64],
            )
            .map_err(|_| Error::Unavailable)?;
        if deleted != 1 {
            return Err(Error::Conflict);
        }
        receipts::insert(
            transaction,
            &request,
            ProjectWorkspaceReceipt::ProjectDeleted {
                project_id: id,
                new_version,
            },
        )?;
        Ok(new_version)
    })
}

fn update_project(
    transaction: &Transaction<'_>,
    principal: &str,
    expected_version: u64,
    project: &Project,
) -> Result<(), Error> {
    let updated = transaction
        .execute(
            "UPDATE projects SET version = ?1, archived = ?2
             WHERE project_id = ?3 AND principal_id = ?4 AND version = ?5",
            params![
                project.version() as i64,
                i64::from(project.archived()),
                project.id().as_bytes(),
                principal,
                expected_version as i64,
            ],
        )
        .map_err(|_| Error::Unavailable)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

fn receipt_delete(receipt: ProjectWorkspaceReceipt, id: ProjectId) -> Result<u64, Error> {
    match receipt {
        ProjectWorkspaceReceipt::ProjectDeleted {
            project_id,
            new_version,
        } if project_id == id => Ok(new_version),
        _ => Err(Error::InvariantViolation),
    }
}
