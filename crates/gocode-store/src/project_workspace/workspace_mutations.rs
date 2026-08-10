use gocode_application::ports::ProjectWorkspaceRepositoryError as Error;
use gocode_domain::id::{CommandId, IdempotencyKey, WorkspaceId};
use gocode_domain::project_workspace::Workspace;
use rusqlite::{Transaction, params};

use crate::codec::ProjectWorkspaceReceipt;
use crate::store::StoreTransaction;

use super::mutation_support::{
    load_project, load_workspace, map_state_insert, receipt_workspace, request,
};
use super::receipts::{self, Operation, Scope};

pub(super) fn create_workspace(
    store: &StoreTransaction,
    principal: &str,
    command_id: CommandId,
    key: &IdempotencyKey,
    workspace: Workspace,
) -> Result<Workspace, Error> {
    if workspace.version() != 1 || workspace.open_state() {
        return Err(Error::Conflict);
    }
    let scope = Scope::workspace(Operation::CreateWorkspace, workspace.id().into_bytes());
    store.with_project_workspace_transaction(|transaction| {
        let request = request(
            store,
            principal,
            command_id,
            key,
            scope,
            Some(workspace.project_id().into_bytes()),
            None,
            Some(workspace.display_name()),
            None,
        );
        if let Some(receipt) = receipts::lookup(transaction, &request)? {
            return receipt_workspace(receipt, workspace.id());
        }
        let project = load_project(transaction, principal, workspace.project_id())?;
        if project.archived() {
            return Err(Error::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO workspaces
                 (workspace_id, project_id, principal_id, display_name, version, open, live)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
                params![
                    workspace.id().as_bytes(),
                    workspace.project_id().as_bytes(),
                    principal,
                    workspace.display_name(),
                    workspace.version() as i64,
                    i64::from(workspace.open_state()),
                ],
            )
            .map_err(map_state_insert)?;
        receipts::insert(
            transaction,
            &request,
            ProjectWorkspaceReceipt::Workspace(workspace.clone()),
        )?;
        Ok(workspace.clone())
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn change_workspace(
    store: &StoreTransaction,
    principal: &str,
    command_id: CommandId,
    key: &IdempotencyKey,
    id: WorkspaceId,
    expected_version: u64,
    operation: Operation,
    admission_digest: Option<&[u8; 32]>,
) -> Result<Workspace, Error> {
    let scope = Scope::workspace(operation, id.into_bytes());
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
            admission_digest,
        );
        if let Some(receipt) = receipts::lookup(transaction, &request)? {
            return receipt_workspace(receipt, id);
        }
        let mut workspace = load_workspace(transaction, principal, id)?;
        if workspace.version() != expected_version {
            return Err(Error::Conflict);
        }
        match operation {
            Operation::OpenWorkspace => workspace.open(),
            Operation::BindWorkspaceRoot if admission_digest.is_some() => workspace.bind_root(),
            _ => return Err(Error::InvariantViolation),
        }
        .map_err(|_| Error::Conflict)?;
        update_workspace(transaction, principal, expected_version, &workspace)?;
        receipts::insert(
            transaction,
            &request,
            ProjectWorkspaceReceipt::Workspace(workspace.clone()),
        )?;
        Ok(workspace)
    })
}

fn update_workspace(
    transaction: &Transaction<'_>,
    principal: &str,
    expected_version: u64,
    workspace: &Workspace,
) -> Result<(), Error> {
    let updated = transaction
        .execute(
            "UPDATE workspaces SET version = ?1, open = ?2
             WHERE workspace_id = ?3 AND principal_id = ?4 AND version = ?5 AND live = 1",
            params![
                workspace.version() as i64,
                i64::from(workspace.open_state()),
                workspace.id().as_bytes(),
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
