use runne_application::ports::{
    ProjectWorkspaceRepositoryError as Error, RootAdmissionAuthorizer, RootAdmissionStoreBinding,
};
use runne_domain::id::{CommandId, IdempotencyKey, WorkspaceId};
use runne_domain::project_workspace::Workspace;
use rusqlite::{Transaction, params};

use crate::codec::{MAX_REHYDRATED_VERSION, ProjectWorkspaceReceipt};
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
        let identity_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM workspace_identity_history
                 WHERE workspace_id = ?1)",
                [workspace.id().as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| Error::Unavailable)?;
        if identity_exists {
            return Err(Error::Conflict);
        }
        let project = load_project(transaction, principal, workspace.project_id())?;
        if project.archived() {
            return Err(Error::Conflict);
        }
        // Project versions encode archived state by parity. Membership changes
        // therefore advance by two so they fence stale destructive summaries
        // without changing the Project's archived state.
        if project.version() > MAX_REHYDRATED_VERSION.saturating_sub(2) {
            return Err(Error::InvariantViolation);
        }
        let advanced = transaction
            .execute(
                "UPDATE projects SET version = version + 2
                 WHERE project_id = ?1 AND principal_id = ?2 AND version = ?3 AND archived = 0",
                params![
                    workspace.project_id().as_bytes(),
                    principal,
                    project.version() as i64
                ],
            )
            .map_err(|_| Error::Unavailable)?;
        if advanced != 1 {
            return Err(Error::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO workspace_identity_history
                 (workspace_id, project_id, principal_id, classification)
                 VALUES (?1, ?2, ?3, 'canonical')",
                params![
                    workspace.id().as_bytes(),
                    workspace.project_id().as_bytes(),
                    principal,
                ],
            )
            .map_err(map_state_insert)?;
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
    mut authorizer: Option<&mut dyn RootAdmissionAuthorizer>,
) -> Result<Workspace, Error> {
    if expected_version >= MAX_REHYDRATED_VERSION {
        return Err(Error::InvariantViolation);
    }
    let scope = Scope::workspace(operation, id.into_bytes());
    store.with_project_workspace_transaction(|transaction| {
        // This runs after BEGIN IMMEDIATE while the caller still holds its authority lease.
        let admission = match authorizer.as_deref_mut() {
            Some(authorizer) => Some(authorizer.authorize_root_admission()?),
            None => None,
        };
        let binding = admission
            .and_then(|admission| admission.into_store_binding(&store.runtime_authority_id().0));
        if authorizer.is_some() && binding.is_none() {
            return Err(Error::Forbidden);
        }
        let request = request(
            store,
            principal,
            command_id,
            key,
            scope,
            None,
            Some(expected_version),
            None,
            binding.as_ref().map(|value| value.admission_digest()),
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
            Operation::BindWorkspaceRoot if binding.is_some() => workspace.bind_root(),
            _ => return Err(Error::InvariantViolation),
        }
        .map_err(|_| Error::Conflict)?;
        if let Some(admission) = binding {
            consume_nonce(
                transaction,
                store,
                principal,
                id,
                expected_version,
                &admission,
            )?;
        }
        update_workspace(transaction, principal, expected_version, &workspace)?;
        receipts::insert(
            transaction,
            &request,
            ProjectWorkspaceReceipt::Workspace(workspace.clone()),
        )?;
        Ok(workspace)
    })
}

fn consume_nonce(
    transaction: &Transaction<'_>,
    store: &StoreTransaction,
    principal: &str,
    id: WorkspaceId,
    expected_version: u64,
    admission: &RootAdmissionStoreBinding,
) -> Result<(), Error> {
    if admission.nonce().iter().all(|value| *value == 0)
        || admission.admission_digest().iter().all(|value| *value == 0)
    {
        return Err(Error::InvariantViolation);
    }
    let consumed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Unavailable)?
        .as_micros();
    let consumed_at = i64::try_from(consumed_at).map_err(|_| Error::Unavailable)?;
    transaction
        .execute(
            "INSERT INTO root_admission_nonces
         (runtime_authority_id, nonce, principal_id, workspace_id, expected_version,
          admission_digest, consumed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                store.runtime_authority_id().0,
                admission.nonce(),
                principal,
                id.as_bytes(),
                expected_version as i64,
                admission.admission_digest(),
                consumed_at
            ],
        )
        .map_err(super::mutation_support::map_state_insert)?;
    Ok(())
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
