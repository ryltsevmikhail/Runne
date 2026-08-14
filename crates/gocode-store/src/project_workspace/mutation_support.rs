use gocode_application::ports::ProjectWorkspaceRepositoryError as Error;
use gocode_domain::id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId};
use gocode_domain::project_workspace::{Project, Workspace};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::codec::ProjectWorkspaceReceipt;
use crate::store::StoreTransaction;

use super::fingerprint::{FingerprintInput, semantic_fingerprint};
use super::receipts::{ReceiptRequest, Scope};
use super::records::{project_from_row, workspace_from_row};

#[allow(clippy::too_many_arguments)]
pub(super) fn request<'a>(
    store: &'a StoreTransaction,
    principal: &'a str,
    command_id: CommandId,
    key: &'a IdempotencyKey,
    scope: Scope,
    related_id: Option<[u8; 16]>,
    expected_version: Option<u64>,
    display_name: Option<&str>,
    admission_digest: Option<&[u8; 32]>,
) -> ReceiptRequest<'a> {
    let authority = &store.runtime_authority_id().0;
    let fingerprint = semantic_fingerprint(FingerprintInput {
        authority,
        principal,
        command_id,
        key,
        scope,
        related_id,
        expected_version,
        display_name,
        admission_digest,
    });
    ReceiptRequest {
        authority,
        principal,
        command_id,
        key,
        scope,
        fingerprint,
    }
}

pub(super) fn load_project(
    transaction: &Transaction<'_>,
    principal: &str,
    id: ProjectId,
) -> Result<Project, Error> {
    transaction
        .query_row(
            "SELECT project_id, display_name, version, archived FROM projects
             WHERE project_id = ?1 AND principal_id = ?2",
            params![id.as_bytes(), principal],
            project_from_row,
        )
        .optional()
        .map_err(|_| Error::InvariantViolation)?
        .ok_or(Error::NotFound)
}

pub(super) fn load_workspace(
    transaction: &Transaction<'_>,
    principal: &str,
    id: WorkspaceId,
) -> Result<Workspace, Error> {
    transaction
        .query_row(
            "SELECT workspace_id, project_id, display_name, version, open FROM workspaces
             WHERE workspace_id = ?1 AND principal_id = ?2 AND live = 1",
            params![id.as_bytes(), principal],
            workspace_from_row,
        )
        .optional()
        .map_err(|_| Error::InvariantViolation)?
        .ok_or(Error::NotFound)
}

pub(super) fn receipt_project(
    receipt: ProjectWorkspaceReceipt,
    id: ProjectId,
) -> Result<Project, Error> {
    match receipt {
        ProjectWorkspaceReceipt::Project(value) if value.id() == id => Ok(value),
        _ => Err(Error::InvariantViolation),
    }
}

pub(super) fn receipt_workspace(
    receipt: ProjectWorkspaceReceipt,
    id: WorkspaceId,
) -> Result<Workspace, Error> {
    match receipt {
        ProjectWorkspaceReceipt::Workspace(value) if value.id() == id => Ok(value),
        _ => Err(Error::InvariantViolation),
    }
}

pub(super) fn map_state_insert(error: rusqlite::Error) -> Error {
    if matches!(error, rusqlite::Error::SqliteFailure(ref code, _) if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE || code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY)
    {
        Error::Conflict
    } else {
        Error::Unavailable
    }
}
