use gocode_application::ports::ProjectWorkspaceRepositoryError as Error;
use gocode_domain::id::{CommandId, IdempotencyKey};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::codec::{
    IdempotencyScopeCodec, ProjectWorkspaceReceipt, ProjectWorkspaceReceiptCodec, StoreCodec,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Operation {
    CreateProject = 1,
    ArchiveProject = 2,
    RestoreProject = 3,
    DeleteProject = 4,
    CreateWorkspace = 5,
    OpenWorkspace = 6,
    BindWorkspaceRoot = 7,
}

#[derive(Clone, Copy)]
pub(super) struct Scope {
    pub operation: Operation,
    pub aggregate_kind: u8,
    pub aggregate_id: [u8; 16],
}

impl Scope {
    pub fn project(operation: Operation, aggregate_id: [u8; 16]) -> Self {
        Self {
            operation,
            aggregate_kind: 1,
            aggregate_id,
        }
    }

    pub fn workspace(operation: Operation, aggregate_id: [u8; 16]) -> Self {
        Self {
            operation,
            aggregate_kind: 2,
            aggregate_id,
        }
    }
}

pub(super) struct ReceiptRequest<'a> {
    pub authority: &'a str,
    pub principal: &'a str,
    pub command_id: CommandId,
    pub key: &'a IdempotencyKey,
    pub scope: Scope,
    pub fingerprint: [u8; 32],
}

pub(super) fn lookup(
    transaction: &Transaction<'_>,
    request: &ReceiptRequest<'_>,
) -> Result<Option<ProjectWorkspaceReceipt>, Error> {
    let taskrun_collision = transaction
        .query_row(
            "SELECT idempotency_scope_bytes, idempotency_key, fingerprint
             FROM command_receipts WHERE command_id = ?1",
            params![request.command_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| Error::Unavailable)?;
    if let Some((scope, key, fingerprint)) = taskrun_collision {
        IdempotencyScopeCodec
            .decode(&scope)
            .map_err(|_| Error::InvariantViolation)?;
        let key = String::from_utf8(key).map_err(|_| Error::InvariantViolation)?;
        IdempotencyKey::new(key).map_err(|_| Error::InvariantViolation)?;
        let _: [u8; 32] = fingerprint
            .try_into()
            .map_err(|_| Error::InvariantViolation)?;
        return Err(Error::Conflict);
    }
    let by_command = transaction
        .query_row(
            "SELECT runtime_authority_id, principal_id, operation, aggregate_kind,
                    aggregate_id, idempotency_key, semantic_fingerprint, outcome
             FROM project_workspace_command_receipts WHERE command_id = ?1",
            params![request.command_id.as_bytes()],
            |row| {
                Ok(StoredReceipt {
                    authority: row.get(0)?,
                    principal: row.get(1)?,
                    operation: row.get(2)?,
                    aggregate_kind: row.get(3)?,
                    aggregate_id: row.get(4)?,
                    key: row.get(5)?,
                    fingerprint: row.get(6)?,
                    outcome: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|_| Error::Unavailable)?;
    if let Some(stored) = by_command {
        if !stored.matches(request) {
            return Err(Error::Conflict);
        }
        return decode(stored.outcome).map(Some);
    }
    let scoped_collision = transaction
        .query_row(
            "SELECT 1 FROM project_workspace_command_receipts
             WHERE runtime_authority_id = ?1 AND principal_id = ?2 AND operation = ?3
               AND aggregate_kind = ?4 AND aggregate_id = ?5 AND idempotency_key = ?6",
            params![
                request.authority,
                request.principal,
                request.scope.operation as i64,
                request.scope.aggregate_kind as i64,
                request.scope.aggregate_id,
                request.key.as_str(),
            ],
            |_| Ok(()),
        )
        .optional()
        .map_err(|_| Error::Unavailable)?
        .is_some();
    if scoped_collision {
        Err(Error::Conflict)
    } else {
        Ok(None)
    }
}

pub(super) fn insert(
    transaction: &Transaction<'_>,
    request: &ReceiptRequest<'_>,
    outcome: ProjectWorkspaceReceipt,
) -> Result<(), Error> {
    let bytes = ProjectWorkspaceReceiptCodec
        .encode(&outcome)
        .map_err(|_| Error::InvariantViolation)?;
    let committed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Unavailable)?
        .as_micros();
    let committed_at = i64::try_from(committed_at).map_err(|_| Error::Unavailable)?;
    transaction
        .execute(
            "INSERT INTO project_workspace_command_receipts
             (command_id, runtime_authority_id, principal_id, operation, aggregate_kind,
              aggregate_id, idempotency_key, semantic_fingerprint, outcome, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                request.command_id.as_bytes(),
                request.authority,
                request.principal,
                request.scope.operation as i64,
                request.scope.aggregate_kind as i64,
                request.scope.aggregate_id,
                request.key.as_str(),
                request.fingerprint,
                bytes,
                committed_at,
            ],
        )
        .map_err(|_| Error::InvariantViolation)?;
    Ok(())
}

fn decode(bytes: Vec<u8>) -> Result<ProjectWorkspaceReceipt, Error> {
    ProjectWorkspaceReceiptCodec
        .decode(&bytes)
        .map_err(|_| Error::InvariantViolation)
}

struct StoredReceipt {
    authority: String,
    principal: String,
    operation: i64,
    aggregate_kind: i64,
    aggregate_id: Vec<u8>,
    key: String,
    fingerprint: Vec<u8>,
    outcome: Vec<u8>,
}

impl StoredReceipt {
    fn matches(&self, request: &ReceiptRequest<'_>) -> bool {
        self.authority == request.authority
            && self.principal == request.principal
            && self.operation == request.scope.operation as i64
            && self.aggregate_kind == request.scope.aggregate_kind as i64
            && self.aggregate_id == request.scope.aggregate_id
            && self.key == request.key.as_str()
            && self.fingerprint == request.fingerprint
    }
}
