use runne_application::permission_modes::{
    ModeSelection, PermissionModeChangeReceipt, PermissionModeHistoryProjection,
    SetPermissionModeCommand,
};
use runne_domain::id::CommandId;
use rusqlite::{OptionalExtension, Transaction, params};

use super::super::{identity, model::PermissionModeStoreError, receipt_codec};

#[derive(Debug)]
struct StoredReceipt {
    command_id: Vec<u8>,
    runtime_authority_id: String,
    principal_id: String,
    workspace_id: Vec<u8>,
    project_id: Vec<u8>,
    idempotency_key: String,
    intent_digest: Vec<u8>,
    selected_mode: i64,
    preset_version: i64,
    authorization_revision: i64,
    managed_policy_version: i64,
    managed_policy_digest: Vec<u8>,
    expires_at: Option<i64>,
    history_projection: Vec<u8>,
}

pub(super) fn lookup(
    tx: &Transaction<'_>,
    command: &SetPermissionModeCommand,
) -> Result<Option<PermissionModeChangeReceipt>, PermissionModeStoreError> {
    let by_id = find_by_id(tx, command.command_id)?;
    let by_key = find_by_key(tx, command)?;
    if let (Some(left), Some(right)) = (&by_id, &by_key)
        && left.command_id != right.command_id
    {
        return Err(PermissionModeStoreError::Command(
            runne_application::permission_modes::PermissionModeError::IdempotencyConflict,
        ));
    }
    let Some(row) = by_id.or(by_key) else {
        return Ok(None);
    };
    if row.command_id.as_slice() != command.command_id.as_bytes()
        || row.runtime_authority_id != command.scope.runtime_authority_id.0
        || row.principal_id != command.scope.principal_id.as_str()
        || row.workspace_id.as_slice() != command.scope.workspace_id.as_bytes()
        || row.idempotency_key != command.idempotency_key.as_str()
        || row.intent_digest.as_slice() != command.intent_digest.as_bytes()
        || row.selected_mode != identity::mode_tag(command.requested_mode)
        || row.preset_version != i64::from(command.preset_version.as_u16())
        || row.managed_policy_version != i64::try_from(command.managed_policy_version).unwrap_or(-1)
        || row.managed_policy_digest.as_slice() != command.managed_policy_digest.as_bytes()
        || row.expires_at != command.expires_at_unix_ms
    {
        return Err(PermissionModeStoreError::Command(
            runne_application::permission_modes::PermissionModeError::IdempotencyConflict,
        ));
    }
    let _: [u8; 16] = row
        .project_id
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let projection = receipt_codec::decode_history(&row.history_projection)?;
    if projection.selected_mode != command.requested_mode
        || projection.authorization_revision
            != u64::try_from(row.authorization_revision)
                .map_err(|_| PermissionModeStoreError::CorruptData)?
        || projection.preset_version.as_u16()
            != u16::try_from(row.preset_version)
                .map_err(|_| PermissionModeStoreError::CorruptData)?
        || projection.managed_policy_version
            != u64::try_from(row.managed_policy_version)
                .map_err(|_| PermissionModeStoreError::CorruptData)?
        || projection.expires_at_unix_ms != row.expires_at
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let selection = ModeSelection {
        scope: command.scope.clone(),
        selected_mode: identity::mode_from_tag(row.selected_mode)?,
        preset_version: identity::preset_version(row.preset_version)?,
        authorization_revision: u64::try_from(row.authorization_revision)
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
        expires_at_unix_ms: row.expires_at,
    };
    Ok(Some(PermissionModeChangeReceipt {
        command_id: command.command_id,
        idempotency_key: command.idempotency_key.clone(),
        intent_digest: command.intent_digest,
        selection,
        projection,
    }))
}

pub(super) fn check_command_id_available(
    tx: &Transaction<'_>,
    command: &SetPermissionModeCommand,
) -> Result<(), PermissionModeStoreError> {
    let collision: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM command_receipts WHERE command_id=?1)
            OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=?1)",
            [command.command_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if collision {
        return Err(PermissionModeStoreError::Command(
            runne_application::permission_modes::PermissionModeError::IdempotencyConflict,
        ));
    }
    Ok(())
}

pub(super) fn insert(
    tx: &Transaction<'_>,
    command: &SetPermissionModeCommand,
    project_id: [u8; 16],
    revision: i64,
    committed_at: i64,
    history: &PermissionModeHistoryProjection,
) -> Result<(), PermissionModeStoreError> {
    let bytes = receipt_codec::encode_history(history)?;
    tx.execute(
        "INSERT INTO permission_mode_command_receipts (
           command_id,runtime_authority_id,principal_id,workspace_id,project_id,idempotency_key,
           intent_digest,selected_mode,preset_version,authorization_revision,managed_policy_version,
           managed_policy_digest,expires_at_unix_ms,history_projection,committed_at_unix_ms
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        params![
            command.command_id.as_bytes().as_slice(),
            command.scope.runtime_authority_id.0,
            command.scope.principal_id.as_str(),
            command.scope.workspace_id.as_bytes().as_slice(),
            project_id.as_slice(),
            command.idempotency_key.as_str(),
            command.intent_digest.as_bytes().as_slice(),
            identity::mode_tag(command.requested_mode),
            i64::from(command.preset_version.as_u16()),
            revision,
            i64::try_from(command.managed_policy_version)
                .map_err(|_| PermissionModeStoreError::ManagedPolicyStale)?,
            command.managed_policy_digest.as_bytes().as_slice(),
            command.expires_at_unix_ms,
            bytes,
            committed_at
        ],
    )
    .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(())
}

fn find_by_id(
    tx: &Transaction<'_>,
    id: CommandId,
) -> Result<Option<StoredReceipt>, PermissionModeStoreError> {
    tx.query_row("SELECT command_id,runtime_authority_id,principal_id,workspace_id,project_id,idempotency_key,
       intent_digest,selected_mode,preset_version,authorization_revision,managed_policy_version,
       managed_policy_digest,expires_at_unix_ms,history_projection FROM permission_mode_command_receipts WHERE command_id=?1",
       [id.as_bytes().as_slice()], stored_from_sql).optional().map_err(|_| PermissionModeStoreError::Unavailable)
}

fn find_by_key(
    tx: &Transaction<'_>,
    command: &SetPermissionModeCommand,
) -> Result<Option<StoredReceipt>, PermissionModeStoreError> {
    tx.query_row("SELECT command_id,runtime_authority_id,principal_id,workspace_id,project_id,idempotency_key,
       intent_digest,selected_mode,preset_version,authorization_revision,managed_policy_version,
       managed_policy_digest,expires_at_unix_ms,history_projection FROM permission_mode_command_receipts
       WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3 AND idempotency_key=?4",
       params![command.scope.runtime_authority_id.0, command.scope.principal_id.as_str(), command.scope.workspace_id.as_bytes(), command.idempotency_key.as_str()],
       stored_from_sql).optional().map_err(|_| PermissionModeStoreError::Unavailable)
}

fn stored_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredReceipt> {
    Ok(StoredReceipt {
        command_id: row.get(0)?,
        runtime_authority_id: row.get(1)?,
        principal_id: row.get(2)?,
        workspace_id: row.get(3)?,
        project_id: row.get(4)?,
        idempotency_key: row.get(5)?,
        intent_digest: row.get(6)?,
        selected_mode: row.get(7)?,
        preset_version: row.get(8)?,
        authorization_revision: row.get(9)?,
        managed_policy_version: row.get(10)?,
        managed_policy_digest: row.get(11)?,
        expires_at: row.get(12)?,
        history_projection: row.get(13)?,
    })
}
