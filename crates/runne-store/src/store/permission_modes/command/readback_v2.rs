use runne_application::permission_modes::{
    ModeSelection, PermissionModeChangeReceipt, PermissionScope,
};
use runne_domain::id::{CommandId, IntegrityDigest};
use rusqlite::{OptionalExtension, Transaction, params};

use super::super::{ceremony_v2, identity, model::*, receipt_codec};
use super::receipt::{self, StoredReceipt};
use crate::store::StoreTransaction;

pub(super) fn load_status(
    store: &StoreTransaction,
    scope: &runne_application::permission_modes::PermissionScope,
    principal: &runne_api::ApiPrincipalId,
    command_id: runne_domain::id::CommandId,
) -> Result<Option<PermissionModeCeremonyStatusV2>, PermissionModeStoreError> {
    ceremony_v2::load_status(store, scope, principal, command_id)
}

pub(super) fn cancel(
    store: &StoreTransaction,
    scope: &runne_application::permission_modes::PermissionScope,
    principal: &runne_api::ApiPrincipalId,
    command_id: runne_domain::id::CommandId,
) -> Result<Option<PermissionModeCeremonyStatusV2>, PermissionModeStoreError> {
    ceremony_v2::cancel(store, scope, principal, command_id)
}

pub(in crate::store::permission_modes) fn lookup_by_scope_and_id(
    tx: &Transaction<'_>,
    command_id: CommandId,
    scope: &PermissionScope,
) -> Result<Option<PermissionModeChangeReceipt>, PermissionModeStoreError> {
    let Some(row) = receipt::find_by_id(tx, command_id)? else {
        return Ok(None);
    };
    if row.command_id.as_slice() != command_id.as_bytes()
        || row.runtime_authority_id != scope.runtime_authority_id.0
        || row.principal_id != scope.principal_id.as_str()
        || row.workspace_id.as_slice() != scope.workspace_id.as_bytes()
    {
        return Err(PermissionModeStoreError::AuthorityMismatch);
    }
    validate_managed_identity(tx, &row, command_id, scope)?;
    receipt_from_row(row, command_id, scope).map(Some)
}

pub(in crate::store::permission_modes) fn lookup_v2_request(
    tx: &Transaction<'_>,
    request: &NativeModeConfirmationRequestV2,
) -> Result<Option<PermissionModeChangeReceipt>, PermissionModeStoreError> {
    let by_id = receipt::find_by_id(tx, request.command_id)?;
    let by_key=tx.query_row(
        "SELECT command_id,runtime_authority_id,principal_id,workspace_id,project_id,idempotency_key,
           intent_digest,selected_mode,preset_version,authorization_revision,managed_policy_version,
           managed_policy_digest,expires_at_unix_ms,history_projection FROM permission_mode_command_receipts
         WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3 AND idempotency_key=?4",
        params![request.scope.runtime_authority_id.0,request.scope.principal_id.as_str(),
            request.scope.workspace_id.as_bytes(),request.idempotency_key.as_str()],receipt::stored_from_sql,
    ).optional().map_err(|_|PermissionModeStoreError::Unavailable)?;
    if let (Some(left), Some(right)) = (&by_id, &by_key)
        && left.command_id != right.command_id
    {
        return Err(conflict());
    }
    let Some(row) = by_id.or(by_key) else {
        return Ok(None);
    };
    let expected = request
        .expected_authorization_revision
        .checked_add(1)
        .unwrap_or(0);
    if row.command_id.as_slice() != request.command_id.as_bytes()
        || row.runtime_authority_id != request.scope.runtime_authority_id.0
        || row.principal_id != request.scope.principal_id.as_str()
        || row.workspace_id.as_slice() != request.scope.workspace_id.as_bytes()
        || row.idempotency_key != request.idempotency_key.as_str()
        || row.selected_mode != identity::mode_tag(request.requested_mode)
        || row.preset_version != i64::from(request.preset_version.as_u16())
        || row.authorization_revision != i64::try_from(expected).unwrap_or(-1)
        || row.expires_at != request.expires_at_unix_ms
    {
        return Err(conflict());
    }
    validate_managed_identity(tx, &row, request.command_id, &request.scope)?;
    receipt_from_row(row, request.command_id, &request.scope).map(Some)
}

fn validate_managed_identity(
    tx: &Transaction<'_>,
    row: &StoredReceipt,
    command_id: CommandId,
    scope: &PermissionScope,
) -> Result<(), PermissionModeStoreError> {
    let project_id: [u8; 16] = row
        .project_id
        .as_slice()
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let revision = u64::try_from(row.authorization_revision)
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let selection = ModeSelection {
        scope: scope.clone(),
        selected_mode: identity::mode_from_tag(row.selected_mode)?,
        preset_version: identity::preset_version(row.preset_version)?,
        authorization_revision: revision,
        expires_at_unix_ms: row.expires_at,
    };
    let selected_row = super::super::managed_identity::selection::SelectionRow {
        project_id,
        selected_mode: row.selected_mode,
        preset_version: row.preset_version,
        revision: row.authorization_revision,
        managed_version: row.managed_policy_version,
        managed_digest: row.managed_policy_digest.clone(),
        expires_at: row.expires_at,
        last_command_id: Some(command_id.as_bytes().to_vec()),
    };
    super::super::managed_identity::selection::validate_receipt_for_readback(
        tx,
        scope,
        &selection,
        &selected_row,
    )
}

fn receipt_from_row(
    row: StoredReceipt,
    command_id: CommandId,
    scope: &PermissionScope,
) -> Result<PermissionModeChangeReceipt, PermissionModeStoreError> {
    let _: [u8; 16] = row
        .project_id
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let intent_digest = IntegrityDigest::from_bytes(
        row.intent_digest
            .try_into()
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
    );
    let idempotency_key = runne_domain::id::IdempotencyKey::new(row.idempotency_key)
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let projection = receipt_codec::decode_history(&row.history_projection)?;
    let selected_mode = identity::mode_from_tag(row.selected_mode)?;
    let preset_version = identity::preset_version(row.preset_version)?;
    let authorization_revision = u64::try_from(row.authorization_revision)
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let managed_policy_version = u64::try_from(row.managed_policy_version)
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    if projection.selected_mode != selected_mode
        || projection.authorization_revision != authorization_revision
        || projection.preset_version != preset_version
        || projection.managed_policy_version != managed_policy_version
        || projection.expires_at_unix_ms != row.expires_at
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(PermissionModeChangeReceipt {
        command_id,
        idempotency_key,
        intent_digest,
        selection: ModeSelection {
            scope: scope.clone(),
            selected_mode,
            preset_version,
            authorization_revision,
            expires_at_unix_ms: row.expires_at,
        },
        projection,
    })
}

fn conflict() -> PermissionModeStoreError {
    runne_application::permission_modes::PermissionModeError::IdempotencyConflict.into()
}
