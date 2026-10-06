use runne_application::permission_modes::{ModeSelection, PermissionScope};
use runne_domain::id::IntegrityDigest;
use rusqlite::{OptionalExtension, params};

use super::super::{identity, model::*};
use crate::store::StoreTransaction;

pub(super) fn load(
    store: &StoreTransaction,
    scope: &PermissionScope,
    authenticated_principal: &runne_api::ApiPrincipalId,
) -> Result<ModeSelection, PermissionModeStoreError> {
    identity::check_scope_authority(store, scope, authenticated_principal)?;
    let reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let owned = identity::owned_open_workspace(&reader, scope)?;
    let row: Option<(Vec<u8>, i64, i64, i64)> = reader
        .query_row(
            "SELECT project_id,selected_mode,preset_version,authorization_revision
             FROM permission_mode_selections
             WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3",
            params![
                scope.runtime_authority_id.0,
                scope.principal_id.as_str(),
                scope.workspace_id.as_bytes()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let Some((project, selected_mode, preset_version, revision)) = row else {
        return Ok(ModeSelection::missing(scope.clone()));
    };
    if project.as_slice() != owned.project_id {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let selected_mode = identity::mode_from_tag(selected_mode)?;
    let preset_version = identity::preset_version(preset_version)?;
    let authorization_revision =
        u64::try_from(revision).map_err(|_| PermissionModeStoreError::CorruptData)?;
    let expires_at_unix_ms: Option<i64> = reader
        .query_row(
            "SELECT expires_at_unix_ms FROM permission_mode_selections
             WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3",
            params![
                scope.runtime_authority_id.0,
                scope.principal_id.as_str(),
                scope.workspace_id.as_bytes()
            ],
            |row| row.get(0),
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if expires_at_unix_ms.is_some_and(|expiry| expiry <= 0) {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(ModeSelection {
        scope: scope.clone(),
        selected_mode,
        preset_version,
        authorization_revision,
        expires_at_unix_ms,
    })
}

pub(super) fn load_snapshot(
    store: &StoreTransaction,
    scope: &PermissionScope,
    authenticated_principal: &runne_api::ApiPrincipalId,
) -> Result<PermissionModeSelectionSnapshot, PermissionModeStoreError> {
    identity::check_scope_authority(store, scope, authenticated_principal)?;
    let reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let owned = identity::owned_open_workspace(&reader, scope)?;
    #[allow(clippy::type_complexity)]
    let row: Option<(Vec<u8>, i64, i64, i64, i64, Vec<u8>, Option<i64>)> = reader
        .query_row(
            "SELECT project_id,selected_mode,preset_version,authorization_revision,
                    managed_policy_version,managed_policy_digest,expires_at_unix_ms
             FROM permission_mode_selections
             WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3",
            params![
                scope.runtime_authority_id.0,
                scope.principal_id.as_str(),
                scope.workspace_id.as_bytes()
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let Some((
        project,
        selected_mode,
        preset_version,
        revision,
        managed_version,
        managed_digest,
        expires_at,
    )) = row
    else {
        return Ok(PermissionModeSelectionSnapshot {
            selection: ModeSelection::missing(scope.clone()),
            managed_policy_version: 0,
            managed_policy_digest: IntegrityDigest::from_bytes(
                crate::store::taskrun_tool_invocation::MISSING_PERMISSION_MODE_MANAGED_DIGEST,
            ),
        });
    };
    if project.as_slice() != owned.project_id {
        return Err(PermissionModeStoreError::CorruptData);
    }
    if expires_at.is_some_and(|expiry| expiry <= 0) {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(PermissionModeSelectionSnapshot {
        selection: ModeSelection {
            scope: scope.clone(),
            selected_mode: identity::mode_from_tag(selected_mode)?,
            preset_version: identity::preset_version(preset_version)?,
            authorization_revision: u64::try_from(revision)
                .map_err(|_| PermissionModeStoreError::CorruptData)?,
            expires_at_unix_ms: expires_at,
        },
        managed_policy_version: u64::try_from(managed_version)
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
        managed_policy_digest: IntegrityDigest::from_bytes(
            managed_digest
                .try_into()
                .map_err(|_| PermissionModeStoreError::CorruptData)?,
        ),
    })
}
