use rusqlite::{Transaction, TransactionBehavior, params};

use super::super::{clock, identity, model::*};
use super::{
    issue,
    persistence::{self, CeremonyRow},
};
use crate::store::StoreTransaction;

pub(in crate::store::permission_modes) fn load_status(
    store: &StoreTransaction,
    scope: &runne_application::permission_modes::PermissionScope,
    principal: &runne_api::ApiPrincipalId,
    command_id: runne_domain::id::CommandId,
) -> Result<Option<PermissionModeCeremonyStatusV2>, PermissionModeStoreError> {
    identity::check_scope_authority(store, scope, principal)?;
    let mut writer = store
        .inner
        .writer
        .lock()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let tx = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if let Some(receipt) =
        super::super::command::readback_v2::lookup_by_scope_and_id(&tx, command_id, scope)?
    {
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Ok(Some(PermissionModeCeremonyStatusV2::Committed(receipt)));
    }
    let Some(row) = persistence::find_by_command_id(&tx, command_id)? else {
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Ok(None);
    };
    let status = observe_row(&tx, &row, scope, command_id, clock::unix_ms()?)?;
    tx.commit()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(Some(status))
}

pub(in crate::store::permission_modes) fn cancel(
    store: &StoreTransaction,
    scope: &runne_application::permission_modes::PermissionScope,
    principal: &runne_api::ApiPrincipalId,
    command_id: runne_domain::id::CommandId,
) -> Result<Option<PermissionModeCeremonyStatusV2>, PermissionModeStoreError> {
    identity::check_scope_authority(store, scope, principal)?;
    let mut writer = store
        .inner
        .writer
        .lock()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let tx = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if let Some(receipt) =
        super::super::command::readback_v2::lookup_by_scope_and_id(&tx, command_id, scope)?
    {
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Ok(Some(PermissionModeCeremonyStatusV2::Committed(receipt)));
    }
    let Some(row) = persistence::find_by_command_id(&tx, command_id)? else {
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Ok(None);
    };
    check_scope(&row, scope, command_id)?;
    if row.digest_version != 2 {
        let status = observe_row(&tx, &row, scope, command_id, clock::unix_ms()?)?;
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Ok(Some(status));
    }
    let now = clock::unix_ms()?;
    let status = match (row.state, row.confirmation_phase) {
        (1, 1)
            if row.expires_at <= now || row.mode_expires_at.is_some_and(|expiry| expiry <= now) =>
        {
            issue::expire_pending(&tx, &row)?;
            PermissionModeCeremonyStatusV2::Expired
        }
        (1, 1) => {
            let changed = tx
                .execute(
                    "UPDATE permission_mode_native_challenges SET state=3,confirmation_phase=4
                 WHERE challenge_id=?1 AND state=1 AND confirmation_phase=1",
                    params![row.challenge_id.as_slice()],
                )
                .map_err(|_| PermissionModeStoreError::Unavailable)?;
            if changed != 1 {
                return Err(PermissionModeStoreError::CorruptData);
            }
            PermissionModeCeremonyStatusV2::Cancelled
        }
        _ => observe_row(&tx, &row, scope, command_id, now)?,
    };
    tx.commit()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(Some(status))
}

fn observe_row(
    tx: &Transaction<'_>,
    row: &CeremonyRow,
    scope: &runne_application::permission_modes::PermissionScope,
    command_id: runne_domain::id::CommandId,
    now: i64,
) -> Result<PermissionModeCeremonyStatusV2, PermissionModeStoreError> {
    check_scope(row, scope, command_id)?;
    if row.digest_version != 2 {
        return match (row.state, row.confirmation_phase) {
            (3, 3) => Ok(PermissionModeCeremonyStatusV2::Invalidated),
            (2, 2) => {
                super::super::command::readback_v2::lookup_by_scope_and_id(tx, command_id, scope)?
                    .map(PermissionModeCeremonyStatusV2::Committed)
                    .ok_or(PermissionModeStoreError::CorruptData)
            }
            _ => Err(
                runne_application::permission_modes::PermissionModeError::IdempotencyConflict
                    .into(),
            ),
        };
    }
    match (row.state, row.confirmation_phase) {
        (2, 2) => {
            super::super::command::readback_v2::lookup_by_scope_and_id(tx, command_id, scope)?
                .map(PermissionModeCeremonyStatusV2::Committed)
                .ok_or(PermissionModeStoreError::CorruptData)
        }
        (3, 3) => Ok(PermissionModeCeremonyStatusV2::Invalidated),
        (3, 4) => Ok(PermissionModeCeremonyStatusV2::Cancelled),
        (3, 5) => Ok(PermissionModeCeremonyStatusV2::Expired),
        (1, 1)
            if row.expires_at <= now || row.mode_expires_at.is_some_and(|expiry| expiry <= now) =>
        {
            issue::expire_pending(tx, row)?;
            Ok(PermissionModeCeremonyStatusV2::Expired)
        }
        (1, 1) => {
            let request = request_from_row(row, scope, command_id)?;
            Ok(PermissionModeCeremonyStatusV2::Pending(
                issue::issued_from_row(tx, &request, row)?,
            ))
        }
        _ => Err(PermissionModeStoreError::CorruptData),
    }
}

fn request_from_row(
    row: &CeremonyRow,
    scope: &runne_application::permission_modes::PermissionScope,
    command_id: runne_domain::id::CommandId,
) -> Result<NativeModeConfirmationRequestV2, PermissionModeStoreError> {
    let request = NativeModeConfirmationRequestV2 {
        command_id,
        idempotency_key: runne_domain::id::IdempotencyKey::new(row.idempotency_key.clone())
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
        scope: scope.clone(),
        expected_authorization_revision: u64::try_from(row.expected_revision)
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
        requested_mode: identity::mode_from_tag(row.requested_mode)?,
        preset_version: identity::preset_version(row.preset_version)?,
        expires_at_unix_ms: row.mode_expires_at,
    };
    if !issue::row_matches_request(row, &request) {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(request)
}

fn check_scope(
    row: &CeremonyRow,
    scope: &runne_application::permission_modes::PermissionScope,
    command_id: runne_domain::id::CommandId,
) -> Result<(), PermissionModeStoreError> {
    if row.command_id.as_slice() != command_id.as_bytes()
        || row.authority_id != scope.runtime_authority_id.0
        || row.principal_id != scope.principal_id.as_str()
        || row.workspace_id.as_slice() != scope.workspace_id.as_bytes()
    {
        return Err(PermissionModeStoreError::AuthorityMismatch);
    }
    Ok(())
}

pub(super) fn launch_matches_row(launch: &ProtectedNativeLaunchContext, row: &CeremonyRow) -> bool {
    row.launch_authority_id.as_slice() == launch.launch_authority_id()
        && row.desktop_host_instance_id.as_slice() == launch.desktop_host_instance_id()
        && row.daemon_instance_id.as_slice() == launch.daemon_instance_id()
        && row.launch_generation == i64::try_from(launch.launch_generation()).unwrap_or(-1)
        && row.native_key_epoch == i64::try_from(launch.key_epoch()).unwrap_or(-1)
}
