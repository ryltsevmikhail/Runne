use runne_application::permission_modes::{
    EffectiveModeHistoryState, PermissionModeChangeReceipt, PermissionModeError,
    PermissionModeHistoryProjection, SetPermissionModeCommand, VerifiedNativeModeConfirmationV2,
    validate_mode_change_command,
};
use rusqlite::{TransactionBehavior, params};

use super::super::{
    ceremony_v2, challenge, clock, identity, managed_identity, model::*, receipt_codec,
};
use super::receipt;
use crate::store::StoreTransaction;

pub(super) fn commit(
    store: &StoreTransaction,
    command: SetPermissionModeCommand,
    confirmation: VerifiedNativeModeConfirmationV2,
    authority: &PermissionModeAuthorityContext<'_>,
    history: PermissionModeHistoryProjection,
) -> Result<PermissionModeChangeReceipt, PermissionModeStoreError> {
    validate_mode_change_command(&command)?;
    identity::check_scope_authority(store, &command.scope, authority.authenticated_principal)?;
    let request = NativeModeConfirmationRequestV2 {
        command_id: command.command_id,
        idempotency_key: command.idempotency_key.clone(),
        scope: command.scope.clone(),
        expected_authorization_revision: command.expected_authorization_revision,
        requested_mode: command.requested_mode,
        preset_version: command.preset_version,
        expires_at_unix_ms: command.expires_at_unix_ms,
    };
    let mut writer = store
        .inner
        .writer
        .lock()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let tx = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let now = clock::unix_ms()?;
    if let Some(previous) = super::readback_v2::lookup_v2_request(&tx, &request)? {
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Ok(previous);
    }
    receipt::check_command_id_available(&tx, &command)?;
    if challenge::persistence::current_revision(&tx, &command.scope)?
        != command.expected_authorization_revision
    {
        return Err(PermissionModeError::StaleRevision.into());
    }
    let next = command
        .expected_authorization_revision
        .checked_add(1)
        .ok_or(PermissionModeError::StaleRevision)?;
    let revision = i64::try_from(next).map_err(|_| PermissionModeError::StaleRevision)?;
    if command
        .expires_at_unix_ms
        .is_some_and(|expiry| expiry <= now)
    {
        return Err(PermissionModeError::Expired.into());
    }
    let workspace = identity::owned_open_workspace(&tx, &command.scope)?;
    let managed = identity::managed_snapshot(authority, workspace.project_id)?;
    let closed_rules = managed_identity::lease::current(authority, workspace, managed)?;
    if managed.revision != command.managed_policy_version
        || closed_rules.canonical_digest != command.managed_policy_digest
    {
        return Err(PermissionModeStoreError::ManagedPolicyStale);
    }
    let store_identity = identity::store_identity(&tx, &command.scope)?;
    let launch = identity::native_launch_fields(authority)?;
    validate_history(&history, &command, next)?;
    let consumed = ceremony_v2::consume::consume_v2(
        &tx,
        &command,
        confirmation,
        workspace,
        managed,
        &closed_rules,
        store_identity,
        &launch,
        now,
    )?;
    if !consumed {
        tx.commit()
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        return Err(PermissionModeStoreError::ReauthenticationUnavailable);
    }
    write_selection(&tx, &command, workspace, managed, revision, now)?;
    tx.execute(
        "UPDATE permission_mode_native_challenges SET state=3,confirmation_phase=3
         WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3 AND state=1",
        params![
            command.scope.runtime_authority_id.0,
            command.scope.principal_id.as_str(),
            command.scope.workspace_id.as_bytes()
        ],
    )
    .map_err(|_| PermissionModeStoreError::Unavailable)?;
    receipt::insert_v2(
        &tx,
        &command,
        workspace.project_id,
        revision,
        now,
        &history,
        managed.digest,
    )?;
    managed_identity::commit::insert_receipt_identity(
        &tx,
        command.command_id.as_bytes(),
        revision,
    )?;
    super::commit::stop_changed_mode_scope(
        &tx,
        &command.scope.runtime_authority_id.0,
        command.scope.principal_id.as_str(),
        command.scope.workspace_id.as_bytes(),
        now,
    )
    .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let result = PermissionModeChangeReceipt {
        command_id: command.command_id,
        idempotency_key: command.idempotency_key.clone(),
        intent_digest: command.intent_digest,
        selection: runne_application::permission_modes::ModeSelection {
            scope: command.scope.clone(),
            selected_mode: command.requested_mode,
            preset_version: command.preset_version,
            authorization_revision: next,
            expires_at_unix_ms: command.expires_at_unix_ms,
        },
        projection: receipt_codec::decode_history(&receipt_codec::encode_history(&history)?)?,
    };
    tx.commit()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(result)
}

fn write_selection(
    tx: &rusqlite::Transaction<'_>,
    command: &SetPermissionModeCommand,
    workspace: identity::OwnedWorkspace,
    managed: ManagedSnapshot,
    revision: i64,
    now: i64,
) -> Result<(), PermissionModeStoreError> {
    if command.expected_authorization_revision == 0 {
        tx.execute(
            "INSERT INTO permission_mode_selections (
               runtime_authority_id,principal_id,workspace_id,project_id,selected_mode,preset_version,
               authorization_revision,managed_policy_version,managed_policy_digest,expires_at_unix_ms,
               last_command_id,intent_digest,updated_at_unix_ms
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![command.scope.runtime_authority_id.0,command.scope.principal_id.as_str(),
                command.scope.workspace_id.as_bytes().as_slice(),workspace.project_id.as_slice(),
                identity::mode_tag(command.requested_mode),i64::from(command.preset_version.as_u16()),revision,
                i64::try_from(managed.revision).map_err(|_|PermissionModeStoreError::ManagedPolicyStale)?,
                managed.digest.as_bytes().as_slice(),command.expires_at_unix_ms,command.command_id.as_bytes().as_slice(),
                command.intent_digest.as_bytes().as_slice(),now],
        ).map_err(|_|PermissionModeStoreError::Unavailable)?;
    } else {
        let changed=tx.execute(
            "UPDATE permission_mode_selections SET project_id=?1,selected_mode=?2,preset_version=?3,
               authorization_revision=?4,managed_policy_version=?5,managed_policy_digest=?6,
               expires_at_unix_ms=?7,last_command_id=?8,intent_digest=?9,updated_at_unix_ms=?10
             WHERE runtime_authority_id=?11 AND principal_id=?12 AND workspace_id=?13 AND authorization_revision=?14",
            params![workspace.project_id.as_slice(),identity::mode_tag(command.requested_mode),
                i64::from(command.preset_version.as_u16()),revision,
                i64::try_from(managed.revision).map_err(|_|PermissionModeStoreError::ManagedPolicyStale)?,
                managed.digest.as_bytes().as_slice(),command.expires_at_unix_ms,command.command_id.as_bytes().as_slice(),
                command.intent_digest.as_bytes().as_slice(),now,command.scope.runtime_authority_id.0,
                command.scope.principal_id.as_str(),command.scope.workspace_id.as_bytes(),
                i64::try_from(command.expected_authorization_revision).map_err(|_|PermissionModeStoreError::CorruptData)?],
        ).map_err(|_|PermissionModeStoreError::Unavailable)?;
        if changed != 1 {
            return Err(PermissionModeError::StaleRevision.into());
        }
    }
    Ok(())
}

fn validate_history(
    history: &PermissionModeHistoryProjection,
    command: &SetPermissionModeCommand,
    revision: u64,
) -> Result<(), PermissionModeStoreError> {
    if history.selected_mode != command.requested_mode
        || history.authorization_revision != revision
        || history.preset_version != command.preset_version
        || history.managed_policy_version != command.managed_policy_version
        || history.expires_at_unix_ms != command.expires_at_unix_ms
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    if let EffectiveModeHistoryState::Ready {
        mode,
        preset_version,
        containment,
        ..
    } = &history.effective
        && (*mode != command.requested_mode
            || *preset_version != command.preset_version
            || history.containment != Some(*containment))
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(())
}
