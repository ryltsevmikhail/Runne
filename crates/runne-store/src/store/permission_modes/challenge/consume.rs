use runne_application::permission_modes::{
    PermissionMode, PermissionModeError, SetPermissionModeCommand,
};
use rusqlite::{Transaction, params};

use super::super::identity::{self, OwnedWorkspace, StoreIdentity};
use super::super::model::*;
use super::digest::challenge_request_digest;
use super::persistence::find_issued_by_digest;

pub(super) fn consume(
    tx: &Transaction<'_>,
    command: &SetPermissionModeCommand,
    workspace: OwnedWorkspace,
    managed: ManagedSnapshot,
    store: StoreIdentity,
    launch: &ProtectedNativeLaunchContext,
    now: i64,
) -> Result<(), PermissionModeStoreError> {
    if command.requested_mode != PermissionMode::FullAccess {
        return Ok(());
    }
    let digest = command
        .challenge_binding_digest
        .ok_or(PermissionModeError::ReauthenticationRequired)?;
    let proof = command
        .verified_native_challenge
        .ok_or(PermissionModeError::ReauthenticationRequired)?;
    if proof.proof_identifier() != digest {
        return Err(PermissionModeError::ReauthenticationRequired.into());
    }
    let issued =
        find_issued_by_digest(tx, digest)?.ok_or(PermissionModeError::ReauthenticationRequired)?;
    let request = FullAccessChallengeRequest {
        command_id: command.command_id,
        idempotency_key: command.idempotency_key.clone(),
        scope: command.scope.clone(),
        expected_authorization_revision: command.expected_authorization_revision,
        mode_expires_at_unix_ms: command.expires_at_unix_ms,
    };
    let expected_request = challenge_request_digest(&request, workspace, managed, store, launch);
    let command_bytes = command.command_id.as_bytes();
    let expected_revision = i64::try_from(command.expected_authorization_revision)
        .map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?;
    if issued.state != 1
        || issued.challenge_id == [0; 16]
        || issued.nonce == [0; 32]
        || issued.proof_identifier.is_some()
        || issued.consumed_at.is_some()
        || issued.issued_at <= 0
        || issued.expires_at <= now
        || issued.issued_at > now
        || issued.expires_at.checked_sub(issued.issued_at) != Some(super::CHALLENGE_TTL_MS)
        || command.challenge_expires_at_unix_ms != Some(issued.expires_at)
        || issued.digest != digest
        || issued.request_digest != expected_request
        || issued.command_id.as_slice() != command_bytes
        || issued.runtime_authority_id != command.scope.runtime_authority_id.0
        || issued.principal_id != command.scope.principal_id.as_str()
        || issued.workspace_id.as_slice() != command.scope.workspace_id.as_bytes()
        || issued.project_id.as_slice() != workspace.project_id
        || issued.workspace_version != i64::try_from(workspace.workspace_version).unwrap_or(-1)
        || issued.idempotency_key != command.idempotency_key.as_str()
        || issued.store_authority_id.as_slice() != store.authority_id
        || issued.store_lineage_id != store.lineage_id.to_string()
        || issued.expected_revision != expected_revision
        || issued.preset_version != 1
        || issued.managed_epoch != i64::try_from(managed.instance_epoch).unwrap_or(-1)
        || issued.managed_revision != i64::try_from(managed.revision).unwrap_or(-1)
        || issued.managed_status != identity::trust_status_tag(managed.status)
        || issued.managed_deny_mask != i64::from(managed.deny_mask)
        || issued.managed_digest.as_slice() != managed.digest.as_bytes()
        || issued.mode_expires_at != command.expires_at_unix_ms
        || issued.launch_authority_id.as_slice() != launch.launch_authority_id()
        || issued.desktop_host_instance_id.as_slice() != launch.desktop_host_instance_id()
        || issued.daemon_instance_id.as_slice() != launch.daemon_instance_id()
        || issued.launch_generation != i64::try_from(launch.launch_generation()).unwrap_or(-1)
        || issued.native_key_epoch != i64::try_from(launch.key_epoch()).unwrap_or(-1)
        || issued.warning_version != i64::from(super::NATIVE_WARNING_VERSION)
    {
        return Err(PermissionModeError::ReauthenticationRequired.into());
    }
    let changed = tx
        .execute(
            "UPDATE permission_mode_native_challenges
         SET state=2,proof_identifier=?1,consumed_at_unix_ms=?2
         WHERE challenge_binding_digest=?1 AND state=1 AND expires_at_unix_ms>?2",
            params![digest.as_bytes().as_slice(), now],
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if changed != 1 {
        return Err(PermissionModeError::ReauthenticationRequired.into());
    }
    Ok(())
}
