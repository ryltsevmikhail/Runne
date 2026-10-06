use runne_application::permission_modes::PermissionScope;
use rusqlite::{OptionalExtension, Transaction, params};

use super::super::{identity, model::*};
use crate::store::permission_modes::challenge::NATIVE_WARNING_VERSION;

mod row;
use row::issued_row_from_sql;

pub(in crate::store::permission_modes) fn current_revision(
    tx: &Transaction<'_>,
    scope: &PermissionScope,
) -> Result<u64, PermissionModeStoreError> {
    let stored: Option<i64> = tx
        .query_row(
            "SELECT authorization_revision FROM permission_mode_selections
             WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3",
            params![
                scope.runtime_authority_id.0,
                scope.principal_id.as_str(),
                scope.workspace_id.as_bytes(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    stored.map_or(Ok(0), |value| {
        u64::try_from(value).map_err(|_| PermissionModeStoreError::CorruptData)
    })
}

pub(super) fn sql_integer(value: u64) -> Result<i64, PermissionModeStoreError> {
    i64::try_from(value).map_err(|_| {
        PermissionModeStoreError::Command(
            runne_application::permission_modes::PermissionModeError::StaleRevision,
        )
    })
}

pub(super) fn find_existing(
    tx: &Transaction<'_>,
    request: &FullAccessChallengeRequest,
) -> Result<Option<super::super::challenge::IssuedRow>, PermissionModeStoreError> {
    let by_command = tx
        .query_row(
            "SELECT request_digest,state,expires_at_unix_ms,challenge_id,nonce,challenge_binding_digest
             FROM permission_mode_native_challenges WHERE command_id=?1",
            [request.command_id.as_bytes().as_slice()],
            issued_row_from_sql,
        )
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let by_key = tx
        .query_row(
            "SELECT request_digest,state,expires_at_unix_ms,challenge_id,nonce,challenge_binding_digest
             FROM permission_mode_native_challenges
             WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3 AND idempotency_key=?4",
            params![request.scope.runtime_authority_id.0, request.scope.principal_id.as_str(),
                request.scope.workspace_id.as_bytes(), request.idempotency_key.as_str()],
            issued_row_from_sql,
        )
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if let (Some(left), Some(right)) = (&by_command, &by_key)
        && left.challenge_id != right.challenge_id
    {
        return Err(PermissionModeStoreError::Command(
            runne_application::permission_modes::PermissionModeError::IdempotencyConflict,
        ));
    }
    Ok(by_command.or(by_key))
}

pub(in crate::store::permission_modes) fn find_issued_by_digest(
    tx: &Transaction<'_>,
    digest: runne_domain::id::IntegrityDigest,
) -> Result<Option<super::IssuedChallengeRow>, PermissionModeStoreError> {
    tx.query_row(
        "SELECT challenge_id,nonce,challenge_binding_digest,request_digest,command_id,
                runtime_authority_id,principal_id,workspace_id,project_id,workspace_version,
                idempotency_key,store_authority_id,store_lineage_id,expected_authorization_revision,
                preset_version,managed_policy_instance_epoch,managed_policy_revision,
                managed_policy_status,managed_deny_mask,managed_policy_digest,mode_expires_at_unix_ms,
                launch_authority_id,desktop_host_instance_id,daemon_instance_id,launch_generation,
                native_key_epoch,native_warning_version,issued_at_unix_ms,expires_at_unix_ms,
                state,proof_identifier,consumed_at_unix_ms
         FROM permission_mode_native_challenges WHERE challenge_binding_digest=?1",
        [digest.as_bytes().as_slice()],
        row::issued_full_row_from_sql,
    )
    .optional()
    .map_err(|_| PermissionModeStoreError::Unavailable)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn insert_challenge(
    tx: &Transaction<'_>,
    request: &FullAccessChallengeRequest,
    workspace: identity::OwnedWorkspace,
    managed: ManagedSnapshot,
    store: identity::StoreIdentity,
    launch: &ProtectedNativeLaunchContext,
    challenge_id: [u8; 16],
    nonce: [u8; 32],
    request_digest: runne_domain::id::IntegrityDigest,
    challenge_digest: runne_domain::id::IntegrityDigest,
    issued_at: i64,
    expires_at: i64,
) -> Result<(), PermissionModeStoreError> {
    tx.execute(
        "INSERT INTO permission_mode_native_challenges (
           challenge_id,nonce,challenge_binding_digest,request_digest,command_id,
           runtime_authority_id,principal_id,workspace_id,project_id,workspace_version,
           idempotency_key,store_authority_id,store_lineage_id,expected_authorization_revision,
           preset_version,managed_policy_instance_epoch,managed_policy_revision,managed_policy_status,
           managed_deny_mask,managed_policy_digest,mode_expires_at_unix_ms,
           launch_authority_id,desktop_host_instance_id,daemon_instance_id,launch_generation,
           native_key_epoch,native_warning_version,issued_at_unix_ms,expires_at_unix_ms
         ) VALUES (
           ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,1,?15,?16,?17,?18,?19,?20,
           ?21,?22,?23,?24,?25,?26,?27,?28
         )",
        params![
            challenge_id.as_slice(), nonce.as_slice(), challenge_digest.as_bytes().as_slice(),
            request_digest.as_bytes().as_slice(), request.command_id.as_bytes().as_slice(),
            request.scope.runtime_authority_id.0, request.scope.principal_id.as_str(),
            request.scope.workspace_id.as_bytes().as_slice(), workspace.project_id.as_slice(),
            i64::try_from(workspace.workspace_version).map_err(|_| PermissionModeStoreError::CorruptData)?,
            request.idempotency_key.as_str(), store.authority_id.as_slice(), store.lineage_id.to_string(),
            i64::try_from(request.expected_authorization_revision).map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?,
            i64::try_from(managed.instance_epoch).map_err(|_| PermissionModeStoreError::ManagedPolicyStale)?,
            i64::try_from(managed.revision).map_err(|_| PermissionModeStoreError::ManagedPolicyStale)?,
            identity::trust_status_tag(managed.status), i64::from(managed.deny_mask), managed.digest.as_bytes().as_slice(),
            request.mode_expires_at_unix_ms, launch.launch_authority_id().as_slice(),
            launch.desktop_host_instance_id().as_slice(), launch.daemon_instance_id().as_slice(),
            i64::try_from(launch.launch_generation()).map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?,
            i64::try_from(launch.key_epoch()).map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?,
            i64::from(NATIVE_WARNING_VERSION), issued_at, expires_at,
        ],
    )
    .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(())
}
