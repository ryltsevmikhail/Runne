use runne_domain::id::IntegrityDigest;
use rusqlite::{OptionalExtension, Transaction, params};

use super::super::{identity, model::*};
#[derive(Clone)]
pub(in crate::store::permission_modes) struct CeremonyRow {
    pub challenge_id: Vec<u8>,
    pub nonce: Vec<u8>,
    pub challenge_digest: IntegrityDigest,
    pub request_digest: IntegrityDigest,
    pub command_id: Vec<u8>,
    pub authority_id: String,
    pub principal_id: String,
    pub workspace_id: Vec<u8>,
    pub project_id: Vec<u8>,
    pub workspace_version: i64,
    pub idempotency_key: String,
    pub store_authority_id: Vec<u8>,
    pub store_lineage_id: String,
    pub expected_revision: i64,
    pub preset_version: i64,
    pub managed_epoch: i64,
    pub managed_revision: i64,
    pub managed_status: i64,
    pub managed_deny_mask: i64,
    pub managed_digest: Vec<u8>,
    pub mode_expires_at: Option<i64>,
    pub launch_authority_id: Vec<u8>,
    pub desktop_host_instance_id: Vec<u8>,
    pub daemon_instance_id: Vec<u8>,
    pub launch_generation: i64,
    pub native_key_epoch: i64,
    pub protected_session_id: Option<Vec<u8>>,
    pub warning_version: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub state: i64,
    pub proof_identifier: Option<Vec<u8>>,
    pub consumed_at: Option<i64>,
    pub requested_mode: i64,
    pub digest_version: i64,
    pub public_request_digest: Vec<u8>,
    pub confirmation_phase: i64,
}

pub(in crate::store::permission_modes) fn fixed<const N: usize>(
    bytes: &[u8],
) -> Result<[u8; N], PermissionModeStoreError> {
    bytes
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)
}

const ROW_COLUMNS: &str = "challenge_id,nonce,challenge_binding_digest,request_digest,command_id,
 runtime_authority_id,principal_id,workspace_id,project_id,workspace_version,idempotency_key,
 store_authority_id,store_lineage_id,expected_authorization_revision,preset_version,
 managed_policy_instance_epoch,managed_policy_revision,managed_policy_status,managed_deny_mask,
 managed_policy_digest,mode_expires_at_unix_ms,launch_authority_id,desktop_host_instance_id,
 daemon_instance_id,launch_generation,native_key_epoch,protected_session_id,native_warning_version,issued_at_unix_ms,
 expires_at_unix_ms,state,proof_identifier,consumed_at_unix_ms,requested_mode,digest_version,
 public_request_digest,confirmation_phase";

pub(super) fn find_existing(
    tx: &Transaction<'_>,
    request: &NativeModeConfirmationRequestV2,
) -> Result<Option<CeremonyRow>, PermissionModeStoreError> {
    let by_id = find_by_command_id(tx, request.command_id)?;
    let by_key = find_by_key(tx, request)?;
    if let (Some(left), Some(right)) = (&by_id, &by_key)
        && left.challenge_id != right.challenge_id
    {
        return Err(conflict());
    }
    Ok(by_id.or(by_key))
}

pub(super) fn find_by_command_id(
    tx: &Transaction<'_>,
    command_id: runne_domain::id::CommandId,
) -> Result<Option<CeremonyRow>, PermissionModeStoreError> {
    let sql =
        format!("SELECT {ROW_COLUMNS} FROM permission_mode_native_challenges WHERE command_id=?1");
    tx.query_row(&sql, [command_id.as_bytes().as_slice()], row_from_sql)
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)
}

fn find_by_key(
    tx: &Transaction<'_>,
    request: &NativeModeConfirmationRequestV2,
) -> Result<Option<CeremonyRow>, PermissionModeStoreError> {
    let sql = format!(
        "SELECT {ROW_COLUMNS} FROM permission_mode_native_challenges WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3 AND idempotency_key=?4"
    );
    tx.query_row(
        &sql,
        params![
            request.scope.runtime_authority_id.0,
            request.scope.principal_id.as_str(),
            request.scope.workspace_id.as_bytes(),
            request.idempotency_key.as_str(),
        ],
        row_from_sql,
    )
    .optional()
    .map_err(|_| PermissionModeStoreError::Unavailable)
}

pub(super) fn find_by_digest(
    tx: &Transaction<'_>,
    digest: IntegrityDigest,
) -> Result<Option<CeremonyRow>, PermissionModeStoreError> {
    let sql = format!(
        "SELECT {ROW_COLUMNS} FROM permission_mode_native_challenges WHERE challenge_binding_digest=?1"
    );
    tx.query_row(&sql, [digest.as_bytes().as_slice()], row_from_sql)
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn insert(
    tx: &Transaction<'_>,
    request: &NativeModeConfirmationRequestV2,
    workspace: identity::OwnedWorkspace,
    managed: ManagedSnapshot,
    store: identity::StoreIdentity,
    launch: &ProtectedNativeLaunchContext,
    challenge_id: &[u8; 16],
    nonce: &[u8; 32],
    issued_digest: IntegrityDigest,
    issued_at: i64,
    expires_at: i64,
    warning_version: u16,
) -> Result<(), PermissionModeStoreError> {
    tx.execute(
        "INSERT INTO permission_mode_native_challenges (
           challenge_id,nonce,challenge_binding_digest,request_digest,command_id,
           runtime_authority_id,principal_id,workspace_id,project_id,workspace_version,
           idempotency_key,store_authority_id,store_lineage_id,expected_authorization_revision,
           preset_version,managed_policy_instance_epoch,managed_policy_revision,managed_policy_status,
           managed_deny_mask,managed_policy_digest,mode_expires_at_unix_ms,launch_authority_id,
           desktop_host_instance_id,daemon_instance_id,launch_generation,native_key_epoch,
           protected_session_id,native_warning_version,issued_at_unix_ms,expires_at_unix_ms,requested_mode,digest_version,
           public_request_digest,confirmation_phase
         ) VALUES (?1,?2,?3,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,
           ?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,2,?31,1)",
        params![
            challenge_id.as_slice(), nonce.as_slice(), issued_digest.as_bytes().as_slice(),
            request.command_id.as_bytes().as_slice(), request.scope.runtime_authority_id.0,
            request.scope.principal_id.as_str(), request.scope.workspace_id.as_bytes().as_slice(),
            workspace.project_id.as_slice(), i64::try_from(workspace.workspace_version)
                .map_err(|_| PermissionModeStoreError::CorruptData)?,
            request.idempotency_key.as_str(), store.authority_id.as_slice(),
            store.lineage_id.to_string(), i64::try_from(request.expected_authorization_revision)
                .map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?,
            i64::from(request.preset_version.as_u16()),
            i64::try_from(managed.instance_epoch).map_err(|_| PermissionModeStoreError::ManagedPolicyStale)?,
            i64::try_from(managed.revision).map_err(|_| PermissionModeStoreError::ManagedPolicyStale)?,
            identity::trust_status_tag(managed.status), i64::from(managed.deny_mask),
            managed.digest.as_bytes().as_slice(), request.expires_at_unix_ms,
            launch.launch_authority_id().as_slice(), launch.desktop_host_instance_id().as_slice(),
            launch.daemon_instance_id().as_slice(), i64::try_from(launch.launch_generation())
                .map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?,
            i64::try_from(launch.key_epoch()).map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?,
            launch.protected_session_id().map(|id| id.as_slice())
                .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?,
            i64::from(warning_version), issued_at, expires_at,
            identity::mode_tag(request.requested_mode), request.public_request_digest().as_bytes().as_slice(),
        ],
    )
    .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(())
}

fn row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<CeremonyRow> {
    Ok(CeremonyRow {
        challenge_id: row.get(0)?,
        nonce: row.get(1)?,
        challenge_digest: digest(row.get(2)?)?,
        request_digest: digest(row.get(3)?)?,
        command_id: row.get(4)?,
        authority_id: row.get(5)?,
        principal_id: row.get(6)?,
        workspace_id: row.get(7)?,
        project_id: row.get(8)?,
        workspace_version: row.get(9)?,
        idempotency_key: row.get(10)?,
        store_authority_id: row.get(11)?,
        store_lineage_id: row.get(12)?,
        expected_revision: row.get(13)?,
        preset_version: row.get(14)?,
        managed_epoch: row.get(15)?,
        managed_revision: row.get(16)?,
        managed_status: row.get(17)?,
        managed_deny_mask: row.get(18)?,
        managed_digest: row.get(19)?,
        mode_expires_at: row.get(20)?,
        launch_authority_id: row.get(21)?,
        desktop_host_instance_id: row.get(22)?,
        daemon_instance_id: row.get(23)?,
        launch_generation: row.get(24)?,
        native_key_epoch: row.get(25)?,
        protected_session_id: row.get(26)?,
        warning_version: row.get(27)?,
        issued_at: row.get(28)?,
        expires_at: row.get(29)?,
        state: row.get(30)?,
        proof_identifier: row.get(31)?,
        consumed_at: row.get(32)?,
        requested_mode: row.get(33)?,
        digest_version: row.get(34)?,
        public_request_digest: row.get(35)?,
        confirmation_phase: row.get(36)?,
    })
}

fn digest(bytes: Vec<u8>) -> rusqlite::Result<IntegrityDigest> {
    bytes
        .try_into()
        .map(IntegrityDigest::from_bytes)
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn conflict() -> PermissionModeStoreError {
    runne_application::permission_modes::PermissionModeError::IdempotencyConflict.into()
}
