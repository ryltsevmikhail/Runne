use runne_api::{
    ApiPrincipalId, PermissionModeNativePendingContextV2, PermissionModeNativePendingPageV2,
    PermissionModeNativePendingV2, permission_control_stable_subject_digest_v1,
};
use runne_application::permission_modes::PermissionScope;
use runne_domain::id::{CommandId, IdempotencyKey, WorkspaceId, validate_uuid_v7_bytes};
use rusqlite::params;

use super::super::{clock, identity, model::*};
use crate::store::StoreTransaction;

const QUERY_LIMIT: usize = runne_api::MAX_NATIVE_PENDING_PAGE_SIZE_V2 + 1;

struct PendingRow {
    command_id: Vec<u8>,
    workspace_id: Vec<u8>,
    idempotency_key: String,
    expected_revision: i64,
    requested_mode: i64,
    preset_version: i64,
    mode_expires_at: Option<i64>,
    issued_at: i64,
    expires_at: i64,
    public_request_digest: Vec<u8>,
}

pub(in crate::store::permission_modes) fn native_pending(
    store: &StoreTransaction,
    principal: &ApiPrincipalId,
    launch: &ProtectedNativeLaunchContext,
    after: Option<CommandId>,
) -> Result<PermissionModeNativePendingPageV2, PermissionModeStoreError> {
    native_pending_filtered(store, principal, launch, after, None)
}

pub(in crate::store::permission_modes) fn native_pending_command(
    store: &StoreTransaction,
    principal: &ApiPrincipalId,
    launch: &ProtectedNativeLaunchContext,
    command_id: CommandId,
) -> Result<Option<PermissionModeNativePendingV2>, PermissionModeStoreError> {
    Ok(
        native_pending_filtered(store, principal, launch, None, Some(command_id))?
            .pending
            .into_iter()
            .next(),
    )
}

fn native_pending_filtered(
    store: &StoreTransaction,
    principal: &ApiPrincipalId,
    launch: &ProtectedNativeLaunchContext,
    after: Option<CommandId>,
    command_filter: Option<CommandId>,
) -> Result<PermissionModeNativePendingPageV2, PermissionModeStoreError> {
    let now = clock::unix_ms()?;
    let reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let authority_id = crate::schema::read_authority_id(&reader)
        .map_err(|_| PermissionModeStoreError::Unavailable)?
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
    let lineage = crate::schema::read_event_log_lineage_id(&reader)
        .map_err(|_| PermissionModeStoreError::Unavailable)?
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
    let authority_id_hex = authority_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if authority_id_hex != store.runtime_authority_id.0 {
        return Err(PermissionModeStoreError::AuthorityMismatch);
    }
    let session = launch
        .protected_session_id()
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
    let cursor = after.map_or([0; 16], |value| value.into_bytes());
    let limit = i64::try_from(QUERY_LIMIT).map_err(|_| PermissionModeStoreError::CorruptData)?;
    let mut statement = reader
        .prepare(
            "SELECT c.command_id,c.workspace_id,c.idempotency_key,
                    c.expected_authorization_revision,c.requested_mode,c.preset_version,
                    c.mode_expires_at_unix_ms,c.issued_at_unix_ms,c.expires_at_unix_ms,
                    c.public_request_digest
             FROM permission_mode_native_challenges c
             JOIN workspaces w ON w.workspace_id=c.workspace_id
             JOIN projects p ON p.project_id=w.project_id
             JOIN workspace_identity_history h ON h.workspace_id=w.workspace_id
             WHERE c.runtime_authority_id=?1 AND c.principal_id=?2
               AND c.store_authority_id=?3 AND c.store_lineage_id=?4
               AND c.launch_authority_id=?5 AND c.desktop_host_instance_id=?6
               AND c.daemon_instance_id=?7 AND c.launch_generation=?8
               AND c.native_key_epoch=?9 AND c.protected_session_id=?10
               AND c.state=1 AND c.confirmation_phase=1 AND c.digest_version=2
               AND c.expires_at_unix_ms>?11
               AND (c.mode_expires_at_unix_ms IS NULL OR c.mode_expires_at_unix_ms>?11)
               AND c.command_id>?12
               AND (?14 IS NULL OR c.command_id=?14)
               AND w.principal_id=?2 AND p.principal_id=?2 AND w.project_id=h.project_id
               AND w.principal_id=h.principal_id AND h.classification='canonical'
               AND w.open=1 AND w.live=1 AND p.archived=0
             ORDER BY c.command_id LIMIT ?13",
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let command_filter_bytes = command_filter.map(CommandId::into_bytes);
    let rows = statement
        .query_map(
            params![
                store.runtime_authority_id.0,
                principal.as_str(),
                authority_id.as_slice(),
                lineage.to_string(),
                launch.launch_authority_id().as_slice(),
                launch.desktop_host_instance_id().as_slice(),
                launch.daemon_instance_id().as_slice(),
                i64::try_from(launch.launch_generation())
                    .map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?,
                i64::try_from(launch.key_epoch())
                    .map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?,
                session.as_slice(),
                now,
                cursor.as_slice(),
                limit,
                command_filter_bytes.as_ref().map(|id| id.as_slice()),
            ],
            |row| {
                Ok(PendingRow {
                    command_id: row.get(0)?,
                    workspace_id: row.get(1)?,
                    idempotency_key: row.get(2)?,
                    expected_revision: row.get(3)?,
                    requested_mode: row.get(4)?,
                    preset_version: row.get(5)?,
                    mode_expires_at: row.get(6)?,
                    issued_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    public_request_digest: row.get(9)?,
                })
            },
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    drop(statement);
    drop(reader);

    let has_more = rows.len() > runne_api::MAX_NATIVE_PENDING_PAGE_SIZE_V2;
    let pending = rows
        .into_iter()
        .take(runne_api::MAX_NATIVE_PENDING_PAGE_SIZE_V2)
        .map(|row| project_row(store, principal, launch, lineage, now, row))
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = has_more
        .then(|| pending.last().map(|item| item.context.command_id.clone()))
        .flatten();
    Ok(PermissionModeNativePendingPageV2 {
        pending,
        next_cursor,
    })
}

fn project_row(
    store: &StoreTransaction,
    principal: &ApiPrincipalId,
    launch: &ProtectedNativeLaunchContext,
    lineage: runne_domain::id::EventLogLineageId,
    now: i64,
    row: PendingRow,
) -> Result<PermissionModeNativePendingV2, PermissionModeStoreError> {
    let command_bytes = fixed::<16>(&row.command_id)?;
    let workspace_bytes = fixed::<16>(&row.workspace_id)?;
    validate_uuid_v7_bytes(&command_bytes).map_err(|_| PermissionModeStoreError::CorruptData)?;
    validate_uuid_v7_bytes(&workspace_bytes).map_err(|_| PermissionModeStoreError::CorruptData)?;
    let command_id = CommandId::from_bytes(command_bytes);
    let workspace_id = WorkspaceId::from_bytes(workspace_bytes);
    let idempotency_key = IdempotencyKey::new(row.idempotency_key)
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let expected_revision =
        u64::try_from(row.expected_revision).map_err(|_| PermissionModeStoreError::CorruptData)?;
    let requested_mode = identity::mode_from_tag(row.requested_mode)?;
    let preset_version = identity::preset_version(row.preset_version)?;
    let issued_at = u64::try_from(row.issued_at)
        .ok()
        .filter(|value| *value > 0 && *value <= u64::try_from(now).unwrap_or(0))
        .ok_or(PermissionModeStoreError::CorruptData)?;
    let expires_at = u64::try_from(row.expires_at)
        .ok()
        .filter(|value| *value > issued_at && *value > u64::try_from(now).unwrap_or(u64::MAX))
        .ok_or(PermissionModeStoreError::CorruptData)?;
    let clipped_expiry = row
        .mode_expires_at
        .map(|value| u64::try_from(value).map_err(|_| PermissionModeStoreError::CorruptData))
        .transpose()?
        .map_or(expires_at, |mode_expiry| expires_at.min(mode_expiry));
    if clipped_expiry <= issued_at || clipped_expiry - issued_at > 120_000 {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let scope = PermissionScope {
        runtime_authority_id: store.runtime_authority_id.clone(),
        principal_id: principal.clone(),
        workspace_id,
    };
    let request = NativeModeConfirmationRequestV2 {
        command_id,
        idempotency_key: idempotency_key.clone(),
        scope,
        expected_authorization_revision: expected_revision,
        requested_mode,
        preset_version,
        expires_at_unix_ms: row.mode_expires_at,
    };
    let public_digest = fixed::<32>(&row.public_request_digest)?;
    if request.public_request_digest().as_bytes() != &public_digest {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let stable_subject_digest = permission_control_stable_subject_digest_v1(principal)
        .map_err(|_| PermissionModeStoreError::AuthorityMismatch)?;
    Ok(PermissionModeNativePendingV2 {
        workspace_id: workspace_id.to_string(),
        principal_id: principal.as_str().to_owned(),
        context: PermissionModeNativePendingContextV2 {
            runtime_authority: store.runtime_authority_id.0.clone(),
            store_lineage_id: *lineage.as_bytes(),
            stable_subject_digest,
            protected_launch_authority_id: *launch.launch_authority_id(),
            desktop_authority_id: *launch.desktop_host_instance_id(),
            daemon_instance_id: *launch.daemon_instance_id(),
            protected_session_id: *launch
                .protected_session_id()
                .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?,
            launch_generation: launch.launch_generation(),
            native_key_epoch: launch.key_epoch(),
            command_id: command_id.to_string(),
            idempotency_key: idempotency_key.as_str().to_owned(),
            public_request_digest: public_digest,
            predecessor_transcript_digest: [0; 32],
            issued_at_unix_ms: issued_at,
            expires_at_unix_ms: clipped_expiry,
        },
    })
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], PermissionModeStoreError> {
    bytes
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)
}
