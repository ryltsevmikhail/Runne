use runne_application::permission_modes::{ModeSelection, PermissionScope};
use runne_domain::id::IntegrityDigest;
use rusqlite::{Connection, OptionalExtension, params};

use super::{
    commit,
    model::{
        ClosedRulesManagedIdentityV2, LegacyRecordIdentityV1, ManagedIdentityMetadata,
        PermissionModeSelectionManagedIdentity,
    },
    persistence, validation,
};
use crate::store::permission_modes::{
    identity,
    model::{PermissionModeAuthorityContext, PermissionModeStoreError},
};

pub(in crate::store::permission_modes) struct SelectionRow {
    pub project_id: [u8; 16],
    pub selected_mode: i64,
    pub preset_version: i64,
    pub revision: i64,
    pub managed_version: i64,
    pub managed_digest: Vec<u8>,
    pub expires_at: Option<i64>,
    pub last_command_id: Option<Vec<u8>>,
}

pub(in crate::store::permission_modes) fn load(
    connection: &Connection,
    scope: &PermissionScope,
    row: Option<SelectionRow>,
    workspace: identity::OwnedWorkspace,
    authority: &PermissionModeAuthorityContext<'_>,
) -> Result<PermissionModeSelectionManagedIdentity, PermissionModeStoreError> {
    let Some(row) = row else {
        let managed = identity::managed_snapshot(authority, workspace.project_id)?;
        let current = super::lease::current(authority, workspace, managed)?;
        return Ok(PermissionModeSelectionManagedIdentity {
            selection: ModeSelection::missing(scope.clone()),
            identity: ManagedIdentityMetadata::ClosedRulesV2(current),
        });
    };
    if row.project_id != workspace.project_id || row.expires_at.is_some_and(|value| value <= 0) {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let selection = ModeSelection {
        scope: scope.clone(),
        selected_mode: identity::mode_from_tag(row.selected_mode)?,
        preset_version: identity::preset_version(row.preset_version)?,
        authorization_revision: u64::try_from(row.revision)
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
        expires_at_unix_ms: row.expires_at,
    };
    let legacy = legacy_identity(&row)?;
    let managed = receipt_identity(connection, scope, &selection, &row)?
        .map(ManagedIdentityMetadata::ClosedRulesV2)
        .unwrap_or(ManagedIdentityMetadata::LegacyRecordV1(legacy));
    Ok(PermissionModeSelectionManagedIdentity {
        selection,
        identity: managed,
    })
}

fn legacy_identity(row: &SelectionRow) -> Result<LegacyRecordIdentityV1, PermissionModeStoreError> {
    Ok(LegacyRecordIdentityV1 {
        project_id: row.project_id,
        managed_policy_version: u64::try_from(row.managed_version)
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
        managed_policy_digest: IntegrityDigest::from_bytes(
            row.managed_digest
                .as_slice()
                .try_into()
                .map_err(|_| PermissionModeStoreError::CorruptData)?,
        ),
    })
}

fn receipt_identity(
    connection: &Connection,
    scope: &PermissionScope,
    selection: &ModeSelection,
    row: &SelectionRow,
) -> Result<Option<ClosedRulesManagedIdentityV2>, PermissionModeStoreError> {
    let Some(command_id) = row.last_command_id.as_deref() else {
        return Ok(None);
    };
    let managed: Option<ReceiptIdentityRow> = connection
        .query_row(
            "SELECT r.runtime_authority_id,r.principal_id,r.workspace_id,r.project_id,
                    r.idempotency_key,r.selected_mode,r.preset_version,r.authorization_revision,
                    r.managed_policy_version,r.managed_policy_digest,
                    x.authorization_revision,x.encoding_tag,x.project_version,
                    x.canonical_digest,x.envelope_digest,x.challenge_id
             FROM permission_mode_command_receipts r
             JOIN permission_mode_command_receipt_managed_identity x USING(command_id)
             WHERE r.command_id=?1",
            [command_id],
            receipt_identity_row,
        )
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let Some(receipt) = managed else {
        let has_challenge_identity: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM permission_mode_native_challenges c
                 JOIN permission_mode_native_challenge_managed_identity m USING(challenge_id)
                 WHERE c.command_id=?1)",
                [command_id],
                |result| result.get(0),
            )
            .map_err(|_| PermissionModeStoreError::Unavailable)?;
        if has_challenge_identity {
            return Err(PermissionModeStoreError::CorruptData);
        }
        return Ok(None);
    };
    if receipt.runtime_authority_id != scope.runtime_authority_id.0
        || receipt.principal_id != scope.principal_id.as_str()
        || receipt.workspace_id.as_slice() != scope.workspace_id.as_bytes()
        || receipt.project_id.as_slice() != row.project_id
        || receipt.selected_mode != identity::mode_tag(selection.selected_mode)
        || receipt.preset_version != i64::from(selection.preset_version.as_u16())
        || receipt.authorization_revision
            != i64::try_from(selection.authorization_revision).unwrap_or(-1)
        || receipt.authorization_revision != receipt.extension_revision
        || receipt.managed_version != row.managed_version
        || receipt.managed_digest.as_slice() != row.managed_digest
        || receipt.encoding_tag != 2
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let challenge_id: [u8; 16] = receipt
        .challenge_id
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let identity = persistence::load_challenge(connection, &challenge_id)?;
    let binding = identity
        .challenge_binding
        .ok_or(PermissionModeStoreError::CorruptData)?;
    if identity.project_version != u64::try_from(receipt.project_version).unwrap_or(0)
        || identity.canonical_digest.as_bytes().as_slice() != receipt.canonical_digest.as_slice()
        || binding.envelope_digest.as_bytes().as_slice() != receipt.envelope_digest.as_slice()
        || identity.project_id.as_slice() != row.project_id
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    commit::validate_challenge_receipt_link(
        connection,
        scope,
        selection,
        row,
        commit::ChallengeReceiptLink {
            command_id,
            challenge_id: &challenge_id,
            receipt_idempotency_key: &receipt.idempotency_key,
            envelope: binding.envelope_digest,
        },
    )?;
    validation::validate(&identity)?;
    Ok(Some(identity))
}

pub(in crate::store::permission_modes) fn validate_receipt_for_readback(
    connection: &Connection,
    scope: &PermissionScope,
    selection: &ModeSelection,
    row: &SelectionRow,
) -> Result<(), PermissionModeStoreError> {
    let _ = receipt_identity(connection, scope, selection, row)?;
    Ok(())
}

struct ReceiptIdentityRow {
    runtime_authority_id: String,
    principal_id: String,
    workspace_id: Vec<u8>,
    project_id: Vec<u8>,
    idempotency_key: String,
    selected_mode: i64,
    preset_version: i64,
    authorization_revision: i64,
    managed_version: i64,
    managed_digest: Vec<u8>,
    extension_revision: i64,
    encoding_tag: i64,
    project_version: i64,
    canonical_digest: Vec<u8>,
    envelope_digest: Vec<u8>,
    challenge_id: Vec<u8>,
}

fn receipt_identity_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReceiptIdentityRow> {
    Ok(ReceiptIdentityRow {
        runtime_authority_id: row.get(0)?,
        principal_id: row.get(1)?,
        workspace_id: row.get(2)?,
        project_id: row.get(3)?,
        idempotency_key: row.get(4)?,
        selected_mode: row.get(5)?,
        preset_version: row.get(6)?,
        authorization_revision: row.get(7)?,
        managed_version: row.get(8)?,
        managed_digest: row.get(9)?,
        extension_revision: row.get(10)?,
        encoding_tag: row.get(11)?,
        project_version: row.get(12)?,
        canonical_digest: row.get(13)?,
        envelope_digest: row.get(14)?,
        challenge_id: row.get(15)?,
    })
}

pub(in crate::store::permission_modes) fn selection_row(
    connection: &Connection,
    scope: &PermissionScope,
) -> Result<Option<SelectionRow>, PermissionModeStoreError> {
    let values = connection
        .query_row(
            "SELECT project_id,selected_mode,preset_version,authorization_revision,
                    managed_policy_version,managed_policy_digest,expires_at_unix_ms,last_command_id
             FROM permission_mode_selections
             WHERE runtime_authority_id=?1 AND principal_id=?2 AND workspace_id=?3",
            params![
                scope.runtime_authority_id.0,
                scope.principal_id.as_str(),
                scope.workspace_id.as_bytes()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    values
        .map(
            |(
                project,
                selected_mode,
                preset_version,
                revision,
                managed_version,
                managed_digest,
                expires_at,
                command,
            )| {
                Ok(SelectionRow {
                    project_id: project
                        .try_into()
                        .map_err(|_| PermissionModeStoreError::CorruptData)?,
                    selected_mode,
                    preset_version,
                    revision,
                    managed_version,
                    managed_digest,
                    expires_at,
                    last_command_id: command,
                })
            },
        )
        .transpose()
}
