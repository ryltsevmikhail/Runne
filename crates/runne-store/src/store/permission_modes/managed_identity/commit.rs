use runne_application::permission_modes::{ModeSelection, PermissionScope};
use rusqlite::{Connection, Transaction, params};

use super::{persistence, selection::SelectionRow};
use crate::store::permission_modes::{identity, model::PermissionModeStoreError};

struct ChallengeReceiptLinkRow {
    command_id: Vec<u8>,
    state: i64,
    confirmation_phase: i64,
    digest_version: i64,
    expected_authorization_revision: i64,
    managed_policy_revision: i64,
    managed_policy_digest: Vec<u8>,
    challenge_binding_digest: Vec<u8>,
    runtime_authority_id: String,
    principal_id: String,
    workspace_id: Vec<u8>,
    project_id: Vec<u8>,
    idempotency_key: String,
    requested_mode: i64,
    preset_version: i64,
}

pub(super) struct ChallengeReceiptLink<'a> {
    pub(super) command_id: &'a [u8],
    pub(super) challenge_id: &'a [u8; 16],
    pub(super) receipt_idempotency_key: &'a str,
    pub(super) envelope: runne_domain::id::IntegrityDigest,
}

pub(super) fn validate_challenge_receipt_link(
    connection: &Connection,
    scope: &PermissionScope,
    selection: &ModeSelection,
    row: &SelectionRow,
    link: ChallengeReceiptLink<'_>,
) -> Result<(), PermissionModeStoreError> {
    let parent: ChallengeReceiptLinkRow = connection
        .query_row(
            "SELECT command_id,state,confirmation_phase,digest_version,
                    expected_authorization_revision,managed_policy_revision,managed_policy_digest,
                    challenge_binding_digest,runtime_authority_id,principal_id,workspace_id,
                    project_id,idempotency_key,requested_mode,preset_version
             FROM permission_mode_native_challenges WHERE challenge_id=?1",
            [link.challenge_id.as_slice()],
            |value| {
                Ok(ChallengeReceiptLinkRow {
                    command_id: value.get(0)?,
                    state: value.get(1)?,
                    confirmation_phase: value.get(2)?,
                    digest_version: value.get(3)?,
                    expected_authorization_revision: value.get(4)?,
                    managed_policy_revision: value.get(5)?,
                    managed_policy_digest: value.get(6)?,
                    challenge_binding_digest: value.get(7)?,
                    runtime_authority_id: value.get(8)?,
                    principal_id: value.get(9)?,
                    workspace_id: value.get(10)?,
                    project_id: value.get(11)?,
                    idempotency_key: value.get(12)?,
                    requested_mode: value.get(13)?,
                    preset_version: value.get(14)?,
                })
            },
        )
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    if parent.command_id.as_slice() != link.command_id
        || parent.state != 2
        || parent.confirmation_phase != 2
        || parent.digest_version != 2
        || parent.expected_authorization_revision.checked_add(1) != Some(row.revision)
        || parent.managed_policy_revision != row.managed_version
        || parent.managed_policy_digest.as_slice() != row.managed_digest
        || parent.challenge_binding_digest.as_slice() != link.envelope.as_bytes()
        || parent.runtime_authority_id != scope.runtime_authority_id.0
        || parent.principal_id != scope.principal_id.as_str()
        || parent.workspace_id.as_slice() != scope.workspace_id.as_bytes()
        || parent.project_id.as_slice() != row.project_id
        || parent.idempotency_key != link.receipt_idempotency_key
        || parent.requested_mode != identity::mode_tag(selection.selected_mode)
        || parent.preset_version != i64::from(selection.preset_version.as_u16())
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(())
}

pub(in crate::store::permission_modes) fn insert_receipt_identity(
    tx: &Transaction<'_>,
    command_id: &[u8; 16],
    authorization_revision: i64,
) -> Result<(), PermissionModeStoreError> {
    let challenge_id = persistence::challenge_id_for_command(tx, command_id)?;
    let identity = persistence::load_challenge(tx, &challenge_id)?;
    let binding = identity
        .challenge_binding
        .ok_or(PermissionModeStoreError::CorruptData)?;
    tx.execute(
        "INSERT INTO permission_mode_command_receipt_managed_identity (
           command_id,challenge_id,authorization_revision,encoding_tag,project_version,
           canonical_digest,envelope_digest
         ) VALUES (?1,?2,?3,2,?4,?5,?6)",
        params![
            command_id.as_slice(),
            challenge_id.as_slice(),
            authorization_revision,
            i64::try_from(identity.project_version)
                .map_err(|_| PermissionModeStoreError::CorruptData)?,
            identity.canonical_digest.as_bytes().as_slice(),
            binding.envelope_digest.as_bytes().as_slice(),
        ],
    )
    .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(())
}
