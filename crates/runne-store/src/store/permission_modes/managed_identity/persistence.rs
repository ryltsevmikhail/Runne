use runne_application::project_trust::{
    ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId,
    ProjectTrustRecord,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{codec, lease, model::ClosedRulesManagedIdentityV2, validation};
use crate::store::permission_modes::model::PermissionModeStoreError;

pub(in crate::store::permission_modes) fn insert_challenge(
    tx: &Transaction<'_>,
    challenge_id: &[u8; 16],
    identity: &ClosedRulesManagedIdentityV2,
) -> Result<(), PermissionModeStoreError> {
    validation::validate(identity)?;
    let binding = identity
        .challenge_binding
        .ok_or(PermissionModeStoreError::CorruptData)?;
    let decisions = identity
        .snapshot
        .policy
        .decisions()
        .map(codec::decision_tag);
    tx.execute(
        "INSERT INTO permission_mode_native_challenge_managed_identity (
           challenge_id,encoding_tag,project_id,project_version,record_instance_epoch,
           record_revision,record_status,record_deny_mask,policy_version,fs_read_decision,
           fs_create_decision,fs_write_decision,fs_delete_decision,process_start_decision,
           network_use_decision,frozen_policy_version,local_command_policy_version,
           legacy_issued_digest,canonical_digest,envelope_digest
         ) VALUES (?1,2,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
        params![
            challenge_id.as_slice(),
            identity.project_id.as_slice(),
            i64::try_from(identity.project_version)
                .map_err(|_| PermissionModeStoreError::ManagedPolicyStale)?,
            i64::try_from(identity.snapshot.record.instance_epoch)
                .map_err(|_| PermissionModeStoreError::ManagedPolicyStale)?,
            i64::try_from(identity.snapshot.record.revision)
                .map_err(|_| PermissionModeStoreError::ManagedPolicyStale)?,
            codec::status_tag(identity.snapshot.record.status),
            i64::from(identity.snapshot.record.managed_deny_mask),
            i64::from(identity.snapshot.policy.version),
            decisions[0],
            decisions[1],
            decisions[2],
            decisions[3],
            decisions[4],
            decisions[5],
            runne_application::project_trust::FROZEN_POLICY_VERSION as i64,
            runne_application::project_trust::LOCAL_COMMAND_POLICY_VERSION as i64,
            binding.legacy_issued_digest.as_bytes().as_slice(),
            identity.canonical_digest.as_bytes().as_slice(),
            binding.envelope_digest.as_bytes().as_slice(),
        ],
    )
    .map_err(|_| PermissionModeStoreError::Unavailable)?;
    Ok(())
}

pub(in crate::store::permission_modes) fn load_challenge(
    connection: &rusqlite::Connection,
    challenge_id: &[u8],
) -> Result<ClosedRulesManagedIdentityV2, PermissionModeStoreError> {
    let raw = connection
        .query_row(
            "SELECT m.encoding_tag,m.project_id,m.project_version,m.record_instance_epoch,
                    m.record_revision,m.record_status,m.record_deny_mask,m.policy_version,
                    m.fs_read_decision,m.fs_create_decision,m.fs_write_decision,m.fs_delete_decision,
                    m.process_start_decision,m.network_use_decision,m.frozen_policy_version,
                    m.local_command_policy_version,m.legacy_issued_digest,m.canonical_digest,
                    m.envelope_digest,c.project_id,c.managed_policy_instance_epoch,
                    c.managed_policy_revision,c.managed_policy_status,c.managed_deny_mask,
                    c.challenge_binding_digest,c.managed_policy_digest
             FROM permission_mode_native_challenge_managed_identity m
             JOIN permission_mode_native_challenges c USING(challenge_id)
             WHERE m.challenge_id=?1",
            [challenge_id],
            raw_identity,
        )
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)?
        .ok_or(PermissionModeStoreError::CorruptData)?;
    decode_challenge(raw)
}

pub(in crate::store::permission_modes) fn challenge_id_for_command(
    tx: &Transaction<'_>,
    command_id: &[u8],
) -> Result<[u8; 16], PermissionModeStoreError> {
    let bytes: Vec<u8> = tx
        .query_row(
            "SELECT challenge_id FROM permission_mode_native_challenges WHERE command_id=?1",
            [command_id],
            |row| row.get(0),
        )
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    bytes
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)
}

#[allow(clippy::too_many_arguments)]
fn raw_identity(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawIdentity> {
    Ok(RawIdentity {
        tag: row.get(0)?,
        project: row.get(1)?,
        project_version: row.get(2)?,
        epoch: row.get(3)?,
        revision: row.get(4)?,
        status: row.get(5)?,
        deny_mask: row.get(6)?,
        policy_version: row.get(7)?,
        decisions: [
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
            row.get(12)?,
            row.get(13)?,
        ],
        frozen_version: row.get(14)?,
        local_version: row.get(15)?,
        legacy_digest: row.get(16)?,
        canonical_digest: row.get(17)?,
        envelope_digest: row.get(18)?,
        parent_project: row.get(19)?,
        parent_epoch: row.get(20)?,
        parent_revision: row.get(21)?,
        parent_status: row.get(22)?,
        parent_deny_mask: row.get(23)?,
        parent_envelope: row.get(24)?,
        parent_record_digest: row.get(25)?,
    })
}

struct RawIdentity {
    tag: i64,
    project: Vec<u8>,
    project_version: i64,
    epoch: i64,
    revision: i64,
    status: i64,
    deny_mask: i64,
    policy_version: i64,
    decisions: [i64; 6],
    frozen_version: i64,
    local_version: i64,
    legacy_digest: Vec<u8>,
    canonical_digest: Vec<u8>,
    envelope_digest: Vec<u8>,
    parent_project: Vec<u8>,
    parent_epoch: i64,
    parent_revision: i64,
    parent_status: i64,
    parent_deny_mask: i64,
    parent_envelope: Vec<u8>,
    parent_record_digest: Vec<u8>,
}

fn decode_challenge(
    raw: RawIdentity,
) -> Result<ClosedRulesManagedIdentityV2, PermissionModeStoreError> {
    use runne_application::project_trust::{FROZEN_POLICY_VERSION, LOCAL_COMMAND_POLICY_VERSION};

    if raw.tag != 2
        || raw.frozen_version != FROZEN_POLICY_VERSION as i64
        || raw.local_version != LOCAL_COMMAND_POLICY_VERSION as i64
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let project: [u8; 16] = raw
        .project
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let record = ProjectTrustRecord {
        status: codec::status_from_tag(raw.status)?,
        instance_epoch: u64::try_from(raw.epoch)
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
        revision: u64::try_from(raw.revision).map_err(|_| PermissionModeStoreError::CorruptData)?,
        managed_deny_mask: u32::try_from(raw.deny_mask)
            .map_err(|_| PermissionModeStoreError::CorruptData)?,
    };
    let decisions: Vec<_> = raw
        .decisions
        .into_iter()
        .map(codec::decision_from_tag)
        .collect::<Result<_, _>>()?;
    let decisions: [runne_application::project_trust::ManagedEffectDecision; 6] = decisions
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let snapshot = ProjectTrustEffectPolicySnapshot {
        record,
        policy: ManagedEffectPolicyV1::new(
            u32::try_from(raw.policy_version).map_err(|_| PermissionModeStoreError::CorruptData)?,
            decisions,
        ),
    };
    let project_version =
        u64::try_from(raw.project_version).map_err(|_| PermissionModeStoreError::CorruptData)?;
    if raw.parent_project.as_slice() != project
        || raw.parent_epoch != raw.epoch
        || raw.parent_revision != raw.revision
        || raw.parent_status != raw.status
        || raw.parent_deny_mask != raw.deny_mask
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let legacy_issued_digest = codec::digest(raw.legacy_digest)?;
    let canonical_digest = codec::digest(raw.canonical_digest)?;
    let envelope_digest = codec::digest(raw.envelope_digest)?;
    if raw.parent_envelope.as_slice() != envelope_digest.as_bytes()
        || runne_application::permission_modes::managed_policy_semantics_digest(
            ProjectTrustProjectId::from_bytes(project),
            record,
        )
        .as_bytes()
        .as_slice()
            != raw.parent_record_digest.as_slice()
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let identity = lease::identity_for_snapshot(
        ProjectTrustProjectId::from_bytes(project),
        project_version,
        snapshot,
    )
    .map_err(|_| PermissionModeStoreError::CorruptData)?;
    if identity.canonical_digest != canonical_digest {
        return Err(PermissionModeStoreError::CorruptData);
    }
    let identity = lease::with_challenge(identity, *legacy_issued_digest.as_bytes());
    validation::validate(&identity)?;
    if identity
        .challenge_binding
        .map(|value| value.envelope_digest)
        != Some(envelope_digest)
    {
        return Err(PermissionModeStoreError::CorruptData);
    }
    Ok(identity)
}
