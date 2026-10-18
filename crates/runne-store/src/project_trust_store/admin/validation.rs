use runne_application::project_trust::admin::{
    AdminError, CurrentPolicyAdmin, ManagedPolicyCommandV1, ReservedManagedPolicyCommandV1,
    managed_policy_command_digest_v1, managed_policy_request_digest_v1,
    policy_admin_session_binding_digest,
};
use runne_application::project_trust::{
    ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, managed_effect_policy_digest_v2,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::{command_rows, identity::AdminIdentity, model::*};
use crate::project_trust_store::ProjectTrustStore;

pub(super) fn validate_current_role(
    connection: &Connection,
    current: &CurrentPolicyAdmin<'_>,
    expected_generation: Option<u64>,
) -> Result<(AdminIdentity, u64), AdminError> {
    let identity = AdminIdentity::from_current(current);
    let Some((registered, status, generation)) = AdminIdentity::load_registered(connection)? else {
        return Err(AdminError::Rejected);
    };
    if !registered.matches_current(current) || status != ROLE_ACTIVE {
        return Err(AdminError::Rejected);
    }
    let generation = u64::try_from(generation).map_err(|_| AdminError::Unavailable)?;
    if generation == 0 || expected_generation.is_some_and(|expected| expected != generation) {
        return Err(AdminError::Rejected);
    }
    Ok((identity, generation))
}

pub(super) fn validate_request_context(
    current: &CurrentPolicyAdmin<'_>,
    command: &ManagedPolicyCommandV1,
) -> Result<(), AdminError> {
    if command.request_digest() != &managed_policy_request_digest_v1(command)
        || command.launch_binding_digest()
            != &policy_admin_session_binding_digest(current.binding())
        || command.expected().instance_epoch == 0
        || command.expected().revision == 0
        || command.admin_generation() == 0
        || command.rules().version != 1
    {
        return Err(AdminError::Rejected);
    }
    Ok(())
}

pub(super) fn validate_reserved_context(
    current: &CurrentPolicyAdmin<'_>,
    command: &ReservedManagedPolicyCommandV1,
    now: i64,
) -> Result<(), AdminError> {
    if command.semantic_digest() != &managed_policy_command_digest_v1(command)
        || command.request_digest() != command.request().request_digest()
        || command.launch_binding_digest()
            != &policy_admin_session_binding_digest(current.binding())
        || command.issued_at_unix_ms() > now
        || command.expires_at_unix_ms() <= now
        || command.expires_at_unix_ms() > current.binding().session_expires_at_unix_ms()
        || command
            .expires_at_unix_ms()
            .saturating_sub(command.issued_at_unix_ms())
            > 120_000
    {
        return Err(AdminError::Rejected);
    }
    Ok(())
}

pub(super) fn load_explicit_snapshot(
    connection: &Connection,
    store: &ProjectTrustStore,
    project: ProjectTrustProjectId,
) -> Result<ProjectTrustEffectPolicySnapshot, AdminError> {
    let row: Option<(i64, i64, i64)> = connection
        .query_row(
            "SELECT status, managed_deny_mask, revision FROM project_trust WHERE project_id=?1",
            params![project.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| AdminError::Unavailable)?;
    let Some((status, mask, revision)) = row else {
        return Err(AdminError::Rejected);
    };
    let record =
        super::super::persistence::row_to_record(store.instance_epoch, status, mask, revision)
            .ok_or(AdminError::Unavailable)?;
    if record.revision == 0 {
        return Err(AdminError::Rejected);
    }
    let values: Option<(i64, i64, i64, i64, i64, i64, i64)> = connection
        .query_row(
            "SELECT policy_version, fs_read, fs_create, fs_write, fs_delete, process_start, network_use
             FROM managed_effect_policies WHERE project_id=?1",
            params![project.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        ).optional().map_err(|_| AdminError::Unavailable)?;
    let Some(values) = values else {
        return Err(AdminError::Unavailable);
    };
    let policy = command_rows::decode_policy(values).ok_or(AdminError::Unavailable)?;
    let snapshot = ProjectTrustEffectPolicySnapshot { record, policy };
    snapshot
        .is_valid()
        .then_some(snapshot)
        .ok_or(AdminError::Unavailable)
}

pub(super) fn validate_command_snapshot(
    snapshot: ProjectTrustEffectPolicySnapshot,
    command: &ManagedPolicyCommandV1,
) -> Result<(), AdminError> {
    if snapshot.record.token() != command.expected()
        || managed_effect_policy_digest_v2(command.project(), &snapshot)
            != Some(*command.old_rules_digest())
    {
        return Err(AdminError::Stale);
    }
    let next = snapshot
        .record
        .revision
        .checked_add(1)
        .ok_or(AdminError::Unavailable)?;
    let next_snapshot = ProjectTrustEffectPolicySnapshot {
        record: runne_application::project_trust::ProjectTrustRecord {
            revision: next,
            ..snapshot.record
        },
        policy: command.rules(),
    };
    if managed_effect_policy_digest_v2(command.project(), &next_snapshot)
        != Some(*command.new_rules_digest())
    {
        return Err(AdminError::Conflict);
    }
    Ok(())
}
