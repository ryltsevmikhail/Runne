use runne_api::ApiPrincipalId;
use runne_application::{
    permission_modes::{
        PermissionMode, PermissionScope, PresetVersion, managed_policy_semantics_digest,
    },
    project_trust::{ProjectTrustEffectLease, ProjectTrustProjectId, ProjectTrustStatus},
};
use runne_domain::id::{EventLogLineageId, validate_uuid_v7_bytes};
use rusqlite::{Connection, OptionalExtension, params};

use super::model::{
    ManagedSnapshot, PermissionModeAuthorityContext, PermissionModeStoreError,
    ProtectedNativeLaunchContext,
};
use crate::store::StoreTransaction;

#[derive(Debug, Clone, Copy)]
pub(super) struct OwnedWorkspace {
    pub(super) project_id: [u8; 16],
    pub(super) project_version: u64,
    pub(super) workspace_version: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct StoreIdentity {
    pub(super) authority_id: [u8; 16],
    pub(super) lineage_id: EventLogLineageId,
}

pub(super) fn check_scope_authority(
    store: &StoreTransaction,
    scope: &PermissionScope,
    principal: &ApiPrincipalId,
) -> Result<(), PermissionModeStoreError> {
    if scope.runtime_authority_id != *store.runtime_authority_id()
        || scope.principal_id != *principal
    {
        return Err(PermissionModeStoreError::AuthorityMismatch);
    }
    Ok(())
}

pub(super) fn owned_open_workspace(
    connection: &Connection,
    scope: &PermissionScope,
) -> Result<OwnedWorkspace, PermissionModeStoreError> {
    let row: Option<(Vec<u8>, i64, i64)> = connection
        .query_row(
            "SELECT w.project_id,p.version,w.version
             FROM workspaces w
             JOIN projects p ON p.project_id=w.project_id
             JOIN workspace_identity_history h ON h.workspace_id=w.workspace_id
             WHERE w.workspace_id=?1 AND w.principal_id=?2 AND p.principal_id=?2
               AND w.project_id=h.project_id AND w.principal_id=h.principal_id
               AND h.classification='canonical' AND w.open=1 AND w.live=1 AND p.archived=0",
            params![scope.workspace_id.as_bytes(), scope.principal_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| PermissionModeStoreError::Unavailable)?;
    let Some((project, project_version, workspace_version)) = row else {
        return Err(PermissionModeStoreError::ScopeUnavailable);
    };
    let project_id: [u8; 16] = project
        .try_into()
        .map_err(|_| PermissionModeStoreError::CorruptData)?;
    let project_version = u64::try_from(project_version)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(PermissionModeStoreError::CorruptData)?;
    let workspace_version = u64::try_from(workspace_version)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(PermissionModeStoreError::CorruptData)?;
    Ok(OwnedWorkspace {
        project_id,
        project_version,
        workspace_version,
    })
}

pub(super) fn managed_snapshot(
    context: &PermissionModeAuthorityContext<'_>,
    project_id: [u8; 16],
) -> Result<ManagedSnapshot, PermissionModeStoreError> {
    if context.trust_project_id.as_bytes() != &project_id {
        return Err(PermissionModeStoreError::ManagedPolicyStale);
    }
    managed_snapshot_from_lease(context.trust_project_id, context.trust_lease)
}

fn managed_snapshot_from_lease(
    project_id: ProjectTrustProjectId,
    lease: &dyn ProjectTrustEffectLease,
) -> Result<ManagedSnapshot, PermissionModeStoreError> {
    let record = lease.record();
    if record.instance_epoch == 0
        || i64::try_from(record.instance_epoch).is_err()
        || i64::try_from(record.revision).is_err()
    {
        return Err(PermissionModeStoreError::ManagedPolicyStale);
    }
    Ok(ManagedSnapshot {
        project_id,
        instance_epoch: record.instance_epoch,
        revision: record.revision,
        status: record.status,
        deny_mask: record.managed_deny_mask,
        digest: managed_policy_semantics_digest(project_id, record),
    })
}

pub(super) fn trust_status_tag(status: ProjectTrustStatus) -> i64 {
    match status {
        ProjectTrustStatus::Untrusted => 1,
        ProjectTrustStatus::Trusted => 2,
        ProjectTrustStatus::Managed => 3,
    }
}

pub(super) fn store_identity(
    connection: &Connection,
    scope: &PermissionScope,
) -> Result<StoreIdentity, PermissionModeStoreError> {
    let authority_id = crate::schema::read_authority_id(connection)
        .map_err(|_| PermissionModeStoreError::Unavailable)?
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
    validate_uuid_v7_bytes(&authority_id)
        .map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?;
    let runtime_authority = authority_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if scope.runtime_authority_id.0 != runtime_authority {
        return Err(PermissionModeStoreError::AuthorityMismatch);
    }
    let lineage_id = crate::schema::read_event_log_lineage_id(connection)
        .map_err(|_| PermissionModeStoreError::Unavailable)?
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)?;
    Ok(StoreIdentity {
        authority_id,
        lineage_id,
    })
}

pub(super) fn mode_from_tag(tag: i64) -> Result<PermissionMode, PermissionModeStoreError> {
    match tag {
        1 => Ok(PermissionMode::AskAlways),
        2 => Ok(PermissionMode::RiskBased),
        3 => Ok(PermissionMode::FullAccess),
        _ => Err(PermissionModeStoreError::CorruptData),
    }
}

pub(super) fn mode_tag(mode: PermissionMode) -> i64 {
    match mode {
        PermissionMode::AskAlways => 1,
        PermissionMode::RiskBased => 2,
        PermissionMode::FullAccess => 3,
    }
}

pub(super) fn preset_version(value: i64) -> Result<PresetVersion, PermissionModeStoreError> {
    if value == i64::from(PresetVersion::V1.as_u16()) {
        Ok(PresetVersion::V1)
    } else {
        Err(PermissionModeStoreError::CorruptData)
    }
}

pub(super) fn native_launch_fields(
    context: &PermissionModeAuthorityContext<'_>,
) -> Result<ProtectedNativeLaunchContext, PermissionModeStoreError> {
    context
        .native_launch
        .copied()
        .ok_or(PermissionModeStoreError::ReauthenticationUnavailable)
}
