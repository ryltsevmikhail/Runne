pub(super) use super::admission_checks::{proof_digest, verify_admission, verify_approval};
use super::codec;
use crate::store::{StoreTransaction, taskrun_claim};
use runne_application::{
    permission_modes::LocalCommandPermissionBindingV1,
    ports::{EventStoreError, TaskRunAssignmentIdentity},
};
use runne_domain::task_run::TaskRunState;
use runne_platform::local_command_linux::PermissionTargetObservationV1;
use rusqlite::{OptionalExtension, params};
use std::time::{SystemTime, UNIX_EPOCH};

type CaptureRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, String);

pub(super) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

pub(super) fn verify_running(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    version: u64,
) -> Result<(), EventStoreError> {
    taskrun_claim::verify_active_assignment(tx, identity)
        .map_err(|_| EventStoreError::CorruptData)?;
    let stream = taskrun_claim::stream_validate::verify_stream(tx, identity.taskrun_id, None)
        .map_err(|_| EventStoreError::CorruptData)?;
    if stream.version != version || stream.state != TaskRunState::Running {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}

pub(super) fn load_capture(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    binding: &LocalCommandPermissionBindingV1,
    terminal: bool,
) -> Result<CaptureRow, EventStoreError> {
    let row: CaptureRow = tx.query_row(
        "SELECT b.binding_digest,b.binding,b.native_owner_id,b.native_owner_generation,a.executable_digest,a.state
         FROM x2_permission_bindings b JOIN taskrun_local_command_attempts a USING(taskrun_id)
         WHERE b.taskrun_id=?1 AND b.attempt_id=?2 AND b.fence=?3",
        params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.fence.0 as i64],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
    ).optional().map_err(|_| EventStoreError::CorruptData)?
        .ok_or(EventStoreError::CorruptData)?;
    let decoded = codec::decode(&row.1).map_err(|_| EventStoreError::CorruptData)?;
    let executable = binding
        .approval()
        .executable_digest
        .ok_or(EventStoreError::CorruptData)?;
    let state_allowed = if terminal {
        matches!(row.5.as_str(), "completed" | "cancelled")
    } else {
        matches!(
            row.5.as_str(),
            "approved" | "launch_intent" | "release_reserved" | "running"
        )
    };
    if !codec::digest_matches(&row.1, &row.0)
        || decoded.canonical_binding_digest != *binding.digest().as_bytes()
        || decoded.executable_digest != *executable.as_bytes()
        || decoded.native_owner_id.as_slice() != row.2.as_slice()
        || decoded.native_owner_generation.to_be_bytes().as_slice() != row.3.as_slice()
        || row.4.is_some()
        || !state_allowed
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok(row)
}

pub(super) fn verify_workspace(
    tx: &rusqlite::Transaction<'_>,
    binding: &LocalCommandPermissionBindingV1,
) -> Result<(), EventStoreError> {
    let row: Option<(Vec<u8>, i64, i64)> = tx.query_row(
        "SELECT w.project_id,p.version,w.version FROM workspaces w JOIN projects p ON p.project_id=w.project_id
         JOIN workspace_identity_history h ON h.workspace_id=w.workspace_id
         WHERE w.workspace_id=?1 AND w.principal_id=?2 AND p.principal_id=?2 AND w.project_id=h.project_id
           AND w.principal_id=h.principal_id AND h.classification='canonical' AND w.open=1 AND w.live=1 AND p.archived=0",
        params![binding.selection().scope.workspace_id.as_bytes(),binding.selection().scope.principal_id.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional().map_err(|_| EventStoreError::CorruptData)?;
    if !row.is_some_and(|(project, pv, wv)| {
        project.as_slice() == binding.project_id().as_bytes()
            && u64::try_from(pv).ok() == Some(binding.project_version())
            && u64::try_from(wv).ok() == Some(binding.workspace_version())
    }) {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}

pub(super) fn observation_matches(
    binding: &LocalCommandPermissionBindingV1,
    observed: PermissionTargetObservationV1,
) -> bool {
    let approval = binding.approval();
    approval.normalized_arguments_digest.as_bytes() == observed.normalized_arguments_digest()
        && approval.tool_schema_digest.as_bytes() == observed.schema_digest()
        && approval.target_identity_digest.as_bytes() == observed.target_identity()
        && approval.target_version == observed.target_version()
        && approval.environment_digest.as_bytes() == observed.environment_digest()
        && approval.cwd_identity_digest.as_bytes() == observed.cwd_identity()
        && approval.executable_digest.map(|value| *value.as_bytes())
            == Some(*observed.executable_digest())
}

pub(super) fn read_capture_digest(
    store: &StoreTransaction,
    binding: &LocalCommandPermissionBindingV1,
) -> Result<[u8; 32], EventStoreError> {
    store
        .load_local_command_permission_capture(binding.assignment().taskrun_id)?
        .filter(|capture| capture.canonical_binding_digest == *binding.digest().as_bytes())
        .map(|capture| capture.binding_digest)
        .ok_or(EventStoreError::CorruptData)
}

pub(super) fn validate_area(
    identity: &TaskRunAssignmentIdentity,
    bytes: &[u8; 100],
) -> Result<(), EventStoreError> {
    if &bytes[..4] != b"RMA1"
        || bytes[4..20] == [0; 16]
        || bytes[28..36] == [0; 8]
        || bytes[44..52] == [0; 8]
        || bytes[52..68] != identity.taskrun_id.as_bytes()[..]
        || bytes[68..84] != identity.attempt_id.as_bytes()[..]
        || bytes[84..100] == [0; 16]
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}
