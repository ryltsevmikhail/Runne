use super::codec;
use crate::store::{StoreTransaction, taskrun_claim};
use runne_application::{
    permission_modes::{
        ContainmentStrategy, FilesystemPosture, LocalCommandPermissionBindingV1, PermissionMode,
    },
    ports::{EventStoreError, TaskRunAssignmentIdentity},
    project_trust::{ManagedEffectClass, ManagedEffectDecision},
};
use runne_domain::{
    id::{ApprovalId, TaskRunId},
    task_run::TaskRunState,
};
use runne_platform::local_command_linux::PermissionTargetObservationV1;
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type CaptureRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, String);
type ApprovalRow = (
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    Vec<u8>,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<String>,
    Option<i64>,
    i64,
);

pub(super) fn verify_approval(
    tx: &Transaction<'_>,
    binding: &LocalCommandPermissionBindingV1,
    id: ApprovalId,
    allow_expired: bool,
) -> Result<i64, EventStoreError> {
    let row: Option<ApprovalRow> = tx.query_row(
        "SELECT task_run_id,attempt_id,invocation_id,principal_id,action,resource,action_digest,
                policy_revision,request_version,state,decision,decision_principal_id,decided_at,expires_at
         FROM approvals WHERE approval_id=?1",
        [id.to_string()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,
            row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?,row.get(11)?,row.get(12)?,row.get(13)?)),
    ).optional().map_err(|_| EventStoreError::CorruptData)?;
    let Some(row) = row else {
        return Err(EventStoreError::CorruptData);
    };
    let accepted = row.12.ok_or(EventStoreError::CorruptData)?;
    let taskrun = binding.assignment().taskrun_id;
    let attempt = binding.assignment().attempt_id;
    let attempt_text = attempt.to_string();
    let resource = format!(
        "taskrun:{taskrun}:workspace:{}",
        binding.selection().scope.workspace_id
    );
    if row.0 != taskrun.to_string()
        || row.1.as_deref() != Some(attempt_text.as_str())
        || row.2 != binding.invocation_id().to_string()
        || row.3 != binding.selection().scope.principal_id.as_str()
        || row.4 != "local_command.execute"
        || row.5 != resource
        || row.6.as_slice() != binding.approval().digest().as_bytes()
        || row.7 != runne_application::project_trust::LOCAL_COMMAND_POLICY_VERSION as i64
        || row.8 != 2
        || row.9 != 2
        || row.10 != Some(1)
        || row.11.as_deref() != Some(row.3.as_str())
        || row.13 != binding.approval().expires_at_unix_ms
        || accepted <= 0
        || (!allow_expired && row.13 <= now_ms())
        || row.13 <= accepted
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok(accepted)
}

pub(super) fn proof_digest(
    taskrun: TaskRunId,
    binding: &LocalCommandPermissionBindingV1,
    id: ApprovalId,
    accepted_at: i64,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:x2-human-approval-proof:v1\0");
    hash.update(taskrun.as_bytes());
    hash.update(binding.assignment().attempt_id.as_bytes());
    hash.update(binding.digest().as_bytes());
    hash.update(binding.approval().digest().as_bytes());
    hash.update(id.as_bytes());
    hash.update(accepted_at.to_be_bytes());
    hash.finalize().into()
}

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

pub(super) fn verify_admission(
    tx: &rusqlite::Transaction<'_>,
    binding: &LocalCommandPermissionBindingV1,
    digest: &[u8; 32],
    now: i64,
    allow_expired: bool,
) -> Result<(), EventStoreError> {
    let row: Option<(i64, Option<Vec<u8>>)> = tx
        .query_row(
            "SELECT admission_kind,proof_digest FROM x2_permission_admission
         WHERE taskrun_id=?1 AND attempt_id=?2 AND binding_digest=?3",
            params![
                binding.assignment().taskrun_id.as_bytes(),
                binding.assignment().attempt_id.as_bytes(),
                digest.as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    match row {
        Some((1, None))
            if binding.selection().selected_mode == PermissionMode::FullAccess
                && binding.scope().filesystem.posture == FilesystemPosture::BroadSameUser
                && matches!(
                    binding.scope().containment,
                    ContainmentStrategy::SameUserCompositeV1
                        | ContainmentStrategy::SameUserCompositeV2
                )
                && binding
                    .closed_rules_snapshot()
                    .policy
                    .decision_for(ManagedEffectClass::ProcessStart)
                    == ManagedEffectDecision::Allow =>
        {
            Ok(())
        }
        Some((2, Some(proof))) => {
            let human: (Vec<u8>, Vec<u8>, i64) = tx
                .query_row(
                    "SELECT approval_id,proof_digest,accepted_at FROM x2_permission_human
                 WHERE taskrun_id=?1 AND attempt_id=?2 AND binding_digest=?3",
                    params![
                        binding.assignment().taskrun_id.as_bytes(),
                        binding.assignment().attempt_id.as_bytes(),
                        digest.as_slice()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|_| EventStoreError::CorruptData)?;
            let id = ApprovalId::from_bytes(
                human
                    .0
                    .as_slice()
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            if human.1 != proof
                || proof.as_slice()
                    != proof_digest(binding.assignment().taskrun_id, binding, id, human.2)
                        .as_slice()
                || verify_approval(tx, binding, id, allow_expired)? != human.2
                || human.2 > now
            {
                return Err(EventStoreError::CorruptData);
            }
            Ok(())
        }
        _ => Err(EventStoreError::CorruptData),
    }
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
