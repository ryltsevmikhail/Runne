use super::super::*;
use super::LocalCommandApprovalBinding;
use runne_application::ports::{EventStoreError, TaskRunAssignmentIdentity};
use runne_domain::task_run::TaskRunState;
use rusqlite::{TransactionBehavior, params};
use sha2::{Digest, Sha256};

type PersistedReleaseBinding = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Vec<u8>,
);
type WorkspaceReleaseRow = (i64, String, Vec<u8>);
type ApprovalReleaseRow = (
    String,
    Option<String>,
    String,
    String,
    Vec<u8>,
    i64,
    i64,
    i64,
);

impl StoreTransaction {
    /// Persists exact assignment and cgroup identity before a gated child exists.
    pub fn persist_local_command_launch_intent(
        &self,
        identity: &TaskRunAssignmentIdentity,
        claimed_version: u64,
        area_identity: &[u8],
    ) -> Result<(), EventStoreError> {
        validate_area_binding(identity, area_identity)?;
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        super::super::taskrun_claim::verify_active_assignment(&tx, identity)
            .map_err(|_| EventStoreError::CorruptData)?;
        let stream = super::super::taskrun_claim::stream_validate::verify_stream(
            &tx,
            identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.version != claimed_version || stream.state != TaskRunState::Running {
            return Err(EventStoreError::CorruptData);
        }
        let node =
            uuid::Uuid::parse_str(&identity.node_id.0).map_err(|_| EventStoreError::CorruptData)?;
        let changed = tx.execute(
            "UPDATE taskrun_local_command_attempts SET attempt_id=?1,node_id=?2,node_epoch=?3,fence=?4,managed_area_identity=?5,state='launch_intent',updated_at=?6 WHERE taskrun_id=?7 AND state='approved' AND attempt_id IS NULL",
            params![identity.attempt_id.as_bytes(),node.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity,now_millis(),identity.taskrun_id.as_bytes()],
        ).map_err(|_| EventStoreError::CorruptData)?;
        if changed != 1 {
            return Err(EventStoreError::CorruptData);
        }
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }

    /// Serializes cancellation against gate GO using the canonical IMMEDIATE writer.
    /// The callback rechecks the held root and releases the stopped child before commit.
    pub fn with_local_command_release(
        &self,
        identity: &TaskRunAssignmentIdentity,
        claimed_version: u64,
        area_identity: &[u8],
        binding: LocalCommandApprovalBinding,
        approval_digest: [u8; 32],
        release_gate: impl FnOnce() -> Result<(), ()>,
    ) -> Result<(), EventStoreError> {
        validate_area_binding(identity, area_identity)?;
        let mut connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| EventStoreError::Unavailable)?;
        super::super::taskrun_claim::verify_active_assignment(&tx, identity)
            .map_err(|_| EventStoreError::CorruptData)?;
        let stream = super::super::taskrun_claim::stream_validate::verify_stream(
            &tx,
            identity.taskrun_id,
            None,
        )
        .map_err(|_| EventStoreError::CorruptData)?;
        if stream.version != claimed_version || stream.state != TaskRunState::Running {
            return Err(EventStoreError::CorruptData);
        }
        let area: Option<Vec<u8>> = tx.query_row(
            "SELECT managed_area_identity FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2 AND node_epoch=?3 AND fence=?4 AND state='launch_intent'",
            params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64],
            |row| row.get(0),
        ).optional().map_err(|_| EventStoreError::CorruptData)?;
        if area.as_deref() != Some(area_identity) {
            return Err(EventStoreError::CorruptData);
        }
        verify_current_release_binding(
            &tx,
            identity,
            binding,
            approval_digest,
            area_identity,
            &self.runtime_authority_id,
        )?;
        tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='release_reserved',updated_at=?1 WHERE taskrun_id=?2 AND state='launch_intent'",
            params![now_millis(),identity.taskrun_id.as_bytes()],
        ).map_err(|_| EventStoreError::CorruptData)?;
        release_gate().map_err(|_| EventStoreError::Unavailable)?;
        tx.execute(
            "UPDATE taskrun_local_command_attempts SET state='running',updated_at=?1 WHERE taskrun_id=?2 AND state='release_reserved'",
            params![now_millis(),identity.taskrun_id.as_bytes()],
        ).map_err(|_| EventStoreError::CorruptData)?;
        tx.commit().map_err(|_| EventStoreError::Unavailable)
    }
}

fn verify_current_release_binding(
    tx: &rusqlite::Transaction<'_>,
    identity: &TaskRunAssignmentIdentity,
    binding: LocalCommandApprovalBinding,
    approval_digest: [u8; 32],
    area_identity: &[u8],
    runtime_authority: &runne_application::ports::RuntimeAuthorityId,
) -> Result<(), EventStoreError> {
    let persisted: Option<PersistedReleaseBinding> = tx
        .query_row(
            "SELECT workspace_id,command_digest,executable_digest,workspace_version,admitted_root_version,
                    admitted_root_identity,trust_epoch,trust_revision,source_policy_version,
                    command_policy_version,approval_id
             FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND attempt_id=?2
               AND node_epoch=?3 AND fence=?4 AND managed_area_identity=?5 AND state='launch_intent'",
            params![identity.taskrun_id.as_bytes(),identity.attempt_id.as_bytes(),identity.node_epoch as i64,identity.fence.0 as i64,area_identity],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some(saved) = persisted else {
        return Err(EventStoreError::CorruptData);
    };
    if saved.1.as_slice() != binding.command_digest
        || saved.2.as_slice() != binding.executable_digest
        || saved.3 != binding.workspace_version as i64
        || saved.4 != binding.admitted_root_version as i64
        || saved.5.as_slice() != binding.admitted_root_identity
        || saved.6 != binding.trust_epoch as i64
        || saved.7 != binding.trust_revision as i64
        || saved.8 != binding.source_policy_version as i64
        || saved.9 != binding.command_policy_version as i64
        || saved.10.as_slice() != binding.approval_id
    {
        return Err(EventStoreError::CorruptData);
    }
    let origin = crate::store::taskrun_submit_origin::verify_submitted_v2_origin(
        tx,
        identity.taskrun_id,
        runtime_authority,
    )
    .map_err(|_| EventStoreError::CorruptData)?
    .ok_or(EventStoreError::CorruptData)?;
    if origin.workspace_id.as_bytes().as_slice() != saved.0.as_slice()
        || origin
            .input
            .local_command()
            .map(|value| value.intent_digest())
            != Some(binding.command_digest)
    {
        return Err(EventStoreError::CorruptData);
    }
    let workspace: Option<WorkspaceReleaseRow> = tx
        .query_row(
            "SELECT w.version,w.principal_id,w.project_id FROM workspaces w
             JOIN projects p ON p.project_id=w.project_id
             WHERE w.workspace_id=?1 AND w.live=1 AND w.open=1 AND p.archived=0",
            [saved.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((version, principal, project)) = workspace else {
        return Err(EventStoreError::CorruptData);
    };
    if version != binding.workspace_version as i64 || principal != origin.principal_id.0 {
        return Err(EventStoreError::CorruptData);
    }
    let project: [u8; 16] = project
        .try_into()
        .map_err(|_| EventStoreError::CorruptData)?;
    if approval_digest_for(binding, project) != approval_digest {
        return Err(EventStoreError::CorruptData);
    }
    let approval_id = runne_domain::id::ApprovalId::from_bytes(binding.approval_id);
    let approval: Option<ApprovalReleaseRow> = tx
        .query_row(
            "SELECT task_run_id,attempt_id,action,resource,action_digest,policy_revision,state,expires_at
             FROM approvals WHERE approval_id=?1 AND principal_id=?2",
            params![approval_id.to_string(), principal],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let now = now_millis();
    let Some(approval) = approval else {
        return Err(EventStoreError::CorruptData);
    };
    let taskrun = identity.taskrun_id.to_string();
    let workspace = runne_domain::id::WorkspaceId::from_bytes(
        saved
            .0
            .as_slice()
            .try_into()
            .map_err(|_| EventStoreError::CorruptData)?,
    );
    let resource = format!("taskrun:{taskrun}:workspace:{workspace}");
    if approval.0 != taskrun
        || approval.1.is_some()
        || approval.2 != "local_command.execute"
        || approval.3 != resource
        || approval.4.as_slice() != approval_digest
        || approval.5 != binding.command_policy_version as i64
        || approval.6 != 2
        || approval.7 <= now
    {
        return Err(EventStoreError::CorruptData);
    }
    Ok(())
}

fn approval_digest_for(binding: LocalCommandApprovalBinding, project: [u8; 16]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne-local-command-approval-v1\0");
    hash.update(binding.command_digest);
    hash.update(binding.executable_digest);
    hash.update(project);
    hash.update(binding.workspace_version.to_be_bytes());
    hash.update(binding.admitted_root_version.to_be_bytes());
    hash.update(binding.admitted_root_identity);
    hash.update(binding.trust_epoch.to_be_bytes());
    hash.update(binding.trust_revision.to_be_bytes());
    hash.update(binding.source_policy_version.to_be_bytes());
    hash.update(binding.command_policy_version.to_be_bytes());
    hash.finalize().into()
}

fn validate_area_binding(
    identity: &TaskRunAssignmentIdentity,
    bytes: &[u8],
) -> Result<(), EventStoreError> {
    if bytes.len() != 100
        || &bytes[..4] != b"RMA1"
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

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
