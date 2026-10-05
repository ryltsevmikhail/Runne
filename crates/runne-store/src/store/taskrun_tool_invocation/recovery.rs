use super::*;
use runne_application::ports::ExecutionNodeId;
use runne_domain::id::{AttemptId, CycleId};
use rusqlite::{TransactionBehavior, params};
mod authorize;

#[derive(Debug, Clone)]
pub struct ToolInvocationAreaRecoveryCandidate {
    pub key: ToolInvocationKey,
    pub semantic_digest: IntegrityDigest,
    pub assignment: TaskRunAssignmentIdentity,
    pub area_identity: [u8; 100],
    pub state: ToolInvocationState,
    pub release_started: bool,
}

impl StoreTransaction {
    pub fn scan_taskrun_tool_area_recovery(
        &self,
        after: Option<(TaskRunId, AttemptId, CycleId, u32)>,
        limit: usize,
    ) -> Result<Vec<ToolInvocationAreaRecoveryCandidate>, ToolInvocationStoreError> {
        if !(1..=128).contains(&limit) {
            return Err(ToolInvocationStoreError::Unavailable);
        }
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        let mut stmt = reader.prepare(
            "SELECT taskrun_id,attempt_id,cycle_id,proposal_index,semantic_digest,
                    claim_fence,claim_node_id,claim_node_epoch,managed_area_identity,state,release_started
             FROM taskrun_tool_invocations WHERE local_stop_state=1 AND managed_area_identity IS NOT NULL
               AND state IN ('claimed','uncertain','cancelled','audit_only')
               AND (?1 IS NULL OR (taskrun_id,attempt_id,cycle_id,proposal_index)>(?1,?2,?3,?4))
             ORDER BY taskrun_id,attempt_id,cycle_id,proposal_index LIMIT ?5",
        ).map_err(|_| ToolInvocationStoreError::Unavailable)?;
        let rows = stmt
            .query_map(
                params![
                    after.map(|v| v.0.as_bytes().to_vec()),
                    after.map(|v| v.1.as_bytes().to_vec()),
                    after.map(|v| v.2.as_bytes().to_vec()),
                    after.map(|v| i64::from(v.3)),
                    limit as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Vec<u8>>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, i64>(10)?,
                    ))
                },
            )
            .map_err(|_| ToolInvocationStoreError::CorruptData)?;
        let mut out = Vec::new();
        for row in rows {
            let (task, attempt, cycle, index, digest, fence, node, epoch, area, state, released) =
                row.map_err(|_| ToolInvocationStoreError::CorruptData)?;
            let taskrun_id = TaskRunId::from_bytes(fixed::<16>(task)?);
            let attempt_id = AttemptId::from_bytes(fixed::<16>(attempt)?);
            let cycle_id = CycleId::from_bytes(fixed::<16>(cycle)?);
            let fence = u64::try_from(fence)
                .ok()
                .filter(|v| *v > 0)
                .ok_or(ToolInvocationStoreError::CorruptData)?;
            let node_epoch = u64::try_from(epoch)
                .ok()
                .filter(|v| *v > 0)
                .ok_or(ToolInvocationStoreError::CorruptData)?;
            let area = fixed::<100>(area)?;
            let state = match state.as_str() {
                "claimed" => ToolInvocationState::Claimed,
                "uncertain" => ToolInvocationState::Uncertain,
                "cancelled" => ToolInvocationState::Cancelled,
                "audit_only" => ToolInvocationState::AuditOnly,
                _ => return Err(ToolInvocationStoreError::CorruptData),
            };
            out.push(ToolInvocationAreaRecoveryCandidate {
                key: ToolInvocationKey {
                    taskrun_id,
                    attempt_id,
                    cycle_id,
                    proposal_index: u32::try_from(index)
                        .map_err(|_| ToolInvocationStoreError::CorruptData)?,
                },
                semantic_digest: IntegrityDigest::from_bytes(fixed::<32>(digest)?),
                assignment: TaskRunAssignmentIdentity {
                    taskrun_id,
                    attempt_id,
                    node_id: ExecutionNodeId(node),
                    node_epoch,
                    fence: runne_application::ports::TaskRunFence(fence),
                },
                area_identity: area,
                state,
                release_started: released == 1,
            });
        }
        Ok(out)
    }

    /// Authorizes metadata-only reopening/termination of one exact retained D2 area.
    /// Call before touching the managed area; proof persistence rechecks this fence.
    pub fn authorize_taskrun_tool_area_recovery(
        &self,
        candidate: &ToolInvocationAreaRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
    ) -> Result<(), ToolInvocationStoreError> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        authorize::verify_recovery_candidate(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;
        tx.commit()
            .map_err(|_| ToolInvocationStoreError::Unavailable)
    }

    /// Freezes an unresolved area without treating absence or failed reopen as proof.
    pub fn mark_taskrun_tool_area_recovery_uncertain(
        &self,
        candidate: &ToolInvocationAreaRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
    ) -> Result<(), ToolInvocationStoreError> {
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        authorize::verify_recovery_candidate(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;
        if candidate.state == ToolInvocationState::Claimed {
            tx.execute(
                "UPDATE taskrun_tool_invocations SET state='uncertain',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5 AND state='claimed' AND local_stop_state=1",
                params![validate::fresh_now_millis(),candidate.key.taskrun_id.as_bytes(),candidate.key.attempt_id.as_bytes(),candidate.key.cycle_id.as_bytes(),i64::from(candidate.key.proposal_index)],
            ).map_err(|_| ToolInvocationStoreError::CorruptData)?;
        }
        tx.commit()
            .map_err(|_| ToolInvocationStoreError::Unavailable)
    }

    pub fn record_taskrun_tool_area_recovered(
        &self,
        candidate: &ToolInvocationAreaRecoveryCandidate,
        current_node: &ExecutionNodeId,
        current_epoch: u64,
        identity: &runne_platform::process_managed_area::ManagedAreaIdentity,
        proof: &runne_platform::process_managed_area::VerifiedEmptyManagedArea<'_>,
    ) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
        let bytes = identity.to_bytes();
        if bytes != candidate.area_identity
            || proof.identity_bytes() != &bytes
            || bytes[52..68] != *candidate.key.taskrun_id.as_bytes()
            || bytes[68..84] != *candidate.key.attempt_id.as_bytes()
            || bytes[84..100] != candidate.key.managed_area_nonce(candidate.semantic_digest)
            || current_node != &candidate.assignment.node_id
            || current_epoch <= candidate.assignment.node_epoch
            || proof.revalidate().is_err()
        {
            return Err(ToolInvocationStoreError::Conflict);
        }
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        let now = validate::fresh_now_millis();
        authorize::verify_recovery_candidate(
            &tx,
            candidate,
            current_node,
            current_epoch,
            &self.runtime_authority_id,
        )?;
        let old =
            read::load_record(&tx, candidate.key)?.ok_or(ToolInvocationStoreError::InvalidState)?;
        if old.receipt.semantic_digest != candidate.semantic_digest
            || old.managed_area_identity != Some(bytes)
            || old.local_stop_state != LocalToolStopState::Launched
            || old.claim_assignment.as_ref() != Some(&candidate.assignment)
            || !matches!(
                old.receipt.state,
                ToolInvocationState::Claimed
                    | ToolInvocationState::Uncertain
                    | ToolInvocationState::Cancelled
                    | ToolInvocationState::AuditOnly
            )
        {
            return Err(ToolInvocationStoreError::Conflict);
        }
        let next = if old.receipt.state == ToolInvocationState::Claimed {
            "uncertain"
        } else {
            state_db(old.receipt.state)
        };
        tx.execute("UPDATE taskrun_tool_invocations SET local_stop_state=2,empty_proof_identity=?1,state=?2,updated_at=?3 WHERE taskrun_id=?4 AND attempt_id=?5 AND cycle_id=?6 AND proposal_index=?7 AND local_stop_state=1 AND empty_proof_identity IS NULL",
            params![bytes.as_slice(),next,now,candidate.key.taskrun_id.as_bytes(),candidate.key.attempt_id.as_bytes(),candidate.key.cycle_id.as_bytes(),i64::from(candidate.key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
        let result = read::get_from_connection(&tx, candidate.key)?
            .ok_or(ToolInvocationStoreError::CorruptData)?;
        tx.commit()
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        Ok(result)
    }
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], ToolInvocationStoreError> {
    bytes
        .try_into()
        .map_err(|_| ToolInvocationStoreError::CorruptData)
}

fn state_db(state: ToolInvocationState) -> &'static str {
    match state {
        ToolInvocationState::Proposed => "proposed",
        ToolInvocationState::Approved => "approved",
        ToolInvocationState::Denied => "denied",
        ToolInvocationState::Claimed => "claimed",
        ToolInvocationState::Uncertain => "uncertain",
        ToolInvocationState::Result => "result",
        ToolInvocationState::Cancelled => "cancelled",
        ToolInvocationState::AuditOnly => "audit_only",
    }
}
