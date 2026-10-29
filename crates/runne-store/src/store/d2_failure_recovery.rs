use super::*;
use runne_application::ports::{ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunFence};

#[derive(Debug, Clone)]
pub struct D2FailureRecoveryCandidate {
    pub taskrun_id: TaskRunId,
    pub attempt_id: AttemptId,
    pub assignment: TaskRunAssignmentIdentity,
    pub terminal_event_id: [u8; 16],
    pub terminal_version: u64,
    pub conversation_id: Option<ConversationId>,
    pub principal_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct D2FailureRecoveryPage {
    pub candidates: Vec<D2FailureRecoveryCandidate>,
    pub reached_end: bool,
}

impl StoreTransaction {
    /// Authorizes recovery-only D2 workflow stopping on a newer launch of the
    /// same node. This does not grant permission to resume any effect.
    pub fn authorize_d2_failure_recovery(
        &self,
        taskrun_id: TaskRunId,
        assignment: &TaskRunAssignmentIdentity,
        expected_head: u64,
        current_epoch: u64,
    ) -> Result<(), CommitError> {
        use crate::store::parse_helpers::storage_failure;
        let node = uuid::Uuid::parse_str(&assignment.node_id.0)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let authority = uuid::Uuid::parse_str(&self.runtime_authority_id.0)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if taskrun_id != assignment.taskrun_id
            || node != authority
            || current_epoch <= assignment.node_epoch
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let now_ms = super::position_helpers::current_time_micros()?
            .checked_div(1_000)
            .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let live: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM execution_nodes WHERE node_id=?1 AND launch_generation=?2 AND expires_at_ms>?3)",
            rusqlite::params![node.as_bytes(), i64::try_from(current_epoch).map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?, now_ms],
            |row| row.get(0),
        ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if !live {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        crate::store::taskrun_claim::verify_assignment_history(&tx, assignment)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
            &tx,
            taskrun_id,
            Some(expected_head),
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if stream.state != runne_domain::task_run::TaskRunState::Running {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let budget_rows: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM taskrun_tool_budgets WHERE taskrun_id=?1",
                rusqlite::params![taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if budget_rows > 0 {
            crate::store::taskrun_tool_invocation::budget_policy::verify_origin_policy(
                &tx, taskrun_id,
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        }
        let exact_budget: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1 AND attempt_id=?2 AND policy_revision IN ('d2-safe-tool-loop-budget-v1','coding-tool-loop-budget-v1') AND fence=?3 AND node_id=?4 AND node_epoch=?5)",
            rusqlite::params![taskrun_id.as_bytes(), assignment.attempt_id.as_bytes(), assignment.fence.0 as i64, node.to_string(), assignment.node_epoch as i64],
            |row| row.get(0),
        ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        if budget_rows > 0 && !exact_budget {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))
    }

    /// Bounded terminal candidates only; the daemon validates canonical streams
    /// before projecting any failure into a Conversation.
    pub fn d2_failure_recovery_candidates(
        &self,
        after: Option<[u8; 16]>,
        limit: usize,
    ) -> Result<D2FailureRecoveryPage, CommitError> {
        use crate::store::parse_helpers::storage_failure;
        if limit == 0 || limit > 64 {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let mut statement = reader
            .prepare(
                "SELECT a.taskrun_id,a.attempt_id,a.node_id,a.node_epoch,a.fence,t.last_event_id,t.current_version
                 FROM taskrun_assignments a
                 JOIN aggregate_streams t ON t.aggregate_type=1 AND t.aggregate_id=a.taskrun_id
                 WHERE a.fence=(SELECT MAX(latest.fence) FROM taskrun_assignments latest WHERE latest.taskrun_id=a.taskrun_id)
                   AND NOT EXISTS(
                     SELECT 1 FROM taskrun_terminal_settlement_receipts settled
                     WHERE settled.taskrun_id=a.taskrun_id AND settled.fence=a.fence
                       AND settled.attempt_id=a.attempt_id
                       AND settled.terminal_event_id=t.last_event_id
                   )
                   AND (?1 IS NULL OR a.taskrun_id>?1)
                 ORDER BY a.taskrun_id LIMIT ?2",
            )
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let rows = statement
            .query_map(
                rusqlite::params![after.as_ref().map(|id| id.as_slice()), limit as i64],
                |row| {
                    let taskrun_id = TaskRunId::from_bytes(fixed16(row.get(0)?)?);
                    let attempt_id = AttemptId::from_bytes(fixed16(row.get(1)?)?);
                    let node = fixed16(row.get(2)?)?;
                    Ok(D2FailureRecoveryCandidate {
                        taskrun_id,
                        attempt_id,
                        assignment: TaskRunAssignmentIdentity {
                            taskrun_id,
                            attempt_id,
                            node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node).to_string()),
                            node_epoch: positive(row.get(3)?)?,
                            fence: TaskRunFence(positive(row.get(4)?)?),
                        },
                        terminal_event_id: fixed16(row.get(5)?)?,
                        terminal_version: positive(row.get(6)?)?,
                        conversation_id: None,
                        principal_id: None,
                    })
                },
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let mut candidates = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        for candidate in &mut candidates {
            if let Some(origin) =
                super::taskrun_submit_origin::verify_submitted_v2_origin_for_readiness(
                    &reader,
                    candidate.taskrun_id,
                )
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
            {
                candidate.conversation_id = Some(origin.conversation_id);
                candidate.principal_id = Some(origin.principal_id.0);
            }
        }
        let reached_end = candidates.len() < limit;
        drop(statement);
        drop(reader);
        Ok(D2FailureRecoveryPage {
            candidates,
            reached_end,
        })
    }
}

fn fixed16(value: Vec<u8>) -> Result<[u8; 16], rusqlite::Error> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
fn positive(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}
