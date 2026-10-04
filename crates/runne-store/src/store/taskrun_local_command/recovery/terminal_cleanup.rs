use super::super::{LocalCommandAttemptState, LocalCommandRecoveryCandidate};
use super::helpers::fixed_id;
use crate::store::StoreTransaction;
use runne_application::ports::{EventStoreError, TaskRunAssignmentIdentity, TaskRunFence};
use runne_domain::id::{AttemptId, TaskRunId};
use rusqlite::params;

impl StoreTransaction {
    /// Lists completed local attempts whose durable receipt committed before area removal.
    pub fn scan_local_command_terminal_cleanup(
        &self,
        after: Option<TaskRunId>,
        limit: usize,
    ) -> Result<Vec<LocalCommandRecoveryCandidate>, EventStoreError> {
        if !(1..=128).contains(&limit) {
            return Err(EventStoreError::Unavailable);
        }
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT a.taskrun_id,a.attempt_id,a.node_id,a.node_epoch,a.fence,a.managed_area_identity,a.state,a.exit_code
                 FROM taskrun_local_command_attempts a
                 JOIN taskrun_terminal_settlement_receipts s
                   ON s.taskrun_id=a.taskrun_id AND s.fence=a.fence
                 JOIN taskrun_assignment_occupations o
                   ON o.taskrun_id=s.taskrun_id AND o.fence=s.fence
                 JOIN events e ON e.event_id=s.terminal_event_id
                 WHERE a.state IN ('completed','cancelled')
                   AND a.attempt_id=s.attempt_id AND a.node_id=s.node_id AND a.node_epoch=s.node_epoch
                   AND o.attempt_id=a.attempt_id AND o.node_id=a.node_id AND o.node_epoch=a.node_epoch
                   AND o.state='released' AND o.release_event_id=s.terminal_event_id
                   AND e.aggregate_type=1 AND e.aggregate_id=a.taskrun_id AND e.sequence=s.terminal_version
                   AND (?1 IS NULL OR a.taskrun_id>?1)
                 ORDER BY a.taskrun_id LIMIT ?2",
            )
            .map_err(|_| EventStoreError::Unavailable)?;
        let rows = statement
            .query_map(
                params![after.map(|id| id.as_bytes().to_vec()), limit as i64],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<i32>>(7)?,
                    ))
                },
            )
            .map_err(|_| EventStoreError::Unavailable)?;
        rows.map(|row| {
            let (task, attempt, node, epoch, fence, area_identity, state, exit_code) =
                row.map_err(|_| EventStoreError::CorruptData)?;
            let taskrun_id = fixed_id::<16>(&task)?;
            let attempt_id = fixed_id::<16>(&attempt)?;
            let node_id = fixed_id::<16>(&node)?;
            if epoch <= 0 || fence <= 0 || area_identity.len() != 100 {
                return Err(EventStoreError::CorruptData);
            }
            Ok(LocalCommandRecoveryCandidate {
                identity: TaskRunAssignmentIdentity {
                    taskrun_id: TaskRunId::from_bytes(taskrun_id),
                    attempt_id: AttemptId::from_bytes(attempt_id),
                    node_id: runne_application::ports::ExecutionNodeId(
                        uuid::Uuid::from_bytes(node_id).to_string(),
                    ),
                    node_epoch: u64::try_from(epoch).map_err(|_| EventStoreError::CorruptData)?,
                    fence: TaskRunFence(
                        u64::try_from(fence).map_err(|_| EventStoreError::CorruptData)?,
                    ),
                },
                area_identity,
                state: LocalCommandAttemptState::from_sql(&state)?,
                exit_code,
            })
        })
        .collect()
    }
}
