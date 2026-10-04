use super::parse_helpers::map_event_store_read_error;
use super::*;
use runne_application::ports::{
    ExecutionNodeId, TaskRunAssignmentIdentity, TaskRunFence, TaskRunNoEffectCandidate,
    TaskRunNoEffectScanPage, TaskRunNoEffectScanRequest, TaskRunNoEffectScanner,
};
use rusqlite::TransactionBehavior;

type NoEffectAssignmentRow = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, i64);

impl TaskRunNoEffectScanner for StoreTransaction {
    fn scan_no_effect_assignments(
        &self,
        request: TaskRunNoEffectScanRequest,
    ) -> Result<TaskRunNoEffectScanPage, EventStoreError> {
        let mut reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = reader
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(map_event_store_read_error)?;
        let node = uuid::Uuid::parse_str(&request.node_id().0)
            .map_err(|_| EventStoreError::CorruptData)?;
        if node.is_nil() || node.to_string() != request.node_id().0 || request.current_epoch() == 0
        {
            return Err(EventStoreError::CorruptData);
        }
        let cursor = request.after().map(|id| id.as_bytes().to_vec());
        let mut statement = tx
            .prepare(
                "SELECT o.taskrun_id,o.fence,o.attempt_id,o.node_id,o.node_epoch,s.current_version
             FROM taskrun_assignment_occupations o
             JOIN aggregate_streams s ON s.aggregate_type=1 AND s.aggregate_id=o.taskrun_id
             WHERE o.state='active' AND o.dispatch_intent='absent'
               AND o.node_id=?1 AND o.node_epoch<?2
               AND (?3 IS NULL OR o.taskrun_id>?3)
               AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents i
                              WHERE i.taskrun_id=o.taskrun_id AND i.fence=o.fence)
               AND NOT EXISTS(SELECT 1 FROM taskrun_provider_bindings b
                              WHERE b.taskrun_id=o.taskrun_id)
               AND NOT EXISTS(SELECT 1 FROM provider_execution_admissions a
                              WHERE a.taskrun_id=o.taskrun_id)
             ORDER BY o.taskrun_id ASC LIMIT ?4",
            )
            .map_err(map_event_store_read_error)?;
        let rows = statement
            .query_map(
                params![
                    node.as_bytes(),
                    request.current_epoch() as i64,
                    cursor,
                    (request.limit() + 1) as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .map_err(map_event_store_read_error)?;
        let rows: Vec<NoEffectAssignmentRow> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_event_store_read_error)?;
        let reached_end = rows.len() <= request.limit();
        let examined = rows.len().min(request.limit());
        let next_cursor = rows
            .get(examined.saturating_sub(1))
            .map(|row| {
                let bytes: [u8; 16] = row.0.as_slice().try_into().unwrap_or([0; 16]);
                TaskRunId::from_bytes(bytes)
            })
            .or(request.after());
        let mut candidates = Vec::new();
        for (taskrun, fence, attempt, stored_node, epoch, version) in
            rows.into_iter().take(request.limit())
        {
            let taskrun = TaskRunId::from_bytes(
                taskrun
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let attempt_id = AttemptId::from_bytes(
                attempt
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let epoch = u64::try_from(epoch).map_err(|_| EventStoreError::CorruptData)?;
            let version = u64::try_from(version).map_err(|_| EventStoreError::CorruptData)?;
            let stored_node =
                uuid::Uuid::from_slice(&stored_node).map_err(|_| EventStoreError::CorruptData)?;
            let identity = TaskRunAssignmentIdentity {
                taskrun_id: taskrun,
                attempt_id,
                node_id: ExecutionNodeId(stored_node.to_string()),
                node_epoch: epoch,
                fence: TaskRunFence(
                    u64::try_from(fence).map_err(|_| EventStoreError::CorruptData)?,
                ),
            };
            let history = super::taskrun_claim::verify_assignment_history(&tx, &identity)
                .map_err(|_| EventStoreError::CorruptData)?;
            let latest_payload: Vec<u8> = tx.query_row(
                "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=?2",
                params![taskrun.as_bytes(), version as i64],
                |row| row.get(0),
            ).map_err(map_event_store_read_error)?;
            let latest = TaskRunEventCodec
                .decode(&latest_payload)
                .map_err(|_| EventStoreError::CorruptData)?;
            if history.state() == runne_domain::task_run::TaskRunState::Running {
                if history.active_attempt() != Some(&identity.attempt_id) {
                    return Err(EventStoreError::CorruptData);
                }
                match latest {
                    runne_domain::task_run::TaskRunEvent::AttemptStarted { attempt_id }
                        if attempt_id == identity.attempt_id =>
                    {
                        super::taskrun_claim::verify_active_assignment(&tx, &identity)
                            .map_err(|_| EventStoreError::CorruptData)?;
                    }
                    runne_domain::task_run::TaskRunEvent::AttemptStarted { .. } => {
                        return Err(EventStoreError::CorruptData);
                    }
                    _ => continue,
                }
            } else if history.state() == runne_domain::task_run::TaskRunState::Cancelling {
                if history.active_attempt() != Some(&identity.attempt_id) {
                    return Err(EventStoreError::CorruptData);
                }
                continue;
            } else if history.state().is_terminal() {
                continue;
            } else {
                return Err(EventStoreError::CorruptData);
            }
            let began = super::taskrun_no_effect_proof::has_generation_evidence(
                &tx,
                taskrun,
                identity.attempt_id,
                &self.runtime_authority_id,
            )
            .map_err(|_| EventStoreError::CorruptData)?;
            if epoch < request.current_epoch() && !began {
                candidates.push(TaskRunNoEffectCandidate {
                    identity,
                    current_version: version,
                });
            }
        }
        drop(statement);
        tx.commit().map_err(map_event_store_read_error)?;
        Ok(TaskRunNoEffectScanPage {
            candidates,
            next_cursor,
            reached_end,
        })
    }
}
