use super::*;

impl StoreTransaction {
    /// Checks that a D2 cycle has no helper that could still produce an
    /// unaccounted local effect before the caller appends its canonical Fail.
    pub fn verify_d2_tool_loop_safe_stop(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        attempt_id: runne_domain::id::AttemptId,
        cycle_id: runne_domain::id::CycleId,
        assignment: &TaskRunAssignmentIdentity,
        expected_head: u64,
        require_result: bool,
    ) -> Result<(), CommitError> {
        use crate::store::parse_helpers::storage_failure;
        if assignment.taskrun_id != taskrun_id || assignment.attempt_id != attempt_id {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let tx = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        crate::store::taskrun_claim::verify_assignment_history(&tx, assignment)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        tool_rows::verify_budget_assignment_if_present(&tx, taskrun_id, attempt_id, assignment)?;
        let stream = crate::store::taskrun_claim::stream_validate::verify_stream(
            &tx,
            taskrun_id,
            Some(expected_head),
        )
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let task = TaskRun::replay(&stream.events)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        if task.state() != TaskRunState::Running
            || !task
                .snapshot_v1()
                .active_cycle()
                .is_some_and(|cycle| cycle.cycle_id == cycle_id && cycle.attempt_id == attempt_id)
        {
            return Err(storage_failure(StorageFailureKind::IntegrityViolation));
        }
        let claim_version: i64 = tx
            .query_row(
                "SELECT new_version FROM taskrun_claim_receipts
                 WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3",
                rusqlite::params![
                    taskrun_id.as_bytes(),
                    attempt_id.as_bytes(),
                    assignment.fence.0 as i64
                ],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        let node = uuid::Uuid::parse_str(&assignment.node_id.0)
            .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
        crate::store::verify_d2_cancelled_provider_rounds(
            &tx,
            taskrun_id,
            attempt_id,
            D2ToolLoopCancellationEvidence {
                node_id: *node.as_bytes(),
                node_epoch: assignment.node_epoch,
                fence: assignment.fence.0,
                cancellation_taskrun_version: expected_head,
            },
            u64::try_from(claim_version)
                .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?,
            expected_head,
        )?;
        verify_safe_tool_stop(
            &tx,
            taskrun_id,
            attempt_id,
            cycle_id,
            assignment,
            require_result,
        )?;
        tx.commit()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))
    }
}

impl runne_application::ports::D2ToolLoopFailurePort for StoreTransaction {
    fn fail_d2_tool_loop(
        &self,
        input: runne_application::ports::D2ToolLoopFailureV1,
    ) -> Result<runne_application::ports::D2ToolLoopFailureResult, CommitError> {
        super::fail_d2_tool_loop(self, input)
    }
}
