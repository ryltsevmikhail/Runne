type StepOutcomePermissionRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i64>,
);

impl StoreTransaction {
    fn commit_transaction(
        &self,
        tx: rusqlite::Transaction<'_>,
        payload: CommandCommit,
        taskrun_id: TaskRunId,
        taskrun_bytes: &[u8; 16],
    ) -> Result<CommitResult, CommitError> {
        self.commit_transaction_with_permission_terminal(
            tx,
            payload,
            taskrun_id,
            taskrun_bytes,
            None,
        )
    }
}

fn guard_step_outcome_permission(
    tx: &rusqlite::Transaction<'_>,
    store: &StoreTransaction,
    payload: &CommandCommit,
    taskrun_id: TaskRunId,
    now_micros: i64,
) -> Result<(), CommitError> {
    for event in &payload.events {
        let runne_domain::task_run::TaskRunEvent::StepOutcomeRecorded { cycle_id, outcome } =
            event.payload()
        else {
            continue;
        };
        let row: Option<StepOutcomePermissionRow> = tx
            .query_row(
                "SELECT attempt_id,semantic_digest,state,result_digest,helper_receipt_digest,
                        result_truncated,claim_fence,claim_node_id,claim_node_epoch
                 FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND cycle_id=?2
                   AND proposal_index=?3",
                rusqlite::params![
                    taskrun_id.as_bytes(),
                    cycle_id.as_bytes(),
                    i64::from(outcome.proposal_index)
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| step_outcome_integrity_failure())?;
        let Some((attempt, semantic, state, result, receipt, truncated, fence, node, epoch)) = row
        else {
            continue;
        };
        if state != "result" || truncated != Some(0) {
            return Err(step_outcome_integrity_failure());
        }
        let attempt = attempt
            .try_into()
            .map_err(|_| step_outcome_integrity_failure())?;
        let semantic = step_outcome_digest(semantic)?;
        let result = step_outcome_digest(result.ok_or_else(step_outcome_integrity_failure)?)?;
        let receipt = step_outcome_digest(receipt.ok_or_else(step_outcome_integrity_failure)?)?;
        if outcome.outcome_type != runne_domain::agent_loop::StepOutcomeType::Succeeded
            || !outcome
                .result_ref
                .as_ref()
                .is_some_and(|result_ref| result_ref.integrity_digest() == &result)
            || outcome.evidence_digests != vec![semantic, result, receipt]
        {
            return Err(step_outcome_integrity_failure());
        }
        let (Some(fence), Some(node), Some(epoch)) = (fence, node, epoch) else {
            return Err(step_outcome_integrity_failure());
        };
        let assignment = runne_application::ports::TaskRunAssignmentIdentity {
            taskrun_id,
            attempt_id: runne_domain::id::AttemptId::from_bytes(attempt),
            node_id: runne_application::ports::ExecutionNodeId(node),
            node_epoch: u64::try_from(epoch).map_err(|_| step_outcome_integrity_failure())?,
            fence: runne_application::ports::TaskRunFence(
                u64::try_from(fence).map_err(|_| step_outcome_integrity_failure())?,
            ),
        };
        let key = crate::store::taskrun_tool_invocation::ToolInvocationKey {
            taskrun_id,
            attempt_id: assignment.attempt_id,
            cycle_id: *cycle_id,
            proposal_index: outcome.proposal_index,
        };
        if !matches!(
            crate::store::taskrun_tool_invocation::permission_is_current_on_connection(
                tx,
                &store.runtime_authority_id.0,
                key,
                semantic,
                &assignment,
                now_micros / 1_000,
            ),
            Ok(true)
        ) {
            return Err(step_outcome_integrity_failure());
        }
    }
    Ok(())
}

fn step_outcome_digest(bytes: Vec<u8>) -> Result<runne_domain::id::IntegrityDigest, CommitError> {
    let bytes = bytes
        .try_into()
        .map_err(|_| step_outcome_integrity_failure())?;
    Ok(runne_domain::id::IntegrityDigest::from_bytes(bytes))
}

fn step_outcome_integrity_failure() -> CommitError {
    storage_failure(StorageFailureKind::IntegrityViolation)
}
