fn active_assignment(
    tx: &Transaction<'_>,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    state: runne_domain::task_run::TaskRunState,
) -> Result<TaskRunAssignmentIdentity, CommitError> {
    let row: Option<(Vec<u8>, i64, i64, String)> = tx
        .query_row(
            "SELECT o.node_id,o.node_epoch,o.fence,o.dispatch_intent
         FROM taskrun_assignment_occupations o JOIN taskrun_assignments a
           ON a.taskrun_id=o.taskrun_id AND a.fence=o.fence
         WHERE o.taskrun_id=?1 AND o.attempt_id=?2 AND a.attempt_id=o.attempt_id
           AND a.node_id=o.node_id AND a.node_epoch=o.node_epoch
           AND o.state='active' AND o.dispatch_intent='present' AND o.release_event_id IS NULL",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let Some((node, epoch, fence, dispatch_intent)) = row else {
        return Err(fail(StorageFailureKind::PolicyDenied));
    };
    if dispatch_intent != "present"
        || !matches!(
            state,
            runne_domain::task_run::TaskRunState::Running
                | runne_domain::task_run::TaskRunState::Cancelling
        )
    {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    // This is historical assignment evidence; current writer authority and the
    // same-transaction remote Unknown proof authorize an explicit successor.
    assignment_identity(taskrun_id, attempt_id, node, epoch, fence)
}

fn assignment_identity(
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    node: Vec<u8>,
    epoch: i64,
    fence: i64,
) -> Result<TaskRunAssignmentIdentity, CommitError> {
    let node: [u8; 16] = node
        .try_into()
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    Ok(TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id,
        node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node).to_string()),
        node_epoch: u64::try_from(epoch).map_err(|_| fail(StorageFailureKind::CorruptData))?,
        fence: TaskRunFence(
            u64::try_from(fence).map_err(|_| fail(StorageFailureKind::CorruptData))?,
        ),
    })
}
