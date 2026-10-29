type ExistingBudgetRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    String,
    i64,
    i64,
    String,
    i64,
);

pub(super) fn ensure_budget(
    store: &StoreTransaction,
    taskrun_id: runne_domain::id::TaskRunId,
    expected_version: u64,
    assignment: &TaskRunAssignmentIdentity,
    _now: i64,
    coding: bool,
) -> Result<runne_domain::reference::BudgetReservationRef, ToolInvocationStoreError> {
    if assignment.taskrun_id != taskrun_id || expected_version == 0 {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let mut writer = store
        .inner
        .writer
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let tx = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let now = validate::fresh_now_millis();
    validate::verify_assignment_lease(&tx, assignment, now)?;
    let stream = super::super::taskrun_claim::stream_validate::verify_stream(
        &tx,
        taskrun_id,
        Some(expected_version),
    )
    .map_err(|_| ToolInvocationStoreError::StaleVersion)?;
    let task = runne_domain::task_run::TaskRun::replay(&stream.events)
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if task.state().is_terminal()
        || task.state() == runne_domain::task_run::TaskRunState::Cancelling
        || task.active_attempt() != Some(&assignment.attempt_id)
    {
        return Err(ToolInvocationStoreError::StaleVersion);
    }
    super::super::taskrun_claim::verify_active_assignment(&tx, assignment)
        .map_err(|_| ToolInvocationStoreError::StaleVersion)?;
    super::super::taskrun_submit_origin::verify_submitted_v2_origin(
        &tx,
        taskrun_id,
        &store.runtime_authority_id,
    )
    .map_err(|_| ToolInvocationStoreError::CorruptData)?
    .ok_or(ToolInvocationStoreError::CorruptData)?;
    if budget_policy::coding_origin(&tx, taskrun_id)? != coding {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let (policy_revision, limit) = if coding {
        (budget_policy::CODING_POLICY, budget_policy::CODING_LIMIT)
    } else {
        (budget_policy::LEGACY_POLICY, MAX_TOOL_EFFECTS)
    };
    let reservation_digest = budget_digest(taskrun_id, assignment, policy_revision, limit);
    let mut id_bytes: [u8; 16] = reservation_digest.as_bytes()[..16]
        .try_into()
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    id_bytes[6] = (id_bytes[6] & 0x0f) | 0x70;
    id_bytes[8] = (id_bytes[8] & 0x3f) | 0x80;
    if id_bytes == [0; 16] {
        return Err(ToolInvocationStoreError::CorruptData);
    }
    let reservation_id = runne_domain::id::BudgetReservationId::from_bytes(id_bytes);
    let existing: Option<ExistingBudgetRow> = tx.query_row(
        "SELECT reservation_id,reservation_digest,attempt_id,fence,policy_revision,effects_limit,continuations_limit,node_id,node_epoch FROM taskrun_tool_budgets WHERE taskrun_id=?1",
        [taskrun_id.as_bytes()],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)),
    ).optional().map_err(|_|ToolInvocationStoreError::CorruptData)?;
    if let Some((id, digest, attempt, fence, policy, effects, continuations, node_id, node_epoch)) =
        existing
    {
        if id.as_slice() != reservation_id.as_bytes()
            || digest.as_slice() != reservation_digest.as_bytes()
            || attempt.as_slice() != assignment.attempt_id.as_bytes()
            || fence != assignment.fence.0 as i64
            || policy != policy_revision
            || effects != i64::from(limit)
            || continuations != i64::from(limit)
            || node_id != assignment.node_id.0
            || node_epoch != assignment.node_epoch as i64
        {
            return Err(ToolInvocationStoreError::Conflict);
        }
    } else {
        tx.execute("INSERT INTO taskrun_tool_budgets(taskrun_id,attempt_id,fence,node_id,node_epoch,reservation_id,reservation_digest,policy_revision,effects_limit,continuations_limit,effects_used,continuations_used,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9,0,0,?10)",
            params![taskrun_id.as_bytes(),assignment.attempt_id.as_bytes(),assignment.fence.0 as i64,assignment.node_id.0,assignment.node_epoch as i64,reservation_id.as_bytes(),reservation_digest.as_bytes(),policy_revision,limit,now]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    }
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(runne_domain::reference::BudgetReservationRef {
        reservation_id,
        taskrun_id,
        attempt_id: assignment.attempt_id,
        retry_ordinal: 0,
        reservation_digest,
    })
}

fn budget_digest(
    taskrun_id: runne_domain::id::TaskRunId,
    assignment: &TaskRunAssignmentIdentity,
    policy_revision: &str,
    limit: u32,
) -> IntegrityDigest {
    let mut h = sha2::Sha256::new();
    h.update(b"runne-d2-taskrun-tool-budget-v1\0");
    h.update(taskrun_id.as_bytes());
    h.update(assignment.attempt_id.as_bytes());
    h.update(assignment.fence.0.to_be_bytes());
    h.update(assignment.node_id.0.as_bytes());
    h.update(assignment.node_epoch.to_be_bytes());
    h.update(policy_revision.as_bytes());
    h.update(limit.to_be_bytes());
    h.update(limit.to_be_bytes());
    IntegrityDigest::from_bytes(h.finalize().into())
}
