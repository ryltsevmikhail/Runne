// These values are checked together against one immediate transaction snapshot.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_task(
    tx: &Transaction<'_>,
    authority: &RuntimeAuthorityId,
    assignment: &TaskRunAssignmentIdentity,
    expected_version: u64,
    cycle_id: runne_domain::id::CycleId,
    proposal_index: u32,
    submit_principal: &str,
    now: i64,
) -> Result<TaskRun, ToolInvocationStoreError> {
    let stream = super::super::taskrun_claim::stream_validate::verify_stream(
        tx,
        assignment.taskrun_id,
        None,
    )
    .map_err(|_| ToolInvocationStoreError::StaleVersion)?;
    let task =
        TaskRun::replay(&stream.events).map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if matches!(
        task.state(),
        runne_domain::task_run::TaskRunState::Cancelling
            | runne_domain::task_run::TaskRunState::Cancelled
    ) {
        return Err(ToolInvocationStoreError::Cancelled);
    }
    if stream.version != expected_version || task.state().is_terminal() {
        return Err(ToolInvocationStoreError::StaleVersion);
    }
    if super::super::taskrun_claim::verify_active_assignment(tx, assignment).is_err() {
        return Err(ToolInvocationStoreError::StaleVersion);
    }
    verify_assignment_lease(tx, assignment, now)?;
    if task.active_attempt() != Some(&assignment.attempt_id) {
        return Err(ToolInvocationStoreError::StaleVersion);
    }
    let active = task
        .active_cycle()
        .ok_or(ToolInvocationStoreError::InvalidState)?;
    if active.cycle_id != cycle_id
        || active.attempt_id != assignment.attempt_id
        || active.state != LoopCycleState::Acting
        || !active.expected_proposal_indexes.contains(&proposal_index)
    {
        return Err(ToolInvocationStoreError::StaleVersion);
    }
    let origin = super::super::taskrun_submit_origin::verify_submitted_v2_origin(
        tx,
        assignment.taskrun_id,
        authority,
    )
    .map_err(|_| ToolInvocationStoreError::CorruptData)?
    .ok_or(ToolInvocationStoreError::CorruptData)?;
    if origin.principal_id.0 != submit_principal {
        return Err(ToolInvocationStoreError::Conflict);
    }
    if now <= 0 {
        return Err(ToolInvocationStoreError::CorruptData);
    }
    Ok(task)
}

pub(super) fn verify_sources(
    tx: &Transaction<'_>,
    key: ToolInvocationKey,
    sources: &[ToolSourceRef],
) -> Result<(), ToolInvocationStoreError> {
    let dispatch = sources
        .first()
        .map(|s| s.dispatch_attempt_id)
        .ok_or(ToolInvocationStoreError::CorruptData)?;
    if !sources.iter().any(|s| s.event_kind == 4)
        || !sources.iter().any(|s| s.event_kind == 5 && s.terminal)
        || sources.iter().any(|s| s.dispatch_attempt_id != dispatch)
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    for s in sources {
        let valid: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_stream_journal j JOIN provider_execution_admissions a USING(dispatch_attempt_id) WHERE j.dispatch_attempt_id=?1 AND j.sequence=?2 AND j.event_kind=?3 AND j.terminal=?4 AND j.plaintext_digest=?5 AND j.profile_digest=?6 AND j.runtime_generation=?7 AND a.taskrun_id=?8 AND a.execution_attempt_id=?9)",
            params![s.dispatch_attempt_id, s.sequence as i64, i64::from(s.event_kind), i64::from(s.terminal), s.plaintext_digest.as_bytes(), s.profile_digest.as_bytes(), s.runtime_generation as i64, key.taskrun_id.as_bytes(), key.attempt_id.as_bytes()],|r|r.get(0)).map_err(|_|ToolInvocationStoreError::CorruptData)?;
        if !valid {
            return Err(ToolInvocationStoreError::Conflict);
        }
    }
    let completed: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_terminal_dispositions WHERE dispatch_attempt_id=?1 AND disposition=1)",[dispatch],|r|r.get(0)).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let scanner_completed: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM provider_stream_journal WHERE dispatch_attempt_id=?1 AND event_kind=5 AND terminal=1)",[dispatch],|r|r.get(0)).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    if !completed || !scanner_completed {
        return Err(ToolInvocationStoreError::Conflict);
    }
    Ok(())
}

pub(super) fn approval_matches(
    tx: &Transaction<'_>,
    binding: &ToolInvocationBindingV1,
    now: i64,
) -> Result<(), ToolInvocationStoreError> {
    let id = runne_domain::id::ApprovalId::from_bytes(binding.approval_id);
    type ApprovalRow = (String,Option<String>,String,String,Vec<u8>,i64,i64,Option<String>,i64,Option<String>,Option<i64>);
    let row: Option<ApprovalRow>=tx.query_row(
        "SELECT task_run_id,attempt_id,action,resource,action_digest,policy_revision,state,decision_principal_id,expires_at,principal_id,decision FROM approvals WHERE approval_id=?1",
        [id.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?))).optional().map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let Some((
        task,
        attempt,
        action,
        resource,
        digest,
        policy,
        state,
        decision,
        expiry,
        principal,
        decision_value,
    )) = row
    else {
        return Err(ToolInvocationStoreError::ApprovalDenied);
    };
    let attempt_text = binding.key.attempt_id.to_string();
    if task != binding.key.taskrun_id.to_string()
        || attempt.as_deref() != Some(attempt_text.as_str())
        || action != binding.approval_action
        || resource != binding.approval_resource
        || digest != binding.approval_digest.as_bytes()
        || policy != binding.policy_revision as i64
        || expiry != binding.approval_expires_at
        || principal.as_deref() != Some(binding.principal_id.as_str())
        || decision.as_deref() != Some(binding.approval_principal_id.as_str())
    {
        return Err(ToolInvocationStoreError::ApprovalDenied);
    }
    if state != 2 || decision_value != Some(1) {
        return Err(ToolInvocationStoreError::ApprovalDenied);
    }
    if binding.approval_expires_at <= now {
        return Err(ToolInvocationStoreError::ApprovalExpired);
    }
    Ok(())
}

pub(super) fn same_assignment(
    key: ToolInvocationKey,
    a: &TaskRunAssignmentIdentity,
) -> Result<(), ToolInvocationStoreError> {
    if key.taskrun_id != a.taskrun_id || key.attempt_id != a.attempt_id {
        Err(ToolInvocationStoreError::Conflict)
    } else {
        Ok(())
    }
}

pub(super) fn fresh_now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub(super) fn verify_assignment_lease(
    tx: &Transaction<'_>,
    assignment: &TaskRunAssignmentIdentity,
    now: i64,
) -> Result<(), ToolInvocationStoreError> {
    let node = *uuid::Uuid::parse_str(&assignment.node_id.0)
        .map_err(|_| ToolInvocationStoreError::CorruptData)?
        .as_bytes();
    let live: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_assignments WHERE taskrun_id=?1 AND attempt_id=?2 AND node_id=?3 AND node_epoch=?4 AND fence=?5 AND lease_expires_at_ms>?6)",
        params![assignment.taskrun_id.as_bytes(),assignment.attempt_id.as_bytes(),node,assignment.node_epoch as i64,assignment.fence.0 as i64,now],
        |row| row.get(0),
    ).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    if live {
        Ok(())
    } else {
        Err(ToolInvocationStoreError::StaleVersion)
    }
}

pub(super) fn assignment_lease_expired(
    tx: &Transaction<'_>,
    assignment: &TaskRunAssignmentIdentity,
    now: i64,
) -> Result<bool, ToolInvocationStoreError> {
    let node = *uuid::Uuid::parse_str(&assignment.node_id.0)
        .map_err(|_| ToolInvocationStoreError::CorruptData)?
        .as_bytes();
    let expired: Option<bool> = tx.query_row(
        "SELECT lease_expires_at_ms<=?6 FROM taskrun_assignments WHERE taskrun_id=?1 AND attempt_id=?2 AND node_id=?3 AND node_epoch=?4 AND fence=?5",
        params![assignment.taskrun_id.as_bytes(),assignment.attempt_id.as_bytes(),node,assignment.node_epoch as i64,assignment.fence.0 as i64,now],
        |row| row.get(0),
    ).optional().map_err(|_|ToolInvocationStoreError::CorruptData)?;
    expired.ok_or(ToolInvocationStoreError::StaleVersion)
}
