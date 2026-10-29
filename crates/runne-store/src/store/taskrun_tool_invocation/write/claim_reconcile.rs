pub(super) fn claim(
    s: &StoreTransaction,
    key: ToolInvocationKey,
    digest: IntegrityDigest,
    a: &TaskRunAssignmentIdentity,
    version: u64,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    same_assignment(key, a)?;
    let mut w = s
        .inner
        .writer
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let tx = w
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let now = validate::fresh_now_millis();
    let mut r =
        read::get_from_connection(&tx, key)?.ok_or(ToolInvocationStoreError::InvalidState)?;
    if r.semantic_digest != digest {
        return Err(ToolInvocationStoreError::Conflict);
    }
    match r.state {
        ToolInvocationState::Result
        | ToolInvocationState::AuditOnly
        | ToolInvocationState::Cancelled
        | ToolInvocationState::Uncertain => {
            tx.commit()
                .map_err(|_| ToolInvocationStoreError::Unavailable)?;
            return Ok(r);
        }
        ToolInvocationState::Claimed => {
            let binding = load_binding_for_validation(&tx, key)?;
            if version != binding.expected_taskrun_version {
                return Err(ToolInvocationStoreError::StaleVersion);
            }
            let claim: (Option<i64>, Option<String>, Option<i64>, i64) = tx
                .query_row(
                    "SELECT claim_fence,claim_node_id,claim_node_epoch,release_started
                     FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2
                       AND cycle_id=?3 AND proposal_index=?4",
                    params![
                        key.taskrun_id.as_bytes(),
                        key.attempt_id.as_bytes(),
                        key.cycle_id.as_bytes(),
                        i64::from(key.proposal_index)
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .map_err(|_| ToolInvocationStoreError::CorruptData)?;
            if claim.0 != Some(a.fence.0 as i64)
                || claim.1.as_deref() != Some(a.node_id.0.as_str())
                || claim.2 != Some(a.node_epoch as i64)
            {
                return Err(ToolInvocationStoreError::StaleVersion);
            }
            validate::verify_assignment_lease(&tx, a, now)?;
            match validate_task(
                &tx,
                &s.runtime_authority_id,
                a,
                version,
                key.cycle_id,
                key.proposal_index,
                &binding.principal_id,
                now,
            ) {
                Ok(_) => {}
                Err(ToolInvocationStoreError::Cancelled) => {
                    tx.execute("UPDATE taskrun_tool_invocations SET state='cancelled',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5 AND state='claimed'",params![now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
                    r.state = ToolInvocationState::Cancelled;
                    tx.commit()
                        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
                    return Ok(r);
                }
                Err(error) => return Err(error),
            }
            let permission_source =
                validate_release_permission(&tx, &s.runtime_authority_id.0, &binding, now)?;
            if permission_source == ToolPermissionDecisionSource::Human {
                approval_matches(&tx, &binding, now)?;
            }
            verify_sources(&tx, key, &binding.sources)?;
            if claim.3 != 0 {
                tx.execute("UPDATE taskrun_tool_invocations SET state='uncertain',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5 AND state='claimed'",params![now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
                r.state = ToolInvocationState::Uncertain;
            }
            tx.commit()
                .map_err(|_| ToolInvocationStoreError::Unavailable)?;
            return Ok(r);
        }
        ToolInvocationState::Approved => {}
        _ => return Err(ToolInvocationStoreError::InvalidState),
    }
    let binding = load_binding_for_validation(&tx, key)?;
    if version != load_binding_for_validation(&tx, key)?.expected_taskrun_version {
        return Err(ToolInvocationStoreError::StaleVersion);
    }
    validate::verify_assignment_lease(&tx, a, now)?;
    match validate_task(
        &tx,
        &s.runtime_authority_id,
        a,
        version,
        key.cycle_id,
        key.proposal_index,
        &binding.principal_id,
        now,
    ) {
        Ok(_) => {}
        Err(ToolInvocationStoreError::Cancelled) => {
            tx.execute("UPDATE taskrun_tool_invocations SET state='cancelled',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5",params![now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
            r.state = ToolInvocationState::Cancelled;
            tx.commit()
                .map_err(|_| ToolInvocationStoreError::Unavailable)?;
            return Ok(r);
        }
        Err(e) => return Err(e),
    }
    let permission_source =
        validate_release_permission(&tx, &s.runtime_authority_id.0, &binding, now)?;
    if permission_source == ToolPermissionDecisionSource::Human {
        approval_matches(&tx, &binding, now)?;
    }
    verify_sources(&tx, key, &binding.sources)?;
    ensure_no_unresolved(&tx, key.taskrun_id)?;
    let budget = load_budget(&tx, key.taskrun_id)?;
    if budget.effects_used >= budget_policy::limits(&tx, key.taskrun_id)?.0 {
        return Err(ToolInvocationStoreError::BudgetExhausted);
    }
    tx.execute("UPDATE taskrun_tool_budgets SET effects_used=effects_used+1,updated_at=?1 WHERE taskrun_id=?2",params![now,key.taskrun_id.as_bytes()]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    tx.execute("UPDATE taskrun_tool_invocations SET state='claimed',claim_fence=?1,claim_node_id=?2,claim_node_epoch=?3,updated_at=?4 WHERE taskrun_id=?5 AND attempt_id=?6 AND cycle_id=?7 AND proposal_index=?8 AND state='approved'",params![a.fence.0 as i64,a.node_id.0,a.node_epoch as i64,now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    r.state = ToolInvocationState::Claimed;
    r.budget.effects_used += 1;
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(r)
}

pub(super) fn mark_uncertain(
    s: &StoreTransaction,
    key: ToolInvocationKey,
    digest: IntegrityDigest,
    a: &TaskRunAssignmentIdentity,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    same_assignment(key, a)?;
    let mut w = s
        .inner
        .writer
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let tx = w
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let now = validate::fresh_now_millis();
    let old = read::get_from_connection(&tx, key)?.ok_or(ToolInvocationStoreError::InvalidState)?;
    if old.semantic_digest != digest {
        return Err(ToolInvocationStoreError::Conflict);
    }
    if matches!(
        old.state,
        ToolInvocationState::Result
            | ToolInvocationState::AuditOnly
            | ToolInvocationState::Uncertain
    ) {
        tx.commit()
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        return Ok(old);
    }
    if old.state != ToolInvocationState::Claimed {
        return Err(ToolInvocationStoreError::InvalidState);
    }
    let claimed = old.key;
    let (claim_fence,claim_node,claim_epoch):(Option<i64>,Option<String>,Option<i64>)=tx.query_row("SELECT claim_fence,claim_node_id,claim_node_epoch FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",params![claimed.taskrun_id.as_bytes(),claimed.attempt_id.as_bytes(),claimed.cycle_id.as_bytes(),i64::from(claimed.proposal_index)],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let superseded = claim_fence != Some(a.fence.0 as i64)
        || claim_node.as_deref() != Some(a.node_id.0.as_str())
        || claim_epoch != Some(a.node_epoch as i64);
    if !superseded {
        if !validate::assignment_lease_expired(&tx, a, now)? {
            return Err(ToolInvocationStoreError::InvalidState);
        }
    } else {
        super::super::taskrun_claim::verify_active_assignment(&tx, a)
            .map_err(|_| ToolInvocationStoreError::StaleVersion)?;
    }
    tx.execute("UPDATE taskrun_tool_invocations SET state='uncertain',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5",params![now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let mut result = old;
    result.state = ToolInvocationState::Uncertain;
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(result)
}
