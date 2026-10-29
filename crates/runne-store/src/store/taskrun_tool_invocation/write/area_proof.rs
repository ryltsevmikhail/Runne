#[cfg(target_os = "linux")]
type AreaLaunchRow = (Option<Vec<u8>>, i64, i64, Option<String>, Option<i64>);
#[cfg(target_os = "linux")]
type AreaStopRow = (Vec<u8>, i64, i64, Option<String>, Option<i64>);

#[cfg(target_os = "linux")]
pub(super) fn record_area_launch(
    store: &StoreTransaction,
    key: ToolInvocationKey,
    digest: IntegrityDigest,
    assignment: &TaskRunAssignmentIdentity,
    identity: &runne_platform::process_managed_area::ManagedAreaIdentity,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    same_assignment(key, assignment)?;
    let bytes = identity.to_bytes();
    if bytes[52..68] != *key.taskrun_id.as_bytes()
        || bytes[68..84] != *key.attempt_id.as_bytes()
        || bytes[84..100] != key.managed_area_nonce(digest)
    {
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
    let old = read::get_from_connection(&tx, key)?.ok_or(ToolInvocationStoreError::InvalidState)?;
    if old.semantic_digest != digest || old.state != ToolInvocationState::Claimed {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let binding = load_binding_for_validation(&tx, key)?;
    validate_task(
        &tx,
        &store.runtime_authority_id,
        assignment,
        binding.expected_taskrun_version,
        key.cycle_id,
        key.proposal_index,
        &binding.principal_id,
        now,
    )?;
    validate::verify_assignment_lease(&tx, assignment, now)?;
    let permission_source =
        validate_release_permission(&tx, &store.runtime_authority_id.0, &binding, now)?;
    if permission_source == ToolPermissionDecisionSource::Human {
        approval_matches(&tx, &binding, now)?;
    }
    verify_sources(&tx, key, &binding.sources)?;
    let stored: Option<AreaLaunchRow> = tx.query_row(
        "SELECT managed_area_identity,local_stop_state,claim_fence,claim_node_id,claim_node_epoch FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",
        params![key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional().map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let (area, stop_state, fence, node, epoch) =
        stored.ok_or(ToolInvocationStoreError::CorruptData)?;
    if fence != assignment.fence.0 as i64
        || node.as_deref() != Some(assignment.node_id.0.as_str())
        || epoch != Some(assignment.node_epoch as i64)
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    if let Some(existing) = area {
        if existing.as_slice() != bytes || stop_state < 1 {
            return Err(ToolInvocationStoreError::Conflict);
        }
    } else {
        tx.execute("UPDATE taskrun_tool_invocations SET managed_area_identity=?1,local_stop_state=1,updated_at=?2 WHERE taskrun_id=?3 AND attempt_id=?4 AND cycle_id=?5 AND proposal_index=?6 AND managed_area_identity IS NULL AND local_stop_state=0",
            params![bytes.as_slice(),now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    }
    let result =
        read::get_from_connection(&tx, key)?.ok_or(ToolInvocationStoreError::CorruptData)?;
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(result)
}

#[cfg(target_os = "linux")]
pub(super) fn record_area_stopped(
    store: &StoreTransaction,
    key: ToolInvocationKey,
    digest: IntegrityDigest,
    assignment: &TaskRunAssignmentIdentity,
    identity: &runne_platform::process_managed_area::ManagedAreaIdentity,
    proof: &runne_platform::process_managed_area::VerifiedEmptyManagedArea<'_>,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    same_assignment(key, assignment)?;
    let identity_bytes = identity.to_bytes();
    if proof.identity_bytes() != &identity_bytes
        || identity_bytes[52..68] != *key.taskrun_id.as_bytes()
        || identity_bytes[68..84] != *key.attempt_id.as_bytes()
        || identity_bytes[84..100] != key.managed_area_nonce(digest)
        || runne_platform::process_managed_area::ManagedAreaIdentity::from_bytes(&identity_bytes)
            .is_err()
    {
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
    if proof.revalidate().is_err() {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let old = read::get_from_connection(&tx, key)?.ok_or(ToolInvocationStoreError::InvalidState)?;
    if old.semantic_digest != digest {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let prior: Option<AreaStopRow> = tx.query_row(
        "SELECT managed_area_identity,local_stop_state,claim_fence,claim_node_id,claim_node_epoch FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",
        params![key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional().map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let Some((stored, state, fence, node, epoch)) = prior else {
        return Err(ToolInvocationStoreError::CorruptData);
    };
    if stored.as_slice() != identity_bytes
        || state < 1
        || fence != assignment.fence.0 as i64
        || node.as_deref() != Some(assignment.node_id.0.as_str())
        || epoch != Some(assignment.node_epoch as i64)
    {
        return Err(ToolInvocationStoreError::Conflict);
    }
    if state == 1 {
        tx.execute("UPDATE taskrun_tool_invocations SET local_stop_state=2,empty_proof_identity=?1,updated_at=?2 WHERE taskrun_id=?3 AND attempt_id=?4 AND cycle_id=?5 AND proposal_index=?6 AND local_stop_state=1",
            params![identity_bytes.as_slice(),now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    }
    let result =
        read::get_from_connection(&tx, key)?.ok_or(ToolInvocationStoreError::CorruptData)?;
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(result)
}
