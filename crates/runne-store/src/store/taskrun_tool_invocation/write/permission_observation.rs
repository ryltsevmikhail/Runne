pub(super) fn observe_permission(
    store: &StoreTransaction,
    key: ToolInvocationKey,
    semantic_digest: IntegrityDigest,
    assignment: &TaskRunAssignmentIdentity,
) -> Result<bool, ToolInvocationStoreError> {
    let reader = store
        .inner
        .reader
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    permission_is_current_on_connection(
        &reader,
        &store.runtime_authority_id.0,
        key,
        semantic_digest,
        assignment,
        validate::fresh_now_millis(),
    )
}

pub(crate) fn permission_is_current_on_connection(
    connection: &rusqlite::Connection,
    runtime_authority: &str,
    key: ToolInvocationKey,
    semantic_digest: IntegrityDigest,
    assignment: &TaskRunAssignmentIdentity,
    now: i64,
) -> Result<bool, ToolInvocationStoreError> {
    if key.taskrun_id != assignment.taskrun_id || key.attempt_id != assignment.attempt_id {
        return Ok(false);
    }
    let binding = load_binding_for_validation(connection, key)?;
    if binding.semantic_digest != semantic_digest {
        return Ok(false);
    }
    let claim: Option<(Option<i64>, Option<String>, Option<i64>)> = connection
        .query_row(
            "SELECT claim_fence,claim_node_id,claim_node_epoch FROM taskrun_tool_invocations
             WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",
            params![
                key.taskrun_id.as_bytes(),
                key.attempt_id.as_bytes(),
                key.cycle_id.as_bytes(),
                i64::from(key.proposal_index)
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let Some((Some(fence), Some(node), Some(epoch))) = claim else {
        return Ok(false);
    };
    if i64::try_from(assignment.fence.0).ok() != Some(fence)
        || i64::try_from(assignment.node_epoch).ok() != Some(epoch)
        || assignment.node_id.0 != node
    {
        return Ok(false);
    }
    validate_release_permission(connection, runtime_authority, &binding, now)?;
    Ok(true)
}
