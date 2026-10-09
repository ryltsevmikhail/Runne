pub(super) fn record_result(
    store: &StoreTransaction,
    receipt: TrustedToolReceiptV1,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    record_result_inner(store, receipt, false)
}

pub(super) fn record_audit_payload(
    store: &StoreTransaction,
    receipt: TrustedToolReceiptV1,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    record_result_inner(store, receipt, true)
}

fn record_result_inner(
    store: &StoreTransaction,
    receipt: TrustedToolReceiptV1,
    force_audit_only: bool,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    same_assignment(receipt.key, &receipt.assignment)?;
    let payload = &receipt.receipt_payload;
    if payload.payload.plaintext_len() == 0
        || payload.payload.plaintext_len() as usize > MAX_HELPER_RECEIPT_BYTES
        || payload.payload.ciphertext().len() > MAX_HELPER_RECEIPT_BYTES + 16
        || (!force_audit_only && receipt.actual_length > MAX_TOOL_RESULT_BYTES as u64)
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
    let old = read::get_from_connection(&tx, receipt.key)?
        .ok_or(ToolInvocationStoreError::InvalidState)?;
    if old.semantic_digest != receipt.semantic_digest {
        return Err(ToolInvocationStoreError::Conflict);
    }
    if matches!(
        old.state,
        ToolInvocationState::Result | ToolInvocationState::AuditOnly
    ) {
        let same_result = old.result.as_ref().is_some_and(|result| {
            result.receipt_payload == receipt.receipt_payload
                && result.digest == receipt.result_digest
                && result.actual_length == receipt.actual_length.min(i64::MAX as u64)
                && result.truncated == receipt.truncated
        });
        if same_result {
            tx.commit()
                .map_err(|_| ToolInvocationStoreError::Unavailable)?;
            return Ok(old);
        }
        return Err(ToolInvocationStoreError::Conflict);
    }
    if !matches!(
        old.state,
        ToolInvocationState::Claimed | ToolInvocationState::Uncertain
    ) && !(force_audit_only && old.state == ToolInvocationState::Cancelled)
    {
        return Err(ToolInvocationStoreError::InvalidState);
    }
    let binding = load_binding_for_validation(&tx, receipt.key)?;
    type ClaimRow = (i64, String, i64, i64, Option<Vec<u8>>, i64, Option<Vec<u8>>);
    let claim: Option<ClaimRow> = tx
        .query_row(
            "SELECT claim_fence,claim_node_id,claim_node_epoch,release_started,managed_area_identity,local_stop_state,empty_proof_identity FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",
            params![receipt.key.taskrun_id.as_bytes(),receipt.key.attempt_id.as_bytes(),receipt.key.cycle_id.as_bytes(),i64::from(receipt.key.proposal_index)],
            |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
        ).optional().map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let Some((fence, node, epoch, release_started, area, stop_state, proof)) = claim else {
        return Err(ToolInvocationStoreError::CorruptData);
    };
    let area_proved_empty = area
        .as_ref()
        .is_some_and(|identity| stop_state == 2 && proof.as_ref() == Some(identity));
    let audit_before_release = force_audit_only && release_started == 0 && area_proved_empty;
    if (release_started != 1 && !audit_before_release)
        || fence != receipt.assignment.fence.0 as i64
        || node != receipt.assignment.node_id.0
        || epoch != receipt.assignment.node_epoch as i64
        || (force_audit_only
            && !area.as_ref().is_some_and(|identity| {
                (stop_state == 1 && proof.is_none())
                    || area_proved_empty && proof.as_ref() == Some(identity)
            }))
        || (!force_audit_only && (stop_state != 2 || area.is_none() || area != proof))
    {
        return Err(ToolInvocationStoreError::InvalidState);
    }
    let current = super::super::taskrun_claim::stream_validate::verify_stream(
        &tx,
        receipt.key.taskrun_id,
        None,
    )
    .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let task = runne_domain::task_run::TaskRun::replay(&current.events)
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    let state = if force_audit_only
        || receipt.truncated
        || !matches!(
            permission_is_current_on_connection(
                &tx,
                &store.runtime_authority_id.0,
                receipt.key,
                receipt.semantic_digest,
                &receipt.assignment,
                now,
            ),
            Ok(true)
        )
        || task.state().is_terminal()
        || task.state() == runne_domain::task_run::TaskRunState::Cancelling
        || current.version != binding.expected_taskrun_version
        || task.active_attempt() != Some(&receipt.key.attempt_id)
        || !task.active_cycle().is_some_and(|cycle| {
            cycle.cycle_id == receipt.key.cycle_id
                && cycle.state == runne_domain::agent_loop::LoopCycleState::Acting
                && cycle
                    .expected_proposal_indexes
                    .contains(&receipt.key.proposal_index)
        }) {
        "audit_only"
    } else {
        "result"
    };
    persist_payload_nonce(&tx, payload, binding.sources[0].dispatch_attempt_id)?;
    tx.execute(
        "UPDATE taskrun_tool_invocations SET state=?1,helper_receipt_digest=?2,helper_receipt_bytes=?3,receipt_key_id=?4,receipt_key_version=?5,receipt_runtime_authority_id=?6,receipt_database_generation=?7,receipt_nonce=?8,receipt_plaintext_len=?9,result_bytes=NULL,result_digest=?10,result_length=?11,result_truncated=?12,updated_at=?13 WHERE taskrun_id=?14 AND attempt_id=?15 AND cycle_id=?16 AND proposal_index=?17",
        params![state,payload.payload.plaintext_digest().as_slice(),payload.payload.ciphertext(),payload.key.key_id().as_slice(),payload.key.key_version() as i64,payload.key.runtime_authority_id().as_slice(),payload.key.database_generation() as i64,payload.payload.nonce().as_slice(),payload.payload.plaintext_len() as i64,receipt.result_digest.as_bytes(),if force_audit_only { receipt.actual_length.min(i64::MAX as u64) as i64 } else { i64::try_from(receipt.actual_length).map_err(|_|ToolInvocationStoreError::CorruptData)? },i64::from(receipt.truncated),now,receipt.key.taskrun_id.as_bytes(),receipt.key.attempt_id.as_bytes(),receipt.key.cycle_id.as_bytes(),i64::from(receipt.key.proposal_index)],
    ).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let result = read::get_from_connection(&tx, receipt.key)?
        .ok_or(ToolInvocationStoreError::CorruptData)?;
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(result)
}

#[cfg(target_os = "linux")]
pub(super) fn with_release(
    store: &StoreTransaction,
    key: ToolInvocationKey,
    digest: IntegrityDigest,
    assignment: &TaskRunAssignmentIdentity,
    _caller_now: i64,
    child: &mut runne_platform::local_command_linux::PermissionHelperChildV1<'_>,
) -> Result<(), ToolInvocationStoreError> {
    let current_policy = acquire_store_owned_current_policy(store, key)?;
    same_assignment(key, assignment)?;
    let mut writer = store
        .inner
        .writer
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let intent = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let intent_now = validate::fresh_now_millis();
    let old =
        read::get_from_connection(&intent, key)?.ok_or(ToolInvocationStoreError::InvalidState)?;
    if old.semantic_digest != digest {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let binding = load_binding_for_validation(&intent, key)?;
    validate_task(
        &intent,
        &store.runtime_authority_id,
        assignment,
        binding.expected_taskrun_version,
        key.cycle_id,
        key.proposal_index,
        &binding.principal_id,
        intent_now,
    )?;
    validate::verify_assignment_lease(&intent, assignment, intent_now)?;
    if old.state != ToolInvocationState::Claimed {
        return Err(ToolInvocationStoreError::InvalidState);
    }
    let permission_source =
        validate_release_permission(&intent, &store.runtime_authority_id.0, &binding, intent_now)?;
    validate_current_workspace_project(&intent, &current_policy)?;
    validate_current_managed_effect_policy(
        &intent,
        key,
        &binding,
        &current_policy.snapshot,
        current_policy.digest,
    )?;
    validate_helper_child(
        child,
        &binding,
        &current_policy.admission,
        assignment,
        current_policy.workspace_id,
    )?;
    if permission_source == ToolPermissionDecisionSource::Human {
        approval_matches(&intent, &binding, intent_now)?;
    }
    verify_sources(&intent, key, &binding.sources)?;
    let area: Option<(Vec<u8>, i64, Option<Vec<u8>>)> = intent.query_row("SELECT managed_area_identity,local_stop_state,empty_proof_identity FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",params![key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|_|ToolInvocationStoreError::CorruptData)?;
    if area.is_none_or(|(_, state, proof)| state != 1 || proof.is_some()) {
        return Err(ToolInvocationStoreError::InvalidState);
    }
    let changed=intent.execute("UPDATE taskrun_tool_invocations SET release_started=1,updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5 AND release_started=0 AND state='claimed'",params![intent_now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    if changed != 1 {
        return Err(ToolInvocationStoreError::Uncertain);
    }
    intent
        .commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let release_tx = writer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let release_now = validate::fresh_now_millis();
    match validate_task(
        &release_tx,
        &store.runtime_authority_id,
        assignment,
        binding.expected_taskrun_version,
        key.cycle_id,
        key.proposal_index,
        &binding.principal_id,
        release_now,
    ) {
        Ok(_) => validate::verify_assignment_lease(&release_tx, assignment, release_now)?,
        Err(ToolInvocationStoreError::Cancelled) => {
            release_tx.execute("UPDATE taskrun_tool_invocations SET state='cancelled',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5 AND state='claimed'",params![release_now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
            release_tx
                .commit()
                .map_err(|_| ToolInvocationStoreError::Unavailable)?;
            return Err(ToolInvocationStoreError::Cancelled);
        }
        Err(error) => return Err(error),
    }
    let permission_source = validate_release_permission(
        &release_tx,
        &store.runtime_authority_id.0,
        &binding,
        release_now,
    )?;
    validate_current_workspace_project(&release_tx, &current_policy)?;
    validate_current_managed_effect_policy(
        &release_tx,
        key,
        &binding,
        &current_policy.snapshot,
        current_policy.digest,
    )?;
    validate_helper_child(
        child,
        &binding,
        &current_policy.admission,
        assignment,
        current_policy.workspace_id,
    )?;
    if permission_source == ToolPermissionDecisionSource::Human {
        approval_matches(&release_tx, &binding, release_now)?;
    }
    verify_sources(&release_tx, key, &binding.sources)?;
    let owner = store
        .inner
        .permission_owner
        .as_ref()
        .ok_or(ToolInvocationStoreError::Unavailable)?;
    let root_request = super::super::taskrun_local_command::PermissionRootFenceRequestV1::new(
        current_policy.workspace_id,
        current_policy.workspace_version,
        binding.root_revision,
        *binding.root_identity.as_bytes(),
    );
    let released = owner.release_helper_child(&store.runtime_authority_id, &root_request, child);
    if released.is_err() {
        release_tx.execute("UPDATE taskrun_tool_invocations SET state='uncertain',updated_at=?1 WHERE taskrun_id=?2 AND attempt_id=?3 AND cycle_id=?4 AND proposal_index=?5 AND state='claimed'",params![release_now,key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    }
    release_tx
        .commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    if released.is_err() {
        return Err(ToolInvocationStoreError::Uncertain);
    }
    Ok(())
}
