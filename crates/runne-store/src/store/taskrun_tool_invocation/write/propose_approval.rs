type PriorEffectRow = (String, Vec<u8>, String, Option<Vec<u8>>, Vec<u8>, i64);
type ApprovalBindingRow = (
    Vec<u8>, String, String, String, String, Vec<u8>, i64, i64,
    Option<String>, Option<String>, Option<String>, Option<String>, Option<Vec<u8>>,
    Option<i64>, Option<i64>, Option<String>, Option<i64>, Option<i64>, Option<String>,
);

pub(super) fn propose(
    s: &StoreTransaction,
    b: ToolInvocationBindingV1,
    arguments_payload: EncryptedToolPayloadV1,
    a: &TaskRunAssignmentIdentity,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    propose_inner(s, b, arguments_payload, a, None)
}

pub(super) fn propose_with_permission(
    s: &StoreTransaction,
    b: ToolInvocationBindingV1,
    arguments_payload: EncryptedToolPayloadV1,
    permission: ToolPermissionAdmissionV1,
    a: &TaskRunAssignmentIdentity,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    propose_inner(s, b, arguments_payload, a, Some(permission))
}

fn propose_inner(
    s: &StoreTransaction,
    b: ToolInvocationBindingV1,
    arguments_payload: EncryptedToolPayloadV1,
    a: &TaskRunAssignmentIdentity,
    permission: Option<ToolPermissionAdmissionV1>,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    validate_binding(&b).map_err(|error| match error {
        ToolInvocationStoreError::Conflict => {
            ToolInvocationStoreError::ProposalConflict(ProposalConflictKind::Binding)
        }
        other => other,
    })?;
    if arguments_payload.payload.plaintext_len() as usize != b.canonical_arguments.len()
        || arguments_payload.payload.plaintext_digest() != b.arguments_digest.as_bytes()
        || arguments_payload.payload.ciphertext().len() > MAX_TOOL_ARGUMENT_BYTES + 16
    {
        return Err(ToolInvocationStoreError::ProposalConflict(
            ProposalConflictKind::Binding,
        ));
    }
    same_assignment(b.key, a)?;
    let mut w = s
        .inner
        .writer
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let tx = w
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let now = validate::fresh_now_millis();
    if let Some(old) = read::get_from_connection(&tx, b.key)? {
        if old.semantic_digest != b.semantic_digest {
            return Err(ToolInvocationStoreError::Conflict);
        }
        tx.commit()
            .map_err(|_| ToolInvocationStoreError::Unavailable)?;
        return Ok(old);
    }
    validate_task(
        &tx,
        &s.runtime_authority_id,
        a,
        b.expected_taskrun_version,
        b.key.cycle_id,
        b.key.proposal_index,
        &b.principal_id,
        now,
    )?;
    verify_sources(&tx, b.key, &b.sources).map_err(|error| match error {
        ToolInvocationStoreError::Conflict => {
            ToolInvocationStoreError::ProposalConflict(ProposalConflictKind::Sources)
        }
        other => other,
    })?;
    let effect = effect_digest(&b);
    let prior: Option<PriorEffectRow> = tx
        .query_row(
            "SELECT tool_name,arguments_digest,target_name,target_precondition,root_identity,root_revision FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND effect_digest=?2",
            params![b.key.taskrun_id.as_bytes(), effect.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if let Some((tool, arguments, target, target_precondition, root, root_revision)) = prior {
        let conflict = if tool != b.tool_name {
            ProposalConflictKind::EffectDigestToolMismatch
        } else if arguments != b.arguments_digest.as_bytes() {
            ProposalConflictKind::EffectDigestArgumentsMismatch
        } else if target != b.target_name
            || !target_precondition_matches(target_precondition.as_deref(), b.target_precondition)
        {
            ProposalConflictKind::EffectDigestTargetMismatch
        } else if root != b.root_identity.as_bytes() || root_revision != b.root_revision as i64 {
            ProposalConflictKind::EffectDigestRootMismatch
        } else {
            ProposalConflictKind::DuplicateEffect
        };
        return Err(ToolInvocationStoreError::ProposalConflict(conflict));
    }
    let source_bytes = encode_sources(&b.sources);
    let budget_matches:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM taskrun_tool_budgets WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3 AND node_id=?4 AND node_epoch=?5 AND reservation_id IS NOT NULL AND reservation_digest IS NOT NULL)",params![b.key.taskrun_id.as_bytes(),b.key.attempt_id.as_bytes(),a.fence.0 as i64,a.node_id.0,a.node_epoch as i64],|r|r.get(0)).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    if !budget_matches {
        return Err(ToolInvocationStoreError::InvalidState);
    }
    persist_payload_nonce(&tx, &arguments_payload, b.sources[0].dispatch_attempt_id).map_err(
        |error| match error {
            ToolInvocationStoreError::Conflict => {
                ToolInvocationStoreError::ProposalConflict(ProposalConflictKind::PayloadNonce)
            }
            other => other,
        },
    )?;
    tx.execute("INSERT INTO taskrun_tool_invocations(taskrun_id,attempt_id,cycle_id,proposal_index,expected_taskrun_version,call_id,tool_name,tool_revision,schema_digest,canonical_arguments,arguments_digest,semantic_digest,effect_digest,source_refs,environment_id,environment_revision,root_identity,root_revision,target_name,target_precondition,approval_id,principal_id,approval_principal_id,approval_action,approval_resource,approval_digest,policy_revision,approval_expires_at,round_index,state,updated_at,args_key_id,args_key_version,args_runtime_authority_id,args_database_generation,args_nonce,args_plaintext_len,args_plaintext_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,'proposed',?30,?31,?32,?33,?34,?35,?36,?37)",params![b.key.taskrun_id.as_bytes(),b.key.attempt_id.as_bytes(),b.key.cycle_id.as_bytes(),i64::from(b.key.proposal_index),b.expected_taskrun_version as i64,b.call_id,b.tool_name,b.tool_revision,b.schema_digest.as_bytes(),arguments_payload.payload.ciphertext(),b.arguments_digest.as_bytes(),b.semantic_digest.as_bytes(),effect.as_bytes(),source_bytes,b.environment_id,b.environment_revision,b.root_identity.as_bytes(),b.root_revision as i64,b.target_name,b.target_precondition.map(|d|d.into_bytes().to_vec()),b.approval_id,b.principal_id,b.approval_principal_id,b.approval_action,b.approval_resource,b.approval_digest.as_bytes(),b.policy_revision as i64,b.approval_expires_at,b.round_index as i64,now,arguments_payload.key.key_id().as_slice(),arguments_payload.key.key_version() as i64,arguments_payload.key.runtime_authority_id().as_slice(),arguments_payload.key.database_generation() as i64,arguments_payload.payload.nonce().as_slice(),arguments_payload.payload.plaintext_len() as i64,arguments_payload.payload.plaintext_digest()]).map_err(proposal_insert_error)?;
    if let Some(permission) = permission {
        insert_permission(&tx, &b, &permission, now)?;
    }
    let receipt =
        read::get_from_connection(&tx, b.key)?.ok_or(ToolInvocationStoreError::CorruptData)?;
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(receipt)
}

fn target_precondition_matches(
    stored: Option<&[u8]>,
    current: Option<runne_domain::id::IntegrityDigest>,
) -> bool {
    match (stored, current) {
        (None, None) => true,
        (Some(stored), Some(current)) => stored == current.as_bytes(),
        _ => false,
    }
}

fn proposal_insert_error(error: rusqlite::Error) -> ToolInvocationStoreError {
    let kind = match error {
        rusqlite::Error::SqliteFailure(code, _) => match code.extended_code {
            rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            | rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY => ProposalConflictKind::InsertUnique,
            rusqlite::ffi::SQLITE_CONSTRAINT_CHECK | rusqlite::ffi::SQLITE_CONSTRAINT_NOTNULL => {
                ProposalConflictKind::InsertCheck
            }
            rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY => ProposalConflictKind::InsertForeignKey,
            _ => ProposalConflictKind::InsertOther,
        },
        _ => ProposalConflictKind::InsertOther,
    };
    ToolInvocationStoreError::ProposalConflict(kind)
}

pub(super) fn persist_payload_nonce(
    tx: &rusqlite::Transaction<'_>,
    payload: &EncryptedToolPayloadV1,
    dispatch_attempt_id: [u8; 16],
) -> Result<(), ToolInvocationStoreError> {
    let known_key: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_stream_journal j JOIN provider_journal_key_refs k ON k.key_id=j.key_id AND k.key_version=j.key_version WHERE j.dispatch_attempt_id=?1 AND j.event_kind=5 AND j.terminal=1 AND k.key_id=?2 AND k.key_version=?3 AND k.runtime_authority_id=?4 AND k.database_generation=?5)",
            rusqlite::params![dispatch_attempt_id.as_slice(),payload.key.key_id().as_slice(), payload.key.key_version() as i64, payload.key.runtime_authority_id().as_slice(), payload.key.database_generation() as i64],
            |row| row.get(0),
        )
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if !known_key {
        return Err(ToolInvocationStoreError::Conflict);
    }
    let duplicate: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_encryption_nonces WHERE key_id=?1 AND key_version=?2 AND nonce=?3)",
            rusqlite::params![payload.key.key_id().as_slice(), payload.key.key_version() as i64, payload.payload.nonce().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    if duplicate {
        return Err(ToolInvocationStoreError::Conflict);
    }
    tx.execute(
        "INSERT INTO provider_encryption_nonces(key_id,key_version,nonce,purpose,dispatch_attempt_id,sequence) VALUES(?1,?2,?3,2,?4,NULL)",
        rusqlite::params![payload.key.key_id().as_slice(), payload.key.key_version() as i64, payload.payload.nonce().as_slice(), dispatch_attempt_id.as_slice()],
    ).map_err(|_| ToolInvocationStoreError::Conflict)?;
    Ok(())
}

pub(super) fn bind_approval(
    s: &StoreTransaction,
    p: ToolApprovalBindingV1,
    a: &TaskRunAssignmentIdentity,
    _now: i64,
) -> Result<ToolInvocationReceipt, ToolInvocationStoreError> {
    same_assignment(p.key, a)?;
    let mut w = s
        .inner
        .writer
        .lock()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let tx = w
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    let now = validate::fresh_now_millis();
    let binding = load_binding_for_validation(&tx, p.key)?;
    validate_task(
        &tx,
        &s.runtime_authority_id,
        a,
        binding.expected_taskrun_version,
        p.key.cycle_id,
        p.key.proposal_index,
        &binding.principal_id,
        now,
    )?;
    let row: Option<ApprovalBindingRow> = tx.query_row("SELECT i.semantic_digest,i.approval_principal_id,i.approval_action,i.approval_resource,i.principal_id,i.approval_digest,i.policy_revision,i.approval_expires_at,a.decision_principal_id,a.attempt_id,a.action,a.resource,a.action_digest,a.policy_revision,a.state,a.principal_id,a.decision,a.expires_at,a.task_run_id FROM taskrun_tool_invocations i LEFT JOIN approvals a ON a.approval_id=?5 WHERE i.taskrun_id=?1 AND i.attempt_id=?2 AND i.cycle_id=?3 AND i.proposal_index=?4 AND i.approval_id=?6",params![p.key.taskrun_id.as_bytes(),p.key.attempt_id.as_bytes(),p.key.cycle_id.as_bytes(),i64::from(p.key.proposal_index),runne_domain::id::ApprovalId::from_bytes(p.approval_id).to_string(),p.approval_id.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?,r.get(16)?,r.get(17)?,r.get(18)?))).optional().map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let Some((
        digest,
        approver,
        action,
        resource,
        submit,
        adigest,
        policy,
        expiry,
        decision_principal,
        attempt,
        a_action,
        a_resource,
        a_digest,
        a_policy,
        state,
        actual_principal,
        decision,
        a_expiry,
        taskrun,
    )) = row
    else {
        return Err(ToolInvocationStoreError::InvalidState);
    };
    let attempt_text = p.key.attempt_id.to_string();
    if p.decision_principal_id != approver
        || p.expected_policy_revision as i64 != policy
        || p.expected_action_digest.as_bytes() != adigest.as_slice()
        || taskrun.as_deref() != Some(p.key.taskrun_id.to_string().as_str())
        || attempt.as_deref() != Some(attempt_text.as_str())
        || a_action.as_deref() != Some(action.as_str())
        || a_resource.as_deref() != Some(resource.as_str())
        || a_digest.as_deref() != Some(adigest.as_slice())
        || a_policy != Some(policy)
        || a_expiry != Some(expiry)
        || actual_principal.as_deref() != Some(submit.as_str())
        || submit.is_empty()
    {
        return Err(ToolInvocationStoreError::ApprovalDenied);
    }
    let state = match (state, decision) {
        (Some(1), None) => return Err(ToolInvocationStoreError::InvalidState),
        (Some(2), Some(1)) if decision_principal.as_deref() == Some(approver.as_str()) => {
            if expiry <= now {
                return Err(ToolInvocationStoreError::ApprovalExpired);
            }
            "approved"
        }
        (Some(3), Some(2)) if decision_principal.as_deref() == Some(approver.as_str()) => "denied",
        (Some(4), _) => return Err(ToolInvocationStoreError::ApprovalExpired),
        (Some(5), _) => return Err(ToolInvocationStoreError::ApprovalDenied),
        _ => return Err(ToolInvocationStoreError::InvalidState),
    };
    tx.execute("UPDATE taskrun_tool_invocations SET state=?1,updated_at=?2 WHERE taskrun_id=?3 AND attempt_id=?4 AND cycle_id=?5 AND proposal_index=?6 AND semantic_digest=?7 AND state='proposed'",params![state,now,p.key.taskrun_id.as_bytes(),p.key.attempt_id.as_bytes(),p.key.cycle_id.as_bytes(),i64::from(p.key.proposal_index),digest]).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    let r = read::get_from_connection(&tx, p.key)?.ok_or(ToolInvocationStoreError::CorruptData)?;
    let _ = submit;
    tx.commit()
        .map_err(|_| ToolInvocationStoreError::Unavailable)?;
    Ok(r)
}
