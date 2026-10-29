pub(super) fn load_budget(
    tx: &Transaction<'_>,
    task: TaskRunId,
) -> Result<ToolInvocationBudget, ToolInvocationStoreError> {
    budget_policy::limits(tx, task)?;
    let row: Option<(i64, i64)> = tx
        .query_row(
            "SELECT effects_used,continuations_used FROM taskrun_tool_budgets WHERE taskrun_id=?1",
            [task.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| ToolInvocationStoreError::CorruptData)?;
    Ok(row.map_or(
        ToolInvocationBudget {
            effects_used: 0,
            continuations_used: 0,
        },
        |(e, c)| ToolInvocationBudget {
            effects_used: e as u32,
            continuations_used: c as u32,
        },
    ))
}

pub(super) fn ensure_no_unresolved(
    tx: &Transaction<'_>,
    task: TaskRunId,
) -> Result<(), ToolInvocationStoreError> {
    let found:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND state IN ('claimed','uncertain'))",[task.as_bytes()],|r|r.get(0)).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    if found {
        Err(ToolInvocationStoreError::Uncertain)
    } else {
        Ok(())
    }
}

pub(super) fn load_binding_for_validation(
    tx: &Connection,
    key: ToolInvocationKey,
) -> Result<ToolInvocationBindingV1, ToolInvocationStoreError> {
    type R = (
        i64,
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        String,
        String,
        Vec<u8>,
        i64,
        String,
        Option<Vec<u8>>,
        Vec<u8>,
        String,
        String,
        String,
        String,
        Vec<u8>,
        i64,
        i64,
        i64,
        Vec<u8>,
    );
    let r:R=tx.query_row("SELECT expected_taskrun_version,call_id,tool_name,tool_revision,schema_digest,canonical_arguments,arguments_digest,semantic_digest,environment_id,environment_revision,root_identity,root_revision,target_name,target_precondition,approval_id,principal_id,approval_principal_id,approval_action,approval_resource,approval_digest,policy_revision,approval_expires_at,round_index,source_refs FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND attempt_id=?2 AND cycle_id=?3 AND proposal_index=?4",params![key.taskrun_id.as_bytes(),key.attempt_id.as_bytes(),key.cycle_id.as_bytes(),i64::from(key.proposal_index)],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?,r.get(16)?,r.get(17)?,r.get(18)?,r.get(19)?,r.get(20)?,r.get(21)?,r.get(22)?,r.get(23)?))).map_err(|_|ToolInvocationStoreError::CorruptData)?;
    Ok(ToolInvocationBindingV1 {
        key,
        expected_taskrun_version: r.0 as u64,
        call_id: r.1,
        tool_name: r.2,
        tool_revision: r.3,
        schema_digest: parse_digest(r.4)?,
        canonical_arguments: r.5,
        arguments_digest: parse_digest(r.6)?,
        semantic_digest: parse_digest(r.7)?,
        environment_id: r.8,
        environment_revision: r.9,
        root_identity: parse_digest(r.10)?,
        root_revision: r.11 as u64,
        target_name: r.12,
        target_precondition: r.13.map(parse_digest).transpose()?,
        approval_id: r
            .14
            .try_into()
            .map_err(|_| ToolInvocationStoreError::CorruptData)?,
        principal_id: r.15,
        approval_principal_id: r.16,
        approval_action: r.17,
        approval_resource: r.18,
        approval_digest: parse_digest(r.19)?,
        policy_revision: r.20 as u64,
        approval_expires_at: r.21,
        round_index: r.22 as u32,
        sources: decode_sources(&r.23)?,
    })
}

fn parse_digest(bytes: Vec<u8>) -> Result<IntegrityDigest, ToolInvocationStoreError> {
    Ok(IntegrityDigest::from_bytes(
        bytes
            .try_into()
            .map_err(|_| ToolInvocationStoreError::CorruptData)?,
    ))
}
pub(in crate::store) fn decode_sources(
    bytes: &[u8],
) -> Result<Vec<ToolSourceRef>, ToolInvocationStoreError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(98) {
        return Err(ToolInvocationStoreError::CorruptData);
    }
    bytes
        .chunks_exact(98)
        .map(|c| {
            Ok(ToolSourceRef {
                dispatch_attempt_id: c[..16]
                    .try_into()
                    .map_err(|_| ToolInvocationStoreError::CorruptData)?,
                sequence: u64::from_be_bytes(
                    c[16..24]
                        .try_into()
                        .map_err(|_| ToolInvocationStoreError::CorruptData)?,
                ),
                event_kind: c[24],
                terminal: c[25] != 0,
                plaintext_digest: parse_digest(c[26..58].to_vec())?,
                profile_digest: parse_digest(c[58..90].to_vec())?,
                runtime_generation: u64::from_be_bytes(
                    c[90..98]
                        .try_into()
                        .map_err(|_| ToolInvocationStoreError::CorruptData)?,
                ),
            })
        })
        .collect()
}
