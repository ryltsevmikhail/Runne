pub(super) fn encode_checkpoint_ref(buf: &mut Vec<u8>, value: &CheckpointRef) {
    write_uuid(buf, value.checkpoint_id.as_bytes());
    write_u64_be(buf, value.event_position);
    write_digest(buf, &value.integrity_digest);
}

pub(super) fn decode_checkpoint_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<CheckpointRef, StoreCodecError> {
    Ok(CheckpointRef {
        checkpoint_id: CheckpointId::from_bytes(read_uuid(bytes, pos)?),
        event_position: read_u64_be(bytes, pos)?,
        integrity_digest: read_digest(bytes, pos)?,
    })
}

pub(super) fn encode_reconciliation_ref(buf: &mut Vec<u8>, value: &ReconciliationResultRef) {
    write_uuid(buf, value.reconciliation_run_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.predecessor_attempt_id.as_bytes());
    write_u64_be(buf, value.recovery_generation);
    write_u64_be(buf, value.reconciled_stream_position);
    buf.push(match value.status {
        ReconciliationStatus::Reconciled => 0,
        ReconciliationStatus::Failed => 1,
        ReconciliationStatus::InProgress => 2,
    });
    write_u64_be(buf, value.unresolved_effect_count);
    write_digest(buf, &value.result_digest);
}

pub(super) fn decode_reconciliation_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<ReconciliationResultRef, StoreCodecError> {
    let reconciliation_run_id = ReconciliationRunId::from_bytes(read_uuid(bytes, pos)?);
    let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, pos)?);
    let predecessor_attempt_id = AttemptId::from_bytes(read_uuid(bytes, pos)?);
    let recovery_generation = read_u64_be(bytes, pos)?;
    let reconciled_stream_position = read_u64_be(bytes, pos)?;
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let status = match tag {
        0 => ReconciliationStatus::Reconciled,
        1 => ReconciliationStatus::Failed,
        2 => ReconciliationStatus::InProgress,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "ReconciliationStatus",
            });
        }
    };
    Ok(ReconciliationResultRef {
        reconciliation_run_id,
        taskrun_id,
        predecessor_attempt_id,
        recovery_generation,
        reconciled_stream_position,
        status,
        unresolved_effect_count: read_u64_be(bytes, pos)?,
        result_digest: read_digest(bytes, pos)?,
    })
}

pub(super) fn encode_checkpoint_body(
    buf: &mut Vec<u8>,
    value: &LoopCheckpointBody,
) -> Result<(), StoreCodecError> {
    write_string(buf, &value.schema_version)?;
    write_uuid(buf, value.cycle_id.as_bytes());
    write_uuid(buf, value.attempt_id.as_bytes());
    match &value.plan_revision_ref {
        None => buf.push(0),
        Some(plan_ref) => {
            buf.push(1);
            encode_plan_ref(buf, plan_ref)?;
        }
    }
    match &value.context_manifest_ref {
        None => buf.push(0),
        Some(context_ref) => {
            buf.push(1);
            encode_context_ref(buf, context_ref)?;
        }
    }
    if value.step_outcome_refs.len() > u16::MAX as usize {
        return Err(StoreCodecError::Oversized {
            field: "LoopCheckpointBody step outcomes",
            max: u16::MAX as usize,
            actual: value.step_outcome_refs.len(),
        });
    }
    write_u16_be(buf, value.step_outcome_refs.len() as u16);
    for step_ref in &value.step_outcome_refs {
        encode_step_ref(buf, step_ref);
    }
    Ok(())
}

pub(super) fn decode_checkpoint_body(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<LoopCheckpointBody, StoreCodecError> {
    let schema_version = read_string(bytes, pos, "LoopCheckpointBody schema version")?;
    let cycle_id = CycleId::from_bytes(read_uuid(bytes, pos)?);
    let attempt_id = AttemptId::from_bytes(read_uuid(bytes, pos)?);
    let plan_revision_ref = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(decode_plan_ref(bytes, pos)?)
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "LoopCheckpointBody plan option",
            });
        }
    };
    let context_manifest_ref = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(decode_context_ref(bytes, pos)?)
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "LoopCheckpointBody context option",
            });
        }
    };
    let len = read_u16_be(bytes, pos)? as usize;
    let mut step_outcome_refs = Vec::with_capacity(len);
    for _ in 0..len {
        step_outcome_refs.push(decode_step_ref(bytes, pos)?);
    }
    Ok(LoopCheckpointBody {
        schema_version,
        cycle_id,
        attempt_id,
        plan_revision_ref,
        context_manifest_ref,
        step_outcome_refs,
    })
}
