pub(super) fn encode_wake_condition(
    buf: &mut Vec<u8>,
    value: &WakeCondition,
) -> Result<(), StoreCodecError> {
    buf.push(match value.kind {
        WakeConditionKind::ExternalInput => 0,
        WakeConditionKind::Approval => 1,
        WakeConditionKind::ChildTaskRun => 2,
        WakeConditionKind::Timer => 3,
        WakeConditionKind::Reconciliation => 4,
    });
    write_string(buf, &value.condition_ref)?;
    write_digest(buf, &value.condition_digest);
    Ok(())
}

pub(super) fn decode_wake_condition(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<WakeCondition, StoreCodecError> {
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let kind = match tag {
        0 => WakeConditionKind::ExternalInput,
        1 => WakeConditionKind::Approval,
        2 => WakeConditionKind::ChildTaskRun,
        3 => WakeConditionKind::Timer,
        4 => WakeConditionKind::Reconciliation,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "WakeConditionKind",
            });
        }
    };
    Ok(WakeCondition {
        kind,
        condition_ref: read_string(bytes, pos, "WakeCondition reference")?,
        condition_digest: read_digest(bytes, pos)?,
    })
}

pub(super) fn encode_wake_evidence(
    buf: &mut Vec<u8>,
    value: &WakeEvidenceRef,
) -> Result<(), StoreCodecError> {
    write_uuid(buf, value.cycle_id.as_bytes());
    write_digest(buf, &value.condition_digest);
    buf.push(match value.source {
        WakeEvidenceSource::ExternalInput => 0,
        WakeEvidenceSource::Approval => 1,
        WakeEvidenceSource::ChildTaskRun => 2,
        WakeEvidenceSource::Timer => 3,
        WakeEvidenceSource::Reconciliation => 4,
    });
    write_uuid(buf, value.evidence_id.as_bytes());
    write_digest(buf, &value.evidence_digest);
    write_i64_be(buf, value.observed_at_unix_us);
    write_string(buf, &value.authority_revision)
}

pub(super) fn decode_wake_evidence(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<WakeEvidenceRef, StoreCodecError> {
    let cycle_id = CycleId::from_bytes(read_uuid(bytes, pos)?);
    let condition_digest = read_digest(bytes, pos)?;
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let source = match tag {
        0 => WakeEvidenceSource::ExternalInput,
        1 => WakeEvidenceSource::Approval,
        2 => WakeEvidenceSource::ChildTaskRun,
        3 => WakeEvidenceSource::Timer,
        4 => WakeEvidenceSource::Reconciliation,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "WakeEvidenceSource",
            });
        }
    };
    Ok(WakeEvidenceRef {
        cycle_id,
        condition_digest,
        source,
        evidence_id: WakeEvidenceId::from_bytes(read_uuid(bytes, pos)?),
        evidence_digest: read_digest(bytes, pos)?,
        observed_at_unix_us: read_i64_be(bytes, pos)?,
        authority_revision: read_string(bytes, pos, "WakeEvidence authority revision")?,
    })
}

pub(super) fn encode_plan_evaluation(buf: &mut Vec<u8>, value: &PlanEvaluationRef) {
    write_uuid(buf, value.evaluation_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.plan_id.as_bytes());
    write_u64_be(buf, value.plan_revision);
    write_u64_be(buf, value.evaluated_stream_head);
    buf.push(match value.result {
        PlanEvaluationResult::Passed => 0,
        PlanEvaluationResult::Failed => 1,
        PlanEvaluationResult::Blocked => 2,
        PlanEvaluationResult::RequiresReview => 3,
    });
    write_digest(buf, &value.gate_definitions_digest);
    write_digest(buf, &value.evidence_set_digest);
    write_digest(buf, &value.evaluation_digest);
}

pub(super) fn decode_plan_evaluation(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<PlanEvaluationRef, StoreCodecError> {
    let evaluation_id = PlanEvaluationId::from_bytes(read_uuid(bytes, pos)?);
    let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, pos)?);
    let plan_id = PlanId::from_bytes(read_uuid(bytes, pos)?);
    let plan_revision = read_u64_be(bytes, pos)?;
    let evaluated_stream_head = read_u64_be(bytes, pos)?;
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let result = match tag {
        0 => PlanEvaluationResult::Passed,
        1 => PlanEvaluationResult::Failed,
        2 => PlanEvaluationResult::Blocked,
        3 => PlanEvaluationResult::RequiresReview,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "PlanEvaluationResult",
            });
        }
    };
    Ok(PlanEvaluationRef {
        evaluation_id,
        taskrun_id,
        plan_id,
        plan_revision,
        evaluated_stream_head,
        result,
        gate_definitions_digest: read_digest(bytes, pos)?,
        evidence_set_digest: read_digest(bytes, pos)?,
        evaluation_digest: read_digest(bytes, pos)?,
    })
}

pub(super) fn encode_disposition(
    buf: &mut Vec<u8>,
    value: &LoopDisposition,
) -> Result<(), StoreCodecError> {
    match value {
        LoopDisposition::Continue => buf.push(0),
        LoopDisposition::Wait {
            reason,
            wake_condition,
        } => {
            buf.push(1);
            write_string(buf, reason)?;
            encode_wake_condition(buf, wake_condition)?;
        }
        LoopDisposition::Complete {
            plan_evaluation_ref,
        } => {
            buf.push(2);
            encode_plan_evaluation(buf, plan_evaluation_ref);
        }
        LoopDisposition::Fail {
            reason,
            unresolved_proposals,
        } => {
            buf.push(3);
            write_string(buf, reason)?;
            write_u32_vec(buf, unresolved_proposals)?;
        }
    }
    Ok(())
}

pub(super) fn decode_disposition(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<LoopDisposition, StoreCodecError> {
    let tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    match tag {
        0 => Ok(LoopDisposition::Continue),
        1 => Ok(LoopDisposition::Wait {
            reason: read_string(bytes, pos, "LoopDisposition wait reason")?,
            wake_condition: decode_wake_condition(bytes, pos)?,
        }),
        2 => Ok(LoopDisposition::Complete {
            plan_evaluation_ref: decode_plan_evaluation(bytes, pos)?,
        }),
        3 => Ok(LoopDisposition::Fail {
            reason: read_string(bytes, pos, "LoopDisposition fail reason")?,
            unresolved_proposals: read_u32_vec(bytes, pos)?,
        }),
        tag => Err(StoreCodecError::UnknownTag {
            tag,
            context: "LoopDisposition",
        }),
    }
}
