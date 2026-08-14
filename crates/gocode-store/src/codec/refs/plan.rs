pub(super) fn encode_context_ref(
    buf: &mut Vec<u8>,
    value: &ContextManifestRef,
) -> Result<(), StoreCodecError> {
    write_uuid(buf, value.manifest_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.attempt_id.as_bytes());
    write_uuid(buf, value.cycle_id.as_bytes());
    write_u64_be(buf, value.revision);
    write_string(buf, &value.policy_revision)?;
    write_digest(buf, &value.integrity_digest);
    Ok(())
}

pub(super) fn decode_context_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<ContextManifestRef, StoreCodecError> {
    Ok(ContextManifestRef {
        manifest_id: ContextManifestId::from_bytes(read_uuid(bytes, pos)?),
        taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, pos)?),
        attempt_id: AttemptId::from_bytes(read_uuid(bytes, pos)?),
        cycle_id: CycleId::from_bytes(read_uuid(bytes, pos)?),
        revision: read_u64_be(bytes, pos)?,
        policy_revision: read_string(bytes, pos, "ContextManifestRef policy revision")?,
        integrity_digest: read_digest(bytes, pos)?,
    })
}

pub(super) fn encode_result_ref(
    buf: &mut Vec<u8>,
    value: &ResultRef,
) -> Result<(), StoreCodecError> {
    write_uuid(buf, value.result_id().as_bytes());
    write_string(buf, value.media_type())?;
    write_digest(buf, value.integrity_digest());
    Ok(())
}

pub(super) fn decode_result_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<ResultRef, StoreCodecError> {
    ResultRef::new(
        ResultId::from_bytes(read_uuid(bytes, pos)?),
        read_string(bytes, pos, "ResultRef media type")?,
        read_digest(bytes, pos)?,
    )
    .map_err(|_| StoreCodecError::UnknownTag {
        tag: 0,
        context: "ResultRef",
    })
}

pub(super) fn encode_budget_ref(buf: &mut Vec<u8>, value: &BudgetReservationRef) {
    write_uuid(buf, value.reservation_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.attempt_id.as_bytes());
    write_u64_be(buf, value.retry_ordinal);
    write_digest(buf, &value.reservation_digest);
}

pub(super) fn decode_budget_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<BudgetReservationRef, StoreCodecError> {
    Ok(BudgetReservationRef {
        reservation_id: BudgetReservationId::from_bytes(read_uuid(bytes, pos)?),
        taskrun_id: TaskRunId::from_bytes(read_uuid(bytes, pos)?),
        attempt_id: AttemptId::from_bytes(read_uuid(bytes, pos)?),
        retry_ordinal: read_u64_be(bytes, pos)?,
        reservation_digest: read_digest(bytes, pos)?,
    })
}

pub(super) fn encode_plan_ref(
    buf: &mut Vec<u8>,
    value: &PlanRevisionRef,
) -> Result<(), StoreCodecError> {
    write_uuid(buf, value.plan_id.as_bytes());
    write_uuid(buf, value.taskrun_id.as_bytes());
    write_uuid(buf, value.cycle_id.as_bytes());
    write_u64_be(buf, value.revision);
    encode_context_ref(buf, &value.context_manifest_ref)?;
    write_u32_vec(buf, &value.expected_proposal_indexes)?;
    write_digest(buf, &value.proposal_batch_digest);
    encode_result_ref(buf, &value.planning_policy_ref)?;
    encode_budget_ref(buf, &value.planning_budget_ref);
    match &value.parent_ref {
        None => buf.push(0),
        Some(parent) => {
            buf.push(1);
            write_uuid(buf, parent.plan_id.as_bytes());
            write_u64_be(buf, parent.revision);
            write_digest(buf, &parent.integrity_digest);
        }
    }
    write_digest(buf, &value.integrity_digest);
    Ok(())
}

pub(super) fn decode_plan_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<PlanRevisionRef, StoreCodecError> {
    let plan_id = PlanId::from_bytes(read_uuid(bytes, pos)?);
    let taskrun_id = TaskRunId::from_bytes(read_uuid(bytes, pos)?);
    let cycle_id = CycleId::from_bytes(read_uuid(bytes, pos)?);
    let revision = read_u64_be(bytes, pos)?;
    let context_manifest_ref = decode_context_ref(bytes, pos)?;
    let expected_proposal_indexes = read_u32_vec(bytes, pos)?;
    if expected_proposal_indexes
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(StoreCodecError::UnknownTag {
            tag: 0,
            context: "PlanRevisionRef proposal indexes",
        });
    }
    let proposal_batch_digest = read_digest(bytes, pos)?;
    let planning_policy_ref = decode_result_ref(bytes, pos)?;
    let planning_budget_ref = decode_budget_ref(bytes, pos)?;
    let parent_ref = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(PlanParentRef {
                plan_id: PlanId::from_bytes(read_uuid(bytes, pos)?),
                revision: read_u64_be(bytes, pos)?,
                integrity_digest: read_digest(bytes, pos)?,
            })
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "PlanRevisionRef parent",
            });
        }
    };
    Ok(PlanRevisionRef {
        plan_id,
        taskrun_id,
        cycle_id,
        revision,
        context_manifest_ref,
        expected_proposal_indexes,
        proposal_batch_digest,
        planning_policy_ref,
        planning_budget_ref,
        parent_ref,
        integrity_digest: read_digest(bytes, pos)?,
    })
}
