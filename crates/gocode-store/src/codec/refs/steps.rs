
pub(super) fn encode_step_ref(buf: &mut Vec<u8>, value: &StepOutcomeRef) {
    write_uuid(buf, value.cycle_id.as_bytes());
    buf.extend_from_slice(&value.proposal_index.to_be_bytes());
    write_uuid(buf, value.step_id.as_bytes());
    write_digest(buf, &value.outcome_digest);
}

pub(super) fn decode_step_ref(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<StepOutcomeRef, StoreCodecError> {
    let cycle_id = CycleId::from_bytes(read_uuid(bytes, pos)?);
    if *pos + 4 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let proposal_index = u32::from_be_bytes(
        bytes[*pos..*pos + 4]
            .try_into()
            .map_err(|_| StoreCodecError::Truncated)?,
    );
    *pos += 4;
    Ok(StepOutcomeRef {
        cycle_id,
        proposal_index,
        step_id: StepId::from_bytes(read_uuid(bytes, pos)?),
        outcome_digest: read_digest(bytes, pos)?,
    })
}

pub(super) fn encode_step_record(
    buf: &mut Vec<u8>,
    value: &StepOutcomeRecord,
) -> Result<(), StoreCodecError> {
    buf.extend_from_slice(&value.proposal_index.to_be_bytes());
    write_uuid(buf, value.step_id.as_bytes());
    buf.push(match value.outcome_type {
        StepOutcomeType::Succeeded => 0,
        StepOutcomeType::FailedBeforeCommit => 1,
        StepOutcomeType::FailedAfterCommit => 2,
        StepOutcomeType::Uncertain => 3,
        StepOutcomeType::Cancelled => 4,
    });
    match &value.result_ref {
        None => buf.push(0),
        Some(result) => {
            buf.push(1);
            encode_result_ref(buf, result)?;
        }
    }
    match value.effect_id {
        None => buf.push(0),
        Some(effect_id) => {
            buf.push(1);
            write_uuid(buf, effect_id.as_bytes());
        }
    }
    if value.evidence_digests.len() > u16::MAX as usize {
        return Err(StoreCodecError::Oversized {
            field: "StepOutcomeRecord evidence",
            max: u16::MAX as usize,
            actual: value.evidence_digests.len(),
        });
    }
    write_u16_be(buf, value.evidence_digests.len() as u16);
    for digest in &value.evidence_digests {
        write_digest(buf, digest);
    }
    Ok(())
}

pub(super) fn decode_step_record(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<StepOutcomeRecord, StoreCodecError> {
    if *pos + 4 > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let proposal_index = u32::from_be_bytes(
        bytes[*pos..*pos + 4]
            .try_into()
            .map_err(|_| StoreCodecError::Truncated)?,
    );
    *pos += 4;
    let step_id = StepId::from_bytes(read_uuid(bytes, pos)?);
    let outcome_tag = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    let outcome_type = match outcome_tag {
        0 => StepOutcomeType::Succeeded,
        1 => StepOutcomeType::FailedBeforeCommit,
        2 => StepOutcomeType::FailedAfterCommit,
        3 => StepOutcomeType::Uncertain,
        4 => StepOutcomeType::Cancelled,
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "StepOutcomeType",
            });
        }
    };
    let result_ref = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(decode_result_ref(bytes, pos)?)
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "StepOutcomeRecord result option",
            });
        }
    };
    let effect_id = match *bytes.get(*pos).ok_or(StoreCodecError::Truncated)? {
        0 => {
            *pos += 1;
            None
        }
        1 => {
            *pos += 1;
            Some(EffectId::from_bytes(read_uuid(bytes, pos)?))
        }
        tag => {
            return Err(StoreCodecError::UnknownTag {
                tag,
                context: "StepOutcomeRecord effect option",
            });
        }
    };
    let evidence_len = read_u16_be(bytes, pos)? as usize;
    let mut evidence_digests = Vec::with_capacity(evidence_len);
    for _ in 0..evidence_len {
        evidence_digests.push(read_digest(bytes, pos)?);
    }
    Ok(StepOutcomeRecord {
        proposal_index,
        step_id,
        outcome_type,
        result_ref,
        effect_id,
        evidence_digests,
    })
}
