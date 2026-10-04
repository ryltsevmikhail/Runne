fn encode_unknown_successor(
    output: &mut Vec<u8>,
    predecessor: &BoundedCanonicalId,
    successor: &BoundedCanonicalId,
    version_value: u64,
) -> Result<(), SecurityStateError> {
    if predecessor == successor || version_value == 0 {
        return Err(SecurityStateError::InvalidTransition);
    }
    output.push(24);
    codec::put_id(output, predecessor)?;
    codec::put_id(output, successor)?;
    output.extend(version_value.to_be_bytes());
    Ok(())
}

fn decode_unknown_successor(input: &mut &[u8]) -> Result<CanonicalMutationOutcome, SecurityStateError> {
    let predecessor_task_run_id = codec::id(input)?;
    let successor_task_run_id = codec::id(input)?;
    let new_version = version(input)?;
    if predecessor_task_run_id == successor_task_run_id {
        return Err(SecurityStateError::InvalidTransition);
    }
    Ok(CanonicalMutationOutcome::TaskRunUnknownSuccessorCreatedLegacy {
        predecessor_task_run_id,
        successor_task_run_id,
        new_version,
    })
}

fn encode_unknown_successor_v2(
    output: &mut Vec<u8>, predecessor: &BoundedCanonicalId,
    successor: &BoundedCanonicalId, predecessor_version: u64, successor_version: u64,
) -> Result<(), SecurityStateError> {
    if predecessor == successor || predecessor_version == 0 || successor_version != 2 {
        return Err(SecurityStateError::InvalidTransition);
    }
    output.push(25);
    codec::put_id(output, predecessor)?;
    codec::put_id(output, successor)?;
    output.extend(predecessor_version.to_be_bytes());
    output.extend(successor_version.to_be_bytes());
    Ok(())
}

fn decode_unknown_successor_v2(input: &mut &[u8]) -> Result<CanonicalMutationOutcome, SecurityStateError> {
    let predecessor_task_run_id = codec::id(input)?;
    let successor_task_run_id = codec::id(input)?;
    let predecessor_version = version(input)?;
    let successor_version = version(input)?;
    if predecessor_task_run_id == successor_task_run_id || successor_version != 2 {
        return Err(SecurityStateError::InvalidTransition);
    }
    Ok(CanonicalMutationOutcome::TaskRunUnknownSuccessorCreated {
        predecessor_task_run_id, successor_task_run_id, predecessor_version, successor_version,
    })
}
