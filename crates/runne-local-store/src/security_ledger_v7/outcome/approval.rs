use super::super::codec;
use crate::{BoundedCanonicalId, SecurityStateError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalOutcomeState {
    Approved,
    Denied,
    Expired,
    Cancelled,
}

pub(super) fn encode(
    output: &mut Vec<u8>,
    approval_id: &BoundedCanonicalId,
    new_version: u64,
    state: ApprovalOutcomeState,
) -> Result<(), SecurityStateError> {
    if new_version == 0 {
        return Err(SecurityStateError::InvalidTransition);
    }
    output.push(10);
    codec::put_id(output, approval_id)?;
    output.extend(new_version.to_be_bytes());
    output.push(state_tag(state));
    Ok(())
}

pub(super) fn decode(
    input: &mut &[u8],
) -> Result<super::CanonicalMutationOutcome, SecurityStateError> {
    let approval_id = codec::id(input)?;
    let new_version = u64::from_be_bytes(codec::fixed(input)?);
    if new_version == 0 {
        return Err(SecurityStateError::InvalidTransition);
    }
    let state = match codec::byte(input)? {
        1 => ApprovalOutcomeState::Approved,
        2 => ApprovalOutcomeState::Denied,
        3 => ApprovalOutcomeState::Expired,
        4 => ApprovalOutcomeState::Cancelled,
        _ => return Err(SecurityStateError::InvalidTransition),
    };
    Ok(super::CanonicalMutationOutcome::ApprovalRespond {
        approval_id,
        new_version,
        state,
    })
}

const fn state_tag(value: ApprovalOutcomeState) -> u8 {
    match value {
        ApprovalOutcomeState::Approved => 1,
        ApprovalOutcomeState::Denied => 2,
        ApprovalOutcomeState::Expired => 3,
        ApprovalOutcomeState::Cancelled => 4,
    }
}
