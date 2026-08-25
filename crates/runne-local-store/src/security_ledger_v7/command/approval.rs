use super::super::codec;
use crate::{BoundedCanonicalId, SecurityStateError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecisionKind {
    Approve,
    Deny,
}

pub(super) fn encode(
    output: &mut Vec<u8>,
    approval_id: &BoundedCanonicalId,
    expected_version: u64,
    decision: ApprovalDecisionKind,
    action_digest: [u8; 32],
    policy_revision: u64,
    renderer_generation: u64,
) -> Result<(), SecurityStateError> {
    if expected_version == 0
        || policy_revision == 0
        || renderer_generation == 0
        || action_digest == [0; 32]
    {
        return Err(SecurityStateError::InvalidTransition);
    }
    codec::put_id(output, approval_id)?;
    output.extend(expected_version.to_be_bytes());
    output.push(decision_tag(decision));
    output.extend(action_digest);
    output.extend(policy_revision.to_be_bytes());
    output.extend(renderer_generation.to_be_bytes());
    Ok(())
}

pub(super) fn decode(input: &mut &[u8]) -> Result<DecodedApproval, SecurityStateError> {
    let approval_id = codec::id(input)?;
    let expected_version = super::version(input)?;
    let decision = match codec::byte(input)? {
        1 => ApprovalDecisionKind::Approve,
        2 => ApprovalDecisionKind::Deny,
        _ => return Err(SecurityStateError::InvalidTransition),
    };
    let action_digest = codec::fixed(input)?;
    let policy_revision = super::version(input)?;
    let renderer_generation = super::version(input)?;
    if action_digest == [0; 32] {
        return Err(SecurityStateError::InvalidTransition);
    }
    Ok((
        approval_id,
        expected_version,
        decision,
        action_digest,
        policy_revision,
        renderer_generation,
    ))
}

type DecodedApproval = (
    BoundedCanonicalId,
    u64,
    ApprovalDecisionKind,
    [u8; 32],
    u64,
    u64,
);

const fn decision_tag(value: ApprovalDecisionKind) -> u8 {
    match value {
        ApprovalDecisionKind::Approve => 1,
        ApprovalDecisionKind::Deny => 2,
    }
}
