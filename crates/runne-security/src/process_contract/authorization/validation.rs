use super::{
    AuthorizationReplayGuard, Decision, ProcessApprovalV1, ProcessCapabilityV1,
    ValidatedProcessIntentV1,
};
use crate::process_contract::context::{CurrentProcessContextV1, validate_current_context};
use crate::process_contract::{ProcessContractError, ProcessIdentityBindingV1, ProcessIntentV1};

struct CheckedAuthorizationV1 {
    replay_key: Vec<u8>,
}

pub(crate) fn preflight_authorization(
    intent: &ProcessIntentV1,
    capability: Option<&ProcessCapabilityV1>,
    approval: Option<&ProcessApprovalV1>,
    current: &CurrentProcessContextV1,
    replay_guard: &AuthorizationReplayGuard,
    now: u64,
) -> Result<(), ProcessContractError> {
    check_authorization(intent, capability, approval, current, replay_guard, now).map(|_| ())
}

pub(crate) fn validate_authorization(
    intent: ProcessIntentV1,
    capability: Option<&ProcessCapabilityV1>,
    approval: Option<&ProcessApprovalV1>,
    current: &CurrentProcessContextV1,
    replay_guard: &mut AuthorizationReplayGuard,
    now: u64,
) -> Result<ValidatedProcessIntentV1, ProcessContractError> {
    let checked = check_authorization(&intent, capability, approval, current, replay_guard, now)?;
    replay_guard.record_use(checked.replay_key)?;
    Ok(ValidatedProcessIntentV1 { intent })
}

fn check_authorization(
    intent: &ProcessIntentV1,
    capability: Option<&ProcessCapabilityV1>,
    approval: Option<&ProcessApprovalV1>,
    current: &CurrentProcessContextV1,
    replay_guard: &AuthorizationReplayGuard,
    now: u64,
) -> Result<CheckedAuthorizationV1, ProcessContractError> {
    let capability = capability.ok_or(ProcessContractError::CapabilityInvalid)?;
    if capability.domain != replay_guard.domain
        || capability.digest != intent.digest()
        || capability.binding != *intent.binding()
        || capability.approval != *intent.approval()
        || now >= capability.expires
        || capability.revision != current.revision
        || capability.epoch != current.epoch
    {
        return Err(ProcessContractError::CapabilityInvalid);
    }
    let approval = approval.ok_or(ProcessContractError::ApprovalInvalid)?;
    if approval.domain != replay_guard.domain
        || approval.id != *intent.approval()
        || approval.digest != intent.digest()
        || approval.binding != *intent.binding()
        || approval.scope.digest != intent.digest()
        || approval.scope.binding != *intent.binding()
        || approval.approver != current.approver
        || approval.decision != Decision::Approved
        || now >= approval.expires
        || approval.revision != current.revision
        || approval.epoch != current.epoch
    {
        return Err(ProcessContractError::ApprovalInvalid);
    }
    validate_current_context(current, intent)?;
    Ok(CheckedAuthorizationV1 {
        replay_key: authorization_replay_key(capability, approval, intent),
    })
}

fn authorization_replay_key(
    capability: &ProcessCapabilityV1,
    approval: &ProcessApprovalV1,
    intent: &ProcessIntentV1,
) -> Vec<u8> {
    let mut key = Vec::new();
    let binding = binding_bytes(&capability.binding);
    for value in [
        capability.domain.legacy_seed.as_slice(),
        capability
            .domain
            .authority_instance
            .to_be_bytes()
            .as_slice(),
        capability.id.bytes().as_slice(),
        approval.id.bytes().as_slice(),
        intent.digest().as_bytes().as_slice(),
        binding.as_slice(),
        capability.revision.to_be_bytes().as_slice(),
        capability.epoch.to_be_bytes().as_slice(),
    ] {
        part(&mut key, value);
    }
    key
}

fn binding_bytes(binding: &ProcessIdentityBindingV1) -> Vec<u8> {
    let mut value = Vec::new();
    for part_value in [
        binding.principal.bytes().as_slice(),
        binding.authority.bytes().as_slice(),
        binding.owner.as_bytes().as_slice(),
        binding.attempt.as_bytes().as_slice(),
        binding.session.as_bytes().as_slice(),
        binding.generation.as_bytes().as_slice(),
        binding.accounting.bytes().as_slice(),
        binding.sandbox.bytes().as_slice(),
        binding.tree.as_bytes().as_slice(),
    ] {
        part(&mut value, part_value);
    }
    value
}

fn part(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(value);
}
