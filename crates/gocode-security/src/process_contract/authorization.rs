//! Crate-private capability authorization validation and durable replay rejection.
//!
//! This guard rejects authorization replay only. A validated witness is a prerequisite and does
//! not authorize an external effect; outer effect admission remains the sole effect authority.
#![allow(dead_code)]

use std::collections::BTreeSet;

use super::context::{CurrentProcessContextV1, validate_current_context};
use super::{
    ApprovalId, ApproverId, ProcessCapabilityId, ProcessContractError, ProcessIdentityBindingV1,
    ProcessIntentDigestV1, ProcessIntentV1,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Decision {
    Approved,
    Rejected,
}

/// Opaque consume-only approval contract.
pub struct ProcessApprovalV1 {
    id: ApprovalId,
    digest: ProcessIntentDigestV1,
    binding: ProcessIdentityBindingV1,
    scope: ApprovalScopeV1,
    approver: ApproverId,
    decision: Decision,
    expires: u64,
    revision: u64,
    epoch: u64,
}
/// Opaque consume-only runtime capability.
pub struct ProcessCapabilityV1 {
    id: ProcessCapabilityId,
    replay_guard_id: [u8; 16],
    digest: ProcessIntentDigestV1,
    binding: ProcessIdentityBindingV1,
    approval: ApprovalId,
    expires: u64,
    revision: u64,
    epoch: u64,
}
/// Non-cloneable witness owning the exact validated intent.
pub struct ValidatedProcessIntentV1 {
    intent: ProcessIntentV1,
}

pub(crate) struct ApprovalScopeV1 {
    digest: ProcessIntentDigestV1,
    binding: ProcessIdentityBindingV1,
}

impl ValidatedProcessIntentV1 {
    #[must_use]
    pub const fn intent(&self) -> &ProcessIntentV1 {
        &self.intent
    }
}

#[derive(Default)]
pub(crate) struct AuthorizationReplayGuard {
    id: [u8; 16],
    used: BTreeSet<Vec<u8>>,
}
pub(crate) struct AuthorizationReplayGuardSnapshot {
    id: [u8; 16],
    used: BTreeSet<Vec<u8>>,
}

impl AuthorizationReplayGuard {
    pub(crate) fn new(id: [u8; 16]) -> Self {
        Self {
            id,
            used: BTreeSet::new(),
        }
    }
    pub(crate) fn id(&self) -> [u8; 16] {
        self.id
    }
    pub(crate) fn snapshot(&self) -> AuthorizationReplayGuardSnapshot {
        AuthorizationReplayGuardSnapshot {
            id: self.id,
            used: self.used.clone(),
        }
    }
    pub(crate) fn reopen(snapshot: AuthorizationReplayGuardSnapshot) -> Self {
        Self {
            id: snapshot.id,
            used: snapshot.used,
        }
    }
    fn record_use(&mut self, key: Vec<u8>) -> Result<(), ProcessContractError> {
        if !self.used.insert(key) {
            Err(ProcessContractError::CapabilityInvalid)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn issue_capability(
    id: ProcessCapabilityId,
    replay_guard: &AuthorizationReplayGuard,
    intent: &ProcessIntentV1,
    expires: u64,
    revision: u64,
    epoch: u64,
) -> ProcessCapabilityV1 {
    ProcessCapabilityV1 {
        id,
        replay_guard_id: replay_guard.id,
        digest: intent.digest(),
        binding: intent.binding().clone(),
        approval: intent.approval().clone(),
        expires,
        revision,
        epoch,
    }
}

pub(crate) fn approval_scope(intent: &ProcessIntentV1) -> ApprovalScopeV1 {
    ApprovalScopeV1 {
        digest: intent.digest(),
        binding: intent.binding().clone(),
    }
}

pub(crate) fn approve(
    intent: &ProcessIntentV1,
    scope: ApprovalScopeV1,
    approver: ApproverId,
    expires: u64,
    revision: u64,
    epoch: u64,
    approved: bool,
) -> ProcessApprovalV1 {
    ProcessApprovalV1 {
        id: intent.approval().clone(),
        digest: intent.digest(),
        binding: intent.binding().clone(),
        scope,
        approver,
        decision: if approved {
            Decision::Approved
        } else {
            Decision::Rejected
        },
        expires,
        revision,
        epoch,
    }
}

pub(crate) fn validate_authorization(
    intent: ProcessIntentV1,
    capability: Option<&ProcessCapabilityV1>,
    approval: Option<&ProcessApprovalV1>,
    current: &CurrentProcessContextV1,
    replay_guard: &mut AuthorizationReplayGuard,
    now: u64,
) -> Result<ValidatedProcessIntentV1, ProcessContractError> {
    let capability = capability.ok_or(ProcessContractError::CapabilityInvalid)?;
    if capability.replay_guard_id != replay_guard.id
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
    if approval.id != *intent.approval()
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
    validate_current_context(current, &intent)?;
    replay_guard.record_use(authorization_replay_key(capability, approval, &intent))?;
    Ok(ValidatedProcessIntentV1 { intent })
}

pub(crate) fn authorization_replay_key(
    capability: &ProcessCapabilityV1,
    approval: &ProcessApprovalV1,
    intent: &ProcessIntentV1,
) -> Vec<u8> {
    let mut key = Vec::new();
    let binding = binding_bytes(&capability.binding);
    for value in [
        capability.replay_guard_id.as_slice(),
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
