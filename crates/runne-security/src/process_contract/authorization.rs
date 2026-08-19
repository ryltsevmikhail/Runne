//! Crate-private capability authorization issuance and durable replay rejection.
//!
//! This guard rejects authorization replay only. A validated witness is a prerequisite and does
//! not authorize an external effect; outer effect admission remains the sole effect authority.
#![allow(dead_code)]

use std::collections::BTreeSet;

use super::context::CurrentProcessContextV1;
use super::{
    ApprovalId, ApproverId, ProcessCapabilityId, ProcessContractError, ProcessIdentityBindingV1,
    ProcessIntentDigestV1, ProcessIntentV1,
};

mod validation;

pub(crate) use validation::{preflight_authorization, validate_authorization};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Decision {
    Approved,
    Rejected,
}

/// Opaque consume-only approval contract.
pub struct ProcessApprovalV1 {
    id: ApprovalId,
    domain: AuthorizationReplayDomainV1,
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
    domain: AuthorizationReplayDomainV1,
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AuthorizationReplayDomainV1 {
    legacy_seed: [u8; 16],
    authority_instance: u64,
}

impl AuthorizationReplayDomainV1 {
    pub(crate) const fn new(legacy_seed: [u8; 16], authority_instance: u64) -> Self {
        Self {
            legacy_seed,
            authority_instance,
        }
    }

    pub(crate) const fn authority_instance(&self) -> u64 {
        self.authority_instance
    }
}

impl From<[u8; 16]> for AuthorizationReplayDomainV1 {
    fn from(legacy_seed: [u8; 16]) -> Self {
        Self::new(legacy_seed, 0)
    }
}

impl ValidatedProcessIntentV1 {
    #[must_use]
    pub const fn intent(&self) -> &ProcessIntentV1 {
        &self.intent
    }
}

impl ProcessCapabilityV1 {
    /// Returns the stable opaque capability identifier for metadata-only correlation.
    #[must_use]
    pub const fn id_label(&self) -> [u8; 16] {
        *self.id.bytes()
    }
}

pub(crate) struct AuthorizationReplayGuard {
    domain: AuthorizationReplayDomainV1,
    used: BTreeSet<Vec<u8>>,
}

impl AuthorizationReplayGuard {
    pub(crate) fn new(domain: impl Into<AuthorizationReplayDomainV1>) -> Self {
        Self {
            domain: domain.into(),
            used: BTreeSet::new(),
        }
    }
    pub(crate) fn domain(&self) -> AuthorizationReplayDomainV1 {
        self.domain
    }
    #[cfg(test)]
    pub(crate) const fn id(&self) -> [u8; 16] {
        self.domain.legacy_seed
    }
    pub(super) fn record_use(&mut self, key: Vec<u8>) -> Result<(), ProcessContractError> {
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
        domain: replay_guard.domain(),
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

pub(crate) fn approve_bound(
    intent: &ProcessIntentV1,
    scope: ApprovalScopeV1,
    replay_guard: &AuthorizationReplayGuard,
    current: &CurrentProcessContextV1,
    expires: u64,
    approved: bool,
) -> ProcessApprovalV1 {
    ProcessApprovalV1 {
        id: intent.approval().clone(),
        domain: replay_guard.domain(),
        digest: intent.digest(),
        binding: intent.binding().clone(),
        scope,
        approver: current.approver.clone(),
        decision: if approved {
            Decision::Approved
        } else {
            Decision::Rejected
        },
        expires,
        revision: current.revision,
        epoch: current.epoch,
    }
}

#[cfg(test)]
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
        domain: AuthorizationReplayDomainV1::from([1; 16]),
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
