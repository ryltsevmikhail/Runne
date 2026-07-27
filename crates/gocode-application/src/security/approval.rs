//! Запросы и решения human approval без неявной выдачи authority.

use gocode_domain::{
    security::{AuthEpoch, CanonicalAction, NormalizedResource, PrincipalIdentity},
    timestamp::Timestamp,
};

use super::grant::{GrantConstraints, GrantScope};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApprovalId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub approval_id: ApprovalId,
    pub requester: PrincipalIdentity,
    pub action: CanonicalAction,
    pub resource: NormalizedResource,
    pub constraints: GrantConstraints,
    pub scope: GrantScope,
    pub intent_digest: [u8; 32],
    pub risk_summary: String,
    pub policy_revision: u64,
    pub auth_epoch: AuthEpoch,
    pub expires_at: Timestamp,
    pub correlation: String,
}

impl ApprovalRequest {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at < now
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub approval_id: ApprovalId,
    pub approver: PrincipalIdentity,
    pub outcome: ApprovalOutcome,
    pub reason: Option<String>,
    pub decided_at: Timestamp,
    pub auth_epoch: AuthEpoch,
}
