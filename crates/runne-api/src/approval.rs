//! Runtime-owned approval query and decision contracts.

use runne_domain::id::{ApprovalId, AttemptId, InvocationId, TaskRunId};

mod create;
pub use create::{ApprovalCreateCommand, ApprovalRequestHostPort};

const MAX_DISPLAY_BYTES: usize = 4096;

/// Safe state of one runtime-owned approval request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

impl ApprovalState {
    /// Returns the stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Decision that a runtime-authorized approver may submit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

impl ApprovalDecision {
    /// Returns the stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

/// Validation failures for renderer-safe approval summaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalValidationError {
    InvalidDisplayData,
    InvalidVersion,
    InvalidExpiry,
    MissingActionDigest,
    InvalidExpectedVersion,
    InvalidRendererGeneration,
}

/// Sanitized approval request. It contains no secret or protected payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalSummary {
    approval_id: ApprovalId,
    task_run_id: TaskRunId,
    attempt_id: Option<AttemptId>,
    invocation_id: InvocationId,
    action: String,
    resource: String,
    action_digest: [u8; 32],
    policy_revision: u64,
    request_version: u64,
    expires_at: i64,
    risk_summary: String,
    state: ApprovalState,
}

impl ApprovalSummary {
    /// Rehydrates a validated projection with its durable terminal state.
    pub fn with_state(mut self, state: ApprovalState) -> Self {
        self.state = state;
        self
    }

    /// Validates and creates one pending approval summary.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        approval_id: ApprovalId,
        task_run_id: TaskRunId,
        attempt_id: Option<AttemptId>,
        invocation_id: InvocationId,
        action: impl Into<String>,
        resource: impl Into<String>,
        action_digest: [u8; 32],
        policy_revision: u64,
        request_version: u64,
        expires_at: i64,
        risk_summary: impl Into<String>,
    ) -> Result<Self, ApprovalValidationError> {
        let action = action.into();
        let resource = resource.into();
        let risk_summary = risk_summary.into();
        if !valid_display(&action) || !valid_display(&resource) || !valid_display(&risk_summary) {
            return Err(ApprovalValidationError::InvalidDisplayData);
        }
        if policy_revision == 0 || request_version == 0 {
            return Err(ApprovalValidationError::InvalidVersion);
        }
        if expires_at <= 0 {
            return Err(ApprovalValidationError::InvalidExpiry);
        }
        if action_digest == [0; 32] {
            return Err(ApprovalValidationError::MissingActionDigest);
        }
        Ok(Self {
            approval_id,
            task_run_id,
            attempt_id,
            invocation_id,
            action,
            resource,
            action_digest,
            policy_revision,
            request_version,
            expires_at,
            risk_summary,
            state: ApprovalState::Pending,
        })
    }

    /// Returns the approval identity.
    #[must_use]
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }
    /// Returns the owning TaskRun identity.
    #[must_use]
    pub const fn task_run_id(&self) -> TaskRunId {
        self.task_run_id
    }
    /// Returns the active attempt bound to the approval, when present.
    #[must_use]
    pub const fn attempt_id(&self) -> Option<AttemptId> {
        self.attempt_id
    }
    /// Returns the runtime invocation bound to the approval.
    #[must_use]
    pub const fn invocation_id(&self) -> InvocationId {
        self.invocation_id
    }
    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> ApprovalState {
        self.state
    }
    /// Returns whether the runtime currently permits a decision attempt.
    #[must_use]
    pub const fn requires_decision(&self) -> bool {
        matches!(self.state, ApprovalState::Pending)
    }
    /// Returns the expected request version for a decision.
    #[must_use]
    pub const fn request_version(&self) -> u64 {
        self.request_version
    }
    /// Returns the policy revision bound to the request.
    #[must_use]
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    /// Returns the expiry timestamp in Unix milliseconds.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
    /// Returns the policy-bound action digest.
    #[must_use]
    pub const fn action_digest(&self) -> &[u8; 32] {
        &self.action_digest
    }
    /// Returns the safe action label.
    #[must_use]
    pub const fn action(&self) -> &str {
        self.action.as_str()
    }
    /// Returns the normalized safe resource label.
    #[must_use]
    pub const fn resource(&self) -> &str {
        self.resource.as_str()
    }
    /// Returns the bounded risk summary.
    #[must_use]
    pub const fn risk_summary(&self) -> &str {
        self.risk_summary.as_str()
    }
}

fn valid_display(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_DISPLAY_BYTES && !value.chars().any(char::is_control)
}

include!("approval/host.rs");
