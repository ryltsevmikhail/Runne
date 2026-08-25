use super::{
    ApprovalHostError, ApprovalId, ApprovalSummary, ApprovalValidationError, AttemptId,
    InvocationId, TaskRunId,
};
use crate::ApiPrincipalId;

/// Runtime-produced pending approval request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalCreateCommand {
    approval_id: ApprovalId,
    task_run_id: TaskRunId,
    attempt_id: Option<AttemptId>,
    invocation_id: InvocationId,
    principal: ApiPrincipalId,
    action: String,
    resource: String,
    action_digest: [u8; 32],
    policy_revision: u64,
    renderer_generation: u64,
    expires_at: i64,
    risk_summary: String,
}

impl ApprovalCreateCommand {
    /// Creates a validated runtime-owned approval request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        approval_id: ApprovalId,
        task_run_id: TaskRunId,
        attempt_id: Option<AttemptId>,
        invocation_id: InvocationId,
        principal: ApiPrincipalId,
        action: impl Into<String>,
        resource: impl Into<String>,
        action_digest: [u8; 32],
        policy_revision: u64,
        renderer_generation: u64,
        expires_at: i64,
        risk_summary: impl Into<String>,
    ) -> Result<Self, ApprovalValidationError> {
        let action = action.into();
        let resource = resource.into();
        let risk_summary = risk_summary.into();
        if !super::valid_display(&action)
            || !super::valid_display(&resource)
            || !super::valid_display(&risk_summary)
        {
            return Err(ApprovalValidationError::InvalidDisplayData);
        }
        if policy_revision == 0 {
            return Err(ApprovalValidationError::InvalidVersion);
        }
        if renderer_generation == 0 {
            return Err(ApprovalValidationError::InvalidRendererGeneration);
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
            principal,
            action,
            resource,
            action_digest,
            policy_revision,
            renderer_generation,
            expires_at,
            risk_summary,
        })
    }

    #[must_use]
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }
    #[must_use]
    pub const fn task_run_id(&self) -> TaskRunId {
        self.task_run_id
    }
    #[must_use]
    pub const fn attempt_id(&self) -> Option<AttemptId> {
        self.attempt_id
    }
    #[must_use]
    pub const fn invocation_id(&self) -> InvocationId {
        self.invocation_id
    }
    #[must_use]
    pub const fn principal(&self) -> &ApiPrincipalId {
        &self.principal
    }
    #[must_use]
    pub const fn action(&self) -> &str {
        self.action.as_str()
    }
    #[must_use]
    pub const fn resource(&self) -> &str {
        self.resource.as_str()
    }
    #[must_use]
    pub const fn action_digest(&self) -> &[u8; 32] {
        &self.action_digest
    }
    #[must_use]
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    #[must_use]
    pub const fn renderer_generation(&self) -> u64 {
        self.renderer_generation
    }
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
    #[must_use]
    pub const fn risk_summary(&self) -> &str {
        self.risk_summary.as_str()
    }
}

/// Runtime-only boundary used by provider/tool execution to enqueue approval.
pub trait ApprovalRequestHostPort: Send + Sync {
    fn create_pending_approval(
        &self,
        command: ApprovalCreateCommand,
    ) -> impl std::future::Future<Output = Result<ApprovalSummary, ApprovalHostError>> + Send;
}
