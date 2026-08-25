//! Runtime boundary for authenticated, durable approval authority.

use runne_api::{
    ApprovalCommandContext, ApprovalCommandHostPort, ApprovalCreateCommand, ApprovalDecisionAck,
    ApprovalDecisionCommand, ApprovalHostError, ApprovalQueryContext, ApprovalQueryHostPort,
    ApprovalRequestHostPort, ApprovalSummary,
};
use runne_domain::id::ApprovalId;

/// Runtime-owned adapter that keeps approval authority behind the public host
/// contracts. The provider remains the single durable owner of state.
pub struct RuntimeApprovalHost<P> {
    provider: P,
}

impl<P> RuntimeApprovalHost<P> {
    /// Wraps one authoritative approval provider.
    #[must_use]
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P: ApprovalQueryHostPort> ApprovalQueryHostPort for RuntimeApprovalHost<P> {
    async fn list_pending_approvals(
        &self,
        context: ApprovalQueryContext,
    ) -> Result<Vec<ApprovalSummary>, ApprovalHostError> {
        self.provider.list_pending_approvals(context).await
    }

    async fn get_approval(
        &self,
        context: ApprovalQueryContext,
        approval_id: ApprovalId,
    ) -> Result<ApprovalSummary, ApprovalHostError> {
        self.provider.get_approval(context, approval_id).await
    }
}

impl<P: ApprovalCommandHostPort> ApprovalCommandHostPort for RuntimeApprovalHost<P> {
    async fn decide_approval(
        &self,
        context: ApprovalCommandContext,
        command: ApprovalDecisionCommand,
    ) -> Result<ApprovalDecisionAck, ApprovalHostError> {
        self.provider.decide_approval(context, command).await
    }
}

impl<P: ApprovalRequestHostPort> ApprovalRequestHostPort for RuntimeApprovalHost<P> {
    async fn create_pending_approval(
        &self,
        command: ApprovalCreateCommand,
    ) -> Result<ApprovalSummary, ApprovalHostError> {
        self.provider.create_pending_approval(command).await
    }
}
