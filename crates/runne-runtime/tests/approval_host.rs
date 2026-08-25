use runne_api::{
    ApiPrincipalId, ApprovalCommandContext, ApprovalCommandHostPort, ApprovalCreateCommand,
    ApprovalDecisionAck, ApprovalDecisionCommand, ApprovalHostError, ApprovalQueryContext,
    ApprovalQueryHostPort, ApprovalRequestHostPort, ApprovalState, ApprovalSummary,
};
use runne_domain::id::{ApprovalId, TaskRunId};
use runne_runtime::RuntimeApprovalHost;

struct Provider;

impl ApprovalQueryHostPort for Provider {
    async fn list_pending_approvals(
        &self,
        _context: ApprovalQueryContext,
    ) -> Result<Vec<ApprovalSummary>, ApprovalHostError> {
        Ok(Vec::new())
    }

    async fn get_approval(
        &self,
        _context: ApprovalQueryContext,
        _approval_id: ApprovalId,
    ) -> Result<ApprovalSummary, ApprovalHostError> {
        Err(ApprovalHostError::NotFound)
    }
}

impl ApprovalCommandHostPort for Provider {
    async fn decide_approval(
        &self,
        _context: ApprovalCommandContext,
        _command: ApprovalDecisionCommand,
    ) -> Result<ApprovalDecisionAck, ApprovalHostError> {
        Err(ApprovalHostError::Unavailable)
    }
}

impl ApprovalRequestHostPort for Provider {
    async fn create_pending_approval(
        &self,
        _command: ApprovalCreateCommand,
    ) -> Result<ApprovalSummary, ApprovalHostError> {
        Err(ApprovalHostError::Unavailable)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_approval_host_delegates_authenticated_query() {
    let host = RuntimeApprovalHost::new(Provider);
    let result = host
        .list_pending_approvals(ApprovalQueryContext {
            principal: ApiPrincipalId::new("owner").unwrap(),
        })
        .await
        .unwrap();

    assert!(result.is_empty());
    let _ = ApprovalState::Pending;
    let _ = TaskRunId::from_bytes([
        0x01, 0x8f, 0x47, 0xa2, 0x4f, 0x8c, 0x7b, 0x52, 0x8c, 0x35, 0x7a, 0x3a, 0x14, 0xc2, 0xd9,
        0x71,
    ]);
}
