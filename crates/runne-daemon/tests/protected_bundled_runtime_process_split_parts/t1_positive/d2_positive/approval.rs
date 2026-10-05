use super::super::diagnostic::diagnostic;
use super::*;

pub(crate) async fn wait_approval(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    exclude: Option<runne_runtime_client::CanonicalId>,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) -> runne_runtime_client::ApprovalSummaryDto {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        if let Some(approval) = client
            .list_pending_approvals()
            .await
            .expect("read public pending approvals")
            .into_iter()
            .find(|row| row.task_run_id() == task && Some(row.approval_id()) != exclude)
        {
            assert!(approval.requires_decision());
            return approval;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "D2 approval did not become Pending: {}",
            diagnostic(database, task, runtime_root)
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

pub(super) async fn approve_twice(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    approval: &runne_runtime_client::ApprovalSummaryDto,
    label: &str,
) {
    let identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("d2-positive-{label}-approve-{}", uuid::Uuid::now_v7()),
    )
    .expect("human decision command identity");
    let decision = runne_runtime_client::ApprovalDecisionRequest::new(
        identity,
        approval.approval_id(),
        approval.request_version(),
        runne_runtime_client::ApprovalDecisionDto::Approve,
        *approval.action_digest(),
        approval.policy_revision(),
        1,
    )
    .expect("version-bound human approval");
    for _ in 0..2 {
        let ack = client
            .decide_approval(decision.clone())
            .await
            .expect("idempotent public approval decision");
        assert_eq!(ack.approval_id(), approval.approval_id());
        assert_eq!(
            ack.state(),
            runne_runtime_client::ApprovalStateDto::Approved
        );
    }
    assert_eq!(
        client
            .get_approval(approval.approval_id())
            .await
            .expect("re-read approved decision")
            .state(),
        runne_runtime_client::ApprovalStateDto::Approved
    );
}

pub(super) async fn deny_once(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    approval: &runne_runtime_client::ApprovalSummaryDto,
) {
    let identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("d2-deny-create-{}", uuid::Uuid::now_v7()),
    )
    .expect("human denial command identity");
    let decision = runne_runtime_client::ApprovalDecisionRequest::new(
        identity,
        approval.approval_id(),
        approval.request_version(),
        runne_runtime_client::ApprovalDecisionDto::Deny,
        *approval.action_digest(),
        approval.policy_revision(),
        1,
    )
    .expect("version-bound human denial");
    let ack = client
        .decide_approval(decision)
        .await
        .expect("public create denial");
    assert_eq!(ack.state(), runne_runtime_client::ApprovalStateDto::Denied);
    assert_eq!(
        client
            .get_approval(approval.approval_id())
            .await
            .expect("re-read denied approval")
            .state(),
        runne_runtime_client::ApprovalStateDto::Denied
    );
}
