use super::*;

pub(super) async fn deny_read(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    watch: &std::fs::File,
    created: &std::path::Path,
) {
    let approval = wait_approval(client, task, database, runtime_root).await;
    let ack = decide(
        client,
        &approval,
        runne_runtime_client::ApprovalDecisionDto::Deny,
        "deny",
    )
    .await
    .expect("public denial accepted");
    assert_eq!(ack.state(), runne_runtime_client::ApprovalStateDto::Denied);
    assert_eq!(
        wait_terminal(client, task, database, runtime_root).await,
        runne_runtime_client::TaskRunState::Failed,
        "durable denial fails the TaskRun"
    );
    database::assert_failure_projection(database, task);
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    assert_eq!(database::invocation_count(database, task), 1);
    assert_eq!(database::invocation_state(database, task), "denied");
    assert_eq!(database::tool_budget_effects_used(database, task), Some(0));
    assert_eq!(database::release_intent_count(database, task), 0);
    assert_eq!(database::managed_area_launch_count(database, task), 0);
    assert_eq!(database::result_count(database, task), 0);
    assert_eq!(read_watch(watch), 0, "denied read never opened target");
    assert!(!created.exists(), "denied workflow never created output");
    println!("PASS: D2 public denial persisted without native effect");
}

pub(super) async fn stale_approval(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    watch: &std::fs::File,
    created: &std::path::Path,
) {
    let approval = wait_approval(client, task, database, runtime_root).await;
    let stale = make_decision(
        &approval,
        approval.request_version().saturating_add(1),
        runne_runtime_client::ApprovalDecisionDto::Approve,
        "stale",
    );
    assert!(client.decide_approval(stale).await.is_err());
    assert_eq!(
        client
            .get_approval(approval.approval_id())
            .await
            .expect("stale decision leaves pending approval")
            .state(),
        runne_runtime_client::ApprovalStateDto::Pending
    );
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    assert_eq!(database::invocation_state(database, task), "proposed");
    let ack = decide(
        client,
        &approval,
        runne_runtime_client::ApprovalDecisionDto::Deny,
        "cleanup",
    )
    .await
    .expect("clean up stale test with a real denial");
    assert_eq!(ack.state(), runne_runtime_client::ApprovalStateDto::Denied);
    assert_eq!(
        wait_terminal(client, task, database, runtime_root).await,
        runne_runtime_client::TaskRunState::Failed
    );
    database::assert_failure_projection(database, task);
    assert_eq!(database::tool_budget_effects_used(database, task), Some(0));
    assert_eq!(database::release_intent_count(database, task), 0);
    assert_eq!(database::managed_area_launch_count(database, task), 0);
    assert_eq!(database::invocation_state(database, task), "denied");
    assert_eq!(
        read_watch(watch),
        0,
        "stale and denied requests never opened target"
    );
    assert!(
        !created.exists(),
        "stale and denied requests never created output"
    );
    println!("PASS: D2 stale approval version rejected; valid denial had no effect");
}

pub(super) async fn wait_approval(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) -> runne_runtime_client::ApprovalSummaryDto {
    let until = tokio::time::Instant::now() + Duration::from_secs(35);
    loop {
        if let Some(row) = client
            .list_pending_approvals()
            .await
            .expect("public pending approvals")
            .into_iter()
            .find(|row| row.task_run_id() == task)
        {
            return row;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "approval timeout: {}",
            diagnostic(database, task, runtime_root)
        );
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

pub(super) async fn decide(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    approval: &runne_runtime_client::ApprovalSummaryDto,
    decision: runne_runtime_client::ApprovalDecisionDto,
    label: &str,
) -> Result<
    runne_runtime_client::ApprovalDecisionAcknowledgementDto,
    runne_runtime_client::RuntimeApiError,
> {
    client
        .decide_approval(make_decision(
            approval,
            approval.request_version(),
            decision,
            label,
        ))
        .await
}

fn make_decision(
    approval: &runne_runtime_client::ApprovalSummaryDto,
    version: u64,
    decision: runne_runtime_client::ApprovalDecisionDto,
    label: &str,
) -> runne_runtime_client::ApprovalDecisionRequest {
    runne_runtime_client::ApprovalDecisionRequest::new(
        runne_runtime_client::CommandIdentity::new(
            runne_runtime_client::CanonicalId::now_v7(),
            format!("d2-fault-{label}-{}", uuid::Uuid::now_v7()),
        )
        .expect("approval test identity"),
        approval.approval_id(),
        version,
        decision,
        *approval.action_digest(),
        approval.policy_revision(),
        1,
    )
    .expect("approval test request")
}

pub(crate) async fn wait_terminal(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
) -> runne_runtime_client::TaskRunState {
    let until = tokio::time::Instant::now() + Duration::from_secs(40);
    loop {
        let state = client
            .get_task_run(task)
            .await
            .expect("read fault TaskRun")
            .state();
        if matches!(
            state,
            runne_runtime_client::TaskRunState::Failed
                | runne_runtime_client::TaskRunState::PolicyDenied
                | runne_runtime_client::TaskRunState::Unrecoverable
        ) {
            return state;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "TaskRun did not stop: {}",
            diagnostic(database, task, runtime_root)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
