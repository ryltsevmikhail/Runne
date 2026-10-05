use super::*;

pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    watch: &std::fs::File,
    created: &std::path::Path,
) {
    let approval =
        super::super::positive::approval::wait_approval(client, task, None, database, runtime_root)
            .await;
    let expiry = u64::try_from(approval.expires_at()).expect("positive approval expiry");
    let now = unix_millis();
    assert!(
        expiry > now,
        "fixture observed a real unexpired pending approval"
    );
    assert!(expiry - now <= 180_000, "bounded native expiry scenario");
    wait_until(expiry).await;

    let expired = client
        .get_approval(approval.approval_id())
        .await
        .expect("read expired approval");
    assert_eq!(
        expired.state(),
        runne_runtime_client::ApprovalStateDto::Expired
    );
    let identity = runne_runtime_client::CommandIdentity::new(
        runne_runtime_client::CanonicalId::now_v7(),
        format!("d2-expired-approval-{}", uuid::Uuid::now_v7()),
    )
    .expect("late approval identity");
    let request = runne_runtime_client::ApprovalDecisionRequest::new(
        identity,
        approval.approval_id(),
        approval.request_version(),
        runne_runtime_client::ApprovalDecisionDto::Approve,
        *approval.action_digest(),
        approval.policy_revision(),
        1,
    )
    .expect("late decision request");
    assert!(
        client.decide_approval(request).await.is_err(),
        "expired approval cannot be revived"
    );
    assert_eq!(
        super::flows::wait_terminal(client, task, database, runtime_root).await,
        runne_runtime_client::TaskRunState::Failed
    );
    super::database::assert_failure_projection(database, task);
    assert_eq!(super::database::release_intent_count(database, task), 0);
    assert_eq!(
        super::database::managed_area_launch_count(database, task),
        0
    );
    assert_eq!(read_watch(watch), 0);
    assert!(!created.exists());
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    eprintln!("PASS: real approval expiry rejected late approval with no native effect");
}

async fn wait_until(expiry_ms: u64) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(190);
    while unix_millis() <= expiry_ms {
        assert!(
            tokio::time::Instant::now() < deadline,
            "approval did not reach persisted expiry"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}
