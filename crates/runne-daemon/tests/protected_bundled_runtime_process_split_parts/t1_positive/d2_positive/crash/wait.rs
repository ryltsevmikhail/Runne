pub(super) async fn wait_failed(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    root: &std::path::Path,
) -> runne_runtime_client::TaskRunSnapshot {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(40);
    loop {
        let snapshot = client
            .get_task_run(task)
            .await
            .expect("read recovered TaskRun");
        if snapshot.state() == runne_runtime_client::TaskRunState::Failed {
            return snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "D2 recovery did not terminalize stage: {}",
            super::super::super::diagnostic::diagnostic(database, task, root)
        );
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
}

pub(super) async fn wait_cancelled(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    database: &std::path::Path,
    root: &std::path::Path,
) -> runne_runtime_client::TaskRunSnapshot {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(40);
    loop {
        let snapshot = client
            .get_task_run(task)
            .await
            .expect("read cancelled TaskRun");
        if snapshot.state() == runne_runtime_client::TaskRunState::Cancelled {
            return snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "D2 cancellation recovery did not terminalize: {}",
            super::super::super::diagnostic::diagnostic(database, task, root)
        );
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
}
