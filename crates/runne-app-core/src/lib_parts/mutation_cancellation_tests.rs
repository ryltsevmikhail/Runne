#[tokio::test]
async fn cancellation_before_dispatch_transition_keeps_prepared_without_network() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let directory = tempfile::tempdir().expect("directory");
    let core = std::sync::Arc::new(
        AppCore::open_with_mock_runtime(
            &directory.path().join("profile.sqlite3"),
            adversarial_client(&origin),
        )
        .expect("core"),
    );
    let request = project_request();
    let retry = request.clone();
    core.mutation_test_hold_before_dispatch.store(true, std::sync::atomic::Ordering::Release);
    let reached = core.mutation_test_before_dispatch.notified();
    let lease = core.prepare_mutation(request).await.expect("prepare");
    let task = {
        let core = std::sync::Arc::clone(&core);
        tokio::spawn(async move { core.dispatch_prepared_mutation(lease).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), reached)
        .await
        .expect("dispatch hook");
    task.abort();
    let _ = task.await;
    assert_eq!(
        core.prepare_mutation(retry)
            .await
            .expect("record")
            .anchored_record
            .disposition(),
        runne_local_store::ClientMutationDisposition::Prepared,
    );
    assert!(tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept()).await.is_err());
}

#[tokio::test]
async fn cancellation_after_possible_send_reconciles_without_second_mutation() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000801").expect("project");
    let seen = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let server = {
        let seen = std::sync::Arc::clone(&seen);
        let release = std::sync::Arc::clone(&release);
        tokio::spawn(async move {
            let (mut mutation, _) = listener.accept().await.expect("mutation");
            let mut bytes = [0; 8192];
            let used = mutation.read(&mut bytes).await.expect("read mutation");
            let first = String::from_utf8_lossy(&bytes[..used]).into_owned();
            seen.notify_one();
            release.notified().await;
            drop(mutation);
            let (mut reconcile, _) = listener.accept().await.expect("reconcile");
            let used = reconcile.read(&mut bytes).await.expect("read reconcile");
            let second = String::from_utf8_lossy(&bytes[..used]).into_owned();
            reconciled_project(&mut reconcile, project, 1).await;
            (first, second)
        })
    };
    let directory = tempfile::tempdir().expect("directory");
    let core = std::sync::Arc::new(AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), adversarial_client(&origin)).expect("core"));
    let request = project_request();
    let retry = request.clone();
    let lease = core.prepare_mutation(request).await.expect("prepare");
    let task = { let core = std::sync::Arc::clone(&core); tokio::spawn(async move { core.dispatch_prepared_mutation(lease).await }) };
    tokio::time::timeout(std::time::Duration::from_secs(2), seen.notified()).await.expect("mutation seen");
    task.abort();
    let _ = task.await;
    release.notify_one();
    let result = core.dispatch_prepared_mutation(core.prepare_mutation(retry).await.expect("recovered")).await;
    assert!(matches!(result, Ok(MutationDispatchResult::Project(_))));
    let (first, second) = server.await.expect("server");
    assert!(first.starts_with("POST /v1/projects HTTP/1.1"));
    assert!(second.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}

#[tokio::test]
async fn concurrent_duplicate_dispatches_emit_one_mutation_and_one_legal_terminal() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let seen = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let server = {
        let seen = std::sync::Arc::clone(&seen);
        let release = std::sync::Arc::clone(&release);
        tokio::spawn(async move {
            let (mut mutation, _) = listener.accept().await.expect("mutation");
            let mut bytes = [0; 8192];
            let used = mutation.read(&mut bytes).await.expect("read mutation");
            let first = String::from_utf8_lossy(&bytes[..used]).into_owned();
            seen.notify_one();
            release.notified().await;
            project_ack(&mut mutation, CanonicalId::parse("018f2e3a-7000-7000-8000-000000000801").expect("project"), 1).await;
            let (mut reconcile, _) = listener.accept().await.expect("reconcile");
            let used = reconcile.read(&mut bytes).await.expect("read reconcile");
            let second = String::from_utf8_lossy(&bytes[..used]).into_owned();
            reconciled_project(&mut reconcile, CanonicalId::parse("018f2e3a-7000-7000-8000-000000000801").expect("project"), 1).await;
            (first, second)
        })
    };
    let directory = tempfile::tempdir().expect("directory");
    let core = std::sync::Arc::new(AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), adversarial_client(&origin)).expect("core"));
    let request = project_request();
    let first = core.prepare_mutation(request.clone()).await.expect("first");
    let second = core.prepare_mutation(request.clone()).await.expect("second");
    let left = { let core = std::sync::Arc::clone(&core); tokio::spawn(async move { core.dispatch_prepared_mutation(first).await }) };
    tokio::time::timeout(std::time::Duration::from_secs(2), seen.notified()).await.expect("mutation seen");
    let right = { let core = std::sync::Arc::clone(&core); tokio::spawn(async move { core.dispatch_prepared_mutation(second).await }) };
    release.notify_one();
    assert!(matches!(left.await.expect("left"), Ok(MutationDispatchResult::Project(_))));
    assert!(matches!(right.await.expect("right"), Err(AppCoreError::MutationUnavailable)));
    let (mutation, reconcile) = server.await.expect("server");
    assert!(mutation.starts_with("POST /v1/projects HTTP/1.1"));
    assert!(reconcile.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert_eq!(core.prepare_mutation(request).await.expect("terminal").anchored_record.disposition(), runne_local_store::ClientMutationDisposition::CanonicalOutcome);
}
