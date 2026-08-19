#[tokio::test]
async fn not_committed_reconcile_never_resends_in_the_same_invocation() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000801").expect("project");
    let server = tokio::spawn(async move {
        let mut paths = Vec::new();
        for (status, body) in [
            (202, format!(r#"{{"projectId":"{project}","newVersion":1}}"#)),
            (200, r#"{"disposition":"not_committed_retryable"}"#.into()),
            (202, format!(r#"{{"projectId":"{project}","newVersion":1}}"#)),
            (200, format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{project}","newVersion":1}}}}"#)),
        ] {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut request = [0; 4096];
            let count = stream.read(&mut request).await.expect("read");
            paths.push(String::from_utf8_lossy(&request[..count]).into_owned());
            let response = format!("HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            stream.write_all(response.as_bytes()).await.expect("response");
        }
        paths
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), reconcile_client(&origin)).expect("core");
    let request = MutationRequest::create_project(project, "Project".into()).expect("request");
    let retry = request.clone();
    let lease = core.prepare_mutation(request).await.expect("prepare");
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::RuntimeUnavailable)));
    let recovered = core.prepare_mutation(retry).await.expect("recovered");
    assert_eq!(recovered.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::Retryable);
    assert!(matches!(core.dispatch_prepared_mutation(recovered).await, Ok(MutationDispatchResult::Project(_))));
    let paths = server.await.expect("server");
    assert!(paths[0].starts_with("POST /v1/projects HTTP/1.1"));
    assert!(paths[1].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(paths[2].starts_with("POST /v1/projects HTTP/1.1"));
    assert!(paths[3].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}

#[tokio::test]
async fn indeterminate_reissue_is_reconcile_only() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request");
        let mut request = [0; 4096];
        let count = stream.read(&mut request).await.expect("read");
        let request = String::from_utf8_lossy(&request[..count]).into_owned();
        let body = r#"{"disposition":"indeterminate"}"#;
        let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        stream.write_all(response.as_bytes()).await.expect("response");
        request
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), reconcile_client(&origin)).expect("core");
    let mut lease = core.prepare_mutation(MutationRequest::create_project(CanonicalId::now_v7(), "Project".into()).expect("request")).await.expect("prepare");
    core.transition_v7_under_operation(&mut lease, runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 }).expect("dispatching");
    core.transition_v7_under_operation(&mut lease, runne_local_store::V7MutationTransition::Indeterminate { timestamp: 2 }).expect("indeterminate");
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::RuntimeUnavailable)));
    assert!(server.await.expect("server").starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}

#[tokio::test]
async fn reconciliation_conflict_closes_manual_before_any_future_network_call() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("request");
        let mut request = [0; 4096];
        let count = stream.read(&mut request).await.expect("read");
        assert!(String::from_utf8_lossy(&request[..count]).starts_with("POST /v1/commands/reconcile HTTP/1.1"));
        let request_id = "018f2e3a-7000-7000-8000-000000000899";
        let body = format!(r#"{{"code":"command_conflict","requestId":"{request_id}"}}"#);
        let response = format!("HTTP/1.1 409 Conflict\r\nx-request-id: {request_id}\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        stream.write_all(response.as_bytes()).await.expect("response");
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(&directory.path().join("profile.sqlite3"), reconcile_client(&origin)).expect("core");
    let request = MutationRequest::create_project(CanonicalId::now_v7(), "Project".into()).expect("request");
    let retry = request.clone();
    let mut lease = core.prepare_mutation(request).await.expect("prepare");
    core.transition_v7_under_operation(&mut lease, runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 }).expect("dispatching");
    core.transition_v7_under_operation(&mut lease, runne_local_store::V7MutationTransition::Indeterminate { timestamp: 2 }).expect("indeterminate");
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::MutationUnavailable)));
    server.await.expect("server");
    let manual = core.prepare_mutation(retry).await.expect("manual record");
    assert_eq!(manual.anchored_record.disposition(), runne_local_store::ClientMutationDisposition::ManualResolution);
    assert!(matches!(core.dispatch_prepared_mutation(manual).await, Err(AppCoreError::MutationUnavailable)));
}

#[tokio::test]
async fn recovery_rebuilds_only_same_durable_nonterminal_evidence() {
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let profile = [0x41; 32];
    let secure = std::sync::Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(profile),
    );
    let core = AppCore::open_with_test_runtime_secure(
        &path,
        mutation_test_client("authority-recover", "lineage-recover", 1),
        secure.clone(),
        profile,
    )
    .expect("core");
    let mut lease = core
        .prepare_mutation(
            MutationRequest::create_project(CanonicalId::now_v7(), "Project".into())
                .expect("request"),
        )
        .await
        .expect("prepare");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatching");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Indeterminate { timestamp: 2 },
    )
    .expect("reconciling");
    drop(core);

    let resumed = AppCore::open_with_test_runtime_secure(
        &path,
        mutation_test_client("authority-recover", "lineage-recover", 2),
        secure.clone(),
        profile,
    )
    .expect("resumed");
    let recovered = resumed.recover_anchored_mutations_v7().await.expect("recover");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].anchored_record.disposition(), runne_local_store::ClientMutationDisposition::Reconciling);
    drop(resumed);

    let changed = AppCore::open_with_test_runtime_secure(
        &path,
        mutation_test_client("other-authority", "lineage-recover", 3),
        secure,
        profile,
    )
    .expect("changed");
    assert!(changed.recover_anchored_mutations_v7().await.expect("recover").is_empty());
}

#[tokio::test]
async fn restart_closes_carrierless_prepared_bind_and_open_without_a_mutation_post() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(
        listener,
        vec![WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false))],
        1,
    ));
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let profile = [0x85; 32];
    let secure: std::sync::Arc<dyn runne_secure_store::SecureStore> = std::sync::Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(profile),
    );
    let core = AppCore::open_bundled_anchored(&path, secure.clone(), profile).expect("core");
    let start = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(start, protected_workspace_client(&origin))
        .await
        .expect("install");
    core.prepare_open_selected_workspace(
        WORKSPACE_ID.parse().expect("workspace"),
        1,
        protected_admission(),
    )
    .await
    .expect("prepare composite");
    drop(core);

    let resumed = AppCore::open_bundled_anchored(&path, secure, profile).expect("resumed");
    let restart = resumed.begin_bundled_runtime_start().await.expect("restart");
    resumed
        .install_bundled_runtime_client(restart, protected_workspace_client(&origin))
        .await
        .expect("reinstall");
    assert_eq!(resumed.runtime_availability().expect("state"), RuntimeAvailability::Live);
    assert!(resumed.recover_anchored_mutations_v7().await.expect("closed").is_empty());
    let requests = server.await.expect("server");
    assert!(requests[0].starts_with("GET /v1/workspaces/"));
    assert!(requests.iter().all(|request| !request.contains("/root-bindings")));
}

#[tokio::test]
async fn restart_retryable_resends_once_then_blocks_live_until_the_exhausted_record_closes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000811").expect("project");
    let server = tokio::spawn(async move {
        let mut paths = Vec::new();
        for (status, body) in [
            (202, format!(r#"{{"projectId":"{project}","newVersion":1}}"#)),
            (200, r#"{"disposition":"not_committed_retryable"}"#.into()),
        ] {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut request = [0; 4096];
            let count = stream.read(&mut request).await.expect("read");
            paths.push(String::from_utf8_lossy(&request[..count]).into_owned());
            let response = format!("HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            stream.write_all(response.as_bytes()).await.expect("response");
        }
        paths
    });
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let profile = [0x87; 32];
    let secure: std::sync::Arc<dyn runne_secure_store::SecureStore> = std::sync::Arc::new(
        runne_secure_store::test_support::DeterministicSecureStore::new(profile),
    );
    let core = AppCore::open_bundled_anchored(&path, secure.clone(), profile).expect("core");
    let initial = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(initial, protected_workspace_client(&origin))
        .await
        .expect("installed");
    let mut lease = core
        .prepare_mutation(MutationRequest::create_project(project, "Project".into()).expect("request"))
        .await
        .expect("prepared");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::Dispatching { timestamp: 1 },
    )
    .expect("dispatching");
    core.transition_v7_under_operation(
        &mut lease,
        runne_local_store::V7MutationTransition::NotCommittedRetryable { timestamp: 2 },
    )
    .expect("retryable");
    drop(core);

    let resumed = AppCore::open_bundled_anchored(&path, secure, profile).expect("resumed");
    let restart = resumed.begin_bundled_runtime_start().await.expect("restart");
    assert!(matches!(
        resumed.install_bundled_runtime_client(restart, protected_workspace_client(&origin)).await,
        Err(AppCoreError::RuntimeUnavailable)
    ));
    assert_eq!(resumed.runtime_availability().expect("closed"), RuntimeAvailability::Reconnecting);
    let exhausted = resumed.begin_bundled_runtime_restart().await.expect("exhausted restart");
    resumed.install_bundled_runtime_client(exhausted, protected_workspace_client(&origin))
        .await
        .expect("manual close admits live");
    assert_eq!(resumed.runtime_availability().expect("live"), RuntimeAvailability::Live);
    let paths = server.await.expect("server");
    assert_eq!(paths.len(), 2);
    assert!(paths[0].starts_with("POST /v1/projects HTTP/1.1"));
    assert!(paths[1].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}
