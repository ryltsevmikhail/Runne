#[tokio::test]
async fn restart_indeterminate_reconciles_only_and_never_reaches_live() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000812").expect("project");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("reconcile");
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).await.expect("read");
        let request = String::from_utf8_lossy(&bytes[..count]).into_owned();
        let body = r#"{"disposition":"indeterminate"}"#;
        let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        stream.write_all(response.as_bytes()).await.expect("response");
        request
    });
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let profile = [0x88; 32];
    let secure: std::sync::Arc<dyn gocode_secure_store::SecureStore> = std::sync::Arc::new(
        gocode_secure_store::test_support::DeterministicSecureStore::new(profile),
    );
    let core = AppCore::open_bundled_anchored(&path, secure.clone(), profile).expect("core");
    let start = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(start, protected_workspace_client(&origin))
        .await
        .expect("installed");
    let mut lease = core
        .prepare_mutation(MutationRequest::create_project(project, "Project".into()).expect("request"))
        .await
        .expect("prepared");
    core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Dispatching { timestamp: 1 }).expect("dispatching");
    core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Indeterminate { timestamp: 2 }).expect("reconciling");
    drop(core);
    let resumed = AppCore::open_bundled_anchored(&path, secure, profile).expect("resumed");
    let restart = resumed.begin_bundled_runtime_start().await.expect("restart");
    assert!(matches!(resumed.install_bundled_runtime_client(restart, protected_workspace_client(&origin)).await, Err(AppCoreError::RuntimeUnavailable)));
    assert_eq!(resumed.runtime_availability().expect("closed"), RuntimeAvailability::Reconnecting);
    let request = server.await.expect("server");
    assert!(request.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(!request.contains("POST /v1/projects"));
}

#[tokio::test]
async fn restart_durable_reconciliation_reaches_live_without_a_mutation_post() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000813").expect("project");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("reconcile");
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).await.expect("read");
        let request = String::from_utf8_lossy(&bytes[..count]).into_owned();
        let body = format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{project}","newVersion":1}}}}"#);
        let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        stream.write_all(response.as_bytes()).await.expect("response");
        request
    });
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let profile = [0x89; 32];
    let secure: std::sync::Arc<dyn gocode_secure_store::SecureStore> = std::sync::Arc::new(gocode_secure_store::test_support::DeterministicSecureStore::new(profile));
    let core = AppCore::open_bundled_anchored(&path, secure.clone(), profile).expect("core");
    let start = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(start, protected_workspace_client(&origin)).await.expect("installed");
    let mut lease = core.prepare_mutation(MutationRequest::create_project(project, "Project".into()).expect("request")).await.expect("prepared");
    core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Dispatching { timestamp: 1 }).expect("dispatching");
    core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Indeterminate { timestamp: 2 }).expect("reconciling");
    drop(core);
    let resumed = AppCore::open_bundled_anchored(&path, secure, profile).expect("resumed");
    let restart = resumed.begin_bundled_runtime_start().await.expect("restart");
    assert_eq!(resumed.install_bundled_runtime_client(restart, protected_workspace_client(&origin)).await.expect("live"), RuntimeAvailability::Live);
    assert_eq!(resumed.runtime_availability().expect("live"), RuntimeAvailability::Live);
    let request = server.await.expect("server");
    assert!(request.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(!request.contains("POST /v1/projects"));
}

#[tokio::test]
async fn aborted_recovery_install_fences_client_and_resync_cannot_bypass_it() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let project = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000814").expect("project");
    let seen = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let server = {
        let seen = std::sync::Arc::clone(&seen);
        let release = std::sync::Arc::clone(&release);
        tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("first reconcile");
            let mut bytes = [0; 4096];
            let count = first.read(&mut bytes).await.expect("first read");
            let first_request = String::from_utf8_lossy(&bytes[..count]).into_owned();
            seen.notify_one();
            release.notified().await;
            drop(first);
            let (mut second, _) = listener.accept().await.expect("second reconcile");
            let count = second.read(&mut bytes).await.expect("second read");
            let second_request = String::from_utf8_lossy(&bytes[..count]).into_owned();
            let body = format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{project}","newVersion":1}}}}"#);
            let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            second.write_all(response.as_bytes()).await.expect("second response");
            (first_request, second_request)
        })
    };
    let directory = tempfile::tempdir().expect("directory");
    let path = directory.path().join("profile.sqlite3");
    let profile = [0x8a; 32];
    let secure: std::sync::Arc<dyn gocode_secure_store::SecureStore> = std::sync::Arc::new(gocode_secure_store::test_support::DeterministicSecureStore::new(profile));
    let core = std::sync::Arc::new(AppCore::open_bundled_anchored(&path, secure, profile).expect("core"));
    let start = core.begin_bundled_runtime_start().await.expect("start");
    core.install_bundled_runtime_client(start, protected_workspace_client(&origin)).await.expect("installed");
    let mut lease = core.prepare_mutation(MutationRequest::create_project(project, "Project".into()).expect("request")).await.expect("prepared");
    core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Dispatching { timestamp: 1 }).expect("dispatching");
    core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Indeterminate { timestamp: 2 }).expect("reconciling");
    let restart = core.begin_bundled_runtime_restart().await.expect("restart");
    let installing = {
        let core = std::sync::Arc::clone(&core);
        let client = protected_workspace_client(&origin);
        tokio::spawn(async move { core.install_bundled_runtime_client(restart, client).await })
    };
    seen.notified().await;
    installing.abort();
    assert!(installing.await.expect_err("cancelled").is_cancelled());
    assert_eq!(core.runtime_availability().expect("fenced"), RuntimeAvailability::Reconnecting);
    assert!(core.runtime_client().expect("client state").is_none());
    assert_eq!(core.runtime_lifecycle().expect("degraded"), RuntimeLifecycleStatus::Degraded);
    assert!(matches!(core.resync_project_conversation(1).await, Err(AppCoreError::RuntimeUnavailable)));
    release.notify_one();
    let next = core.begin_bundled_runtime_restart().await.expect("next restart");
    assert_eq!(core.install_bundled_runtime_client(next, protected_workspace_client(&origin)).await.expect("recovered"), RuntimeAvailability::Live);
    let (first, second) = server.await.expect("server");
    assert!(first.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(second.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}
