use runne_local_store::ProtectedDraftScope;
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn managed_draft_scope(principal: &str) -> ProtectedDraftScope {
    ProtectedDraftScope {
        lineage: "managed-lineage".into(),
        authority: "managed-authority".into(),
        principal: principal.into(),
        project_id: PROJECT.into(),
        workspace_id: WORKSPACE.into(),
    }
}

async fn delayed_workspace_server() -> (
    String,
    tokio::sync::oneshot::Receiver<String>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 8192];
        let used = stream.read(&mut bytes).await.unwrap();
        let request = String::from_utf8_lossy(&bytes[..used]).into_owned();
        let _ = request_tx.send(request);
        let _ = release_rx.await;
        let body = format!(
            r#"{{"workspaceId":"{WORKSPACE}","projectId":"{PROJECT}","displayName":"Workspace","version":1,"open":true}}"#
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (origin, request_rx, release_tx, server)
}

fn open_draft_core(
    path: &std::path::Path,
    origin: &str,
    profile: [u8; 32],
) -> (
    AppCore,
    Arc<dyn SecureStore>,
    runne_runtime_client::AuthenticatedRuntimeClient,
) {
    let secure: Arc<dyn SecureStore> =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile));
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        origin,
        mutation_test_client("managed-authority", "managed-lineage", 1)
            .session_info()
            .clone(),
    )
    .unwrap();
    let core =
        AppCore::open_with_test_runtime_secure(path, client.clone(), Arc::clone(&secure), profile)
            .unwrap();
    (core, secure, client)
}

fn seed_draft(
    core: &AppCore,
    secure: &dyn SecureStore,
    scope: &ProtectedDraftScope,
    profile_path: &std::path::Path,
) -> (String, Vec<u8>) {
    let store = core.store.lock().unwrap();
    let token = store
        .load_protected_draft(secure, scope)
        .unwrap()
        .scope_token;
    store
        .save_protected_draft(secure, scope, &token, 0, "synthetic saved draft")
        .unwrap();
    drop(store);
    let payload = rusqlite::Connection::open(draft_sidecar_path(profile_path))
        .unwrap()
        .query_row("SELECT payload FROM protected_drafts", [], |row| row.get(0))
        .unwrap();
    (token, payload)
}

fn draft_sidecar_path(profile_path: &std::path::Path) -> std::path::PathBuf {
    let mut path = profile_path.as_os_str().to_owned();
    path.push(".drafts.sqlite3");
    path.into()
}

#[tokio::test]
async fn managed_draft_roundtrip_scope_token_and_retry_safe_clear() {
    let submissions = Arc::new(AtomicUsize::new(0));
    let origin = managed_api_server(ManagedApiMock {
        submissions,
        task_run_ids: Arc::default(),
        fail_approvals: false,
        task_runs: json!([]),
        approvals: json!([]),
    })
    .await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let (core, _secure, client) = open_draft_core(&path, &origin, [0x91; 32]);
    let loaded = core
        .load_managed_task_draft(PROJECT, WORKSPACE)
        .await
        .unwrap();
    assert_eq!(loaded.revision, 0);
    assert_eq!(loaded.scope_token.len(), 64);
    let saved = core
        .save_managed_task_draft(PROJECT, WORKSPACE, &loaded.scope_token, 0, "draft text")
        .await
        .unwrap();
    assert_eq!(saved.revision, 1);
    assert_eq!(
        core.load_managed_task_draft(PROJECT, WORKSPACE)
            .await
            .unwrap()
            .prompt
            .as_deref(),
        Some("draft text")
    );
    let cleared = core
        .clear_managed_task_draft(PROJECT, WORKSPACE, &saved.scope_token, saved.revision)
        .await
        .unwrap();
    let retried = core
        .clear_managed_task_draft(PROJECT, WORKSPACE, &saved.scope_token, saved.revision)
        .await
        .unwrap();
    assert_eq!(retried.revision, cleared.revision);
    assert_eq!(retried.prompt, None);

    let mut other_session = client.session_info().clone();
    other_session.principal_id = "different-principal".into();
    let other_client =
        runne_runtime_client::mock_authenticated_runtime_client(&origin, other_session).unwrap();
    core.replace_runtime_client(Some(other_client)).unwrap();
    let other_scope = core
        .load_managed_task_draft(PROJECT, WORKSPACE)
        .await
        .unwrap();
    assert_eq!(other_scope.revision, 0);
    assert_ne!(other_scope.scope_token, loaded.scope_token);
    assert!(matches!(
        core.clear_managed_task_draft(PROJECT, WORKSPACE, &saved.scope_token, saved.revision)
            .await,
        Err(AppCoreError::ManagedDraftScopeChanged)
    ));
}

#[tokio::test]
async fn principal_switch_during_workspace_lookup_returns_no_plaintext_or_wrong_scope_read() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let (origin, request_rx, release_tx, server) = delayed_workspace_server().await;
    let (core, secure, client) = open_draft_core(&path, &origin, [0x92; 32]);
    let (token, before) = seed_draft(
        &core,
        secure.as_ref(),
        &managed_draft_scope("principal"),
        &path,
    );
    let core = Arc::new(core);
    let pending_core = Arc::clone(&core);
    let load = tokio::spawn(async move {
        pending_core
            .load_managed_task_draft(PROJECT, WORKSPACE)
            .await
    });
    assert!(request_rx.await.unwrap().starts_with("GET /v1/workspaces/"));
    let mut other_session = client.session_info().clone();
    other_session.principal_id = "other-principal".into();
    let other =
        runne_runtime_client::mock_authenticated_runtime_client(&origin, other_session).unwrap();
    core.replace_runtime_client(Some(other)).unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(
        load.await.unwrap(),
        Err(AppCoreError::RuntimeUnavailable)
    ));
    server.await.unwrap();
    let after: Vec<u8> = rusqlite::Connection::open(draft_sidecar_path(&path))
        .unwrap()
        .query_row("SELECT payload FROM protected_drafts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(token.len(), 64);
}

#[tokio::test]
async fn revocation_during_workspace_lookup_prevents_draft_save() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("profile.sqlite3");
    let (origin, request_rx, release_tx, server) = delayed_workspace_server().await;
    let (core, secure, _client) = open_draft_core(&path, &origin, [0x93; 32]);
    let (token, before) = seed_draft(
        &core,
        secure.as_ref(),
        &managed_draft_scope("principal"),
        &path,
    );
    let core = Arc::new(core);
    let pending_core = Arc::clone(&core);
    let save = tokio::spawn(async move {
        pending_core
            .save_managed_task_draft(PROJECT, WORKSPACE, &token, 1, "should not save")
            .await
    });
    assert!(request_rx.await.unwrap().starts_with("GET /v1/workspaces/"));
    core.set_runtime_availability(RuntimeAvailability::Revoked)
        .unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(
        save.await.unwrap(),
        Err(AppCoreError::RuntimeUnavailable)
    ));
    server.await.unwrap();
    let after: Vec<u8> = rusqlite::Connection::open(draft_sidecar_path(&path))
        .unwrap()
        .query_row("SELECT payload FROM protected_drafts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn preflight_reports_unavailable_for_corrupt_protected_sidecar() {
    let origin = managed_api_server(ManagedApiMock {
        submissions: Arc::default(),
        task_run_ids: Arc::default(),
        fail_approvals: false,
        task_runs: json!([]),
        approvals: json!([]),
    })
    .await;
    let directory = tempfile::tempdir().unwrap();
    let profile = [0x94; 32];
    let secure: Arc<dyn SecureStore> =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile));
    let client = runne_runtime_client::mock_authenticated_runtime_client(
        &origin,
        mutation_test_client("managed-authority", "managed-lineage", 1)
            .session_info()
            .clone(),
    )
    .unwrap();
    let path = directory.path().join("profile.sqlite3");
    let core = AppCore::open_with_test_runtime_secure(&path, client, secure, profile).unwrap();
    let mut sidecar = path.as_os_str().to_owned();
    sidecar.push(".drafts.sqlite3");
    let sidecar = std::path::PathBuf::from(sidecar);
    std::fs::write(&sidecar, b"synthetic corrupt sidecar").unwrap();
    std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
    let preflight = core
        .prepare_managed_task_run(PROJECT, WORKSPACE)
        .await
        .unwrap();
    assert_eq!(preflight.draft_policy, ManagedTaskDraftPolicy::Unavailable);
    assert_eq!(
        std::fs::read(sidecar).unwrap(),
        b"synthetic corrupt sidecar"
    );
}
