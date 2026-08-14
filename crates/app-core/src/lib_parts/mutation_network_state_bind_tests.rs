#[tokio::test]
async fn protected_bind_exercises_all_reconciliation_branches_without_carrier_fallback() {
    let cases = [
        vec![WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)), WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)), WorkspaceReply::Json(200, r#"{"disposition":"not_committed_retryable"}"#.into())],
        vec![WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)), WorkspaceReply::Json(200, r#"{"disposition":"indeterminate"}"#.into())],
        vec![WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)), WorkspaceReply::Json(409, r#"{"code":"command_conflict","requestId":"018f2e3a-7000-7000-8000-000000000930"}"#.into())],
        vec![WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)), WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)), WorkspaceReply::Json(200, workspace_reconcile("bind_workspace_root", WORKSPACE_ID, 2)), WorkspaceReply::Json(200, workspace_reconcile("bind_workspace_root", WRONG_ID, 2))],
    ];
    for (index, replies) in cases.into_iter().enumerate() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let expected = replies.len();
        let server = tokio::spawn(workspace_server(listener, replies, expected));
        let directory = tempfile::tempdir().expect("directory");
        let core = protected_workspace_core(&origin, &directory).await;
        let mut prepared = core.prepare_open_selected_workspace(WORKSPACE_ID.parse().expect("workspace"), 1, protected_admission()).await.expect("prepare");
        let (bind, _, _) = prepared.parts_and_possible_send_mut();
        if index == 1 || index == 2 {
            core.transition_v7_under_operation(bind, gocode_local_store::V7MutationTransition::Dispatching { timestamp: 1 }).expect("dispatching");
            core.transition_v7_under_operation(bind, gocode_local_store::V7MutationTransition::Indeterminate { timestamp: 2 }).expect("reconciling");
        }
        let result = core.dispatch_prepared_mutation_under_operation(bind, None, false, false, false).await;
        if index == 3 {
            assert!(result.is_ok());
            assert!(matches!(core.dispatch_prepared_mutation_under_operation(bind, None, false, false, false).await, Err(AppCoreError::MutationUnavailable)));
        } else {
            assert!(result.is_err());
        }
        let requests = server.await.expect("server");
        let binds = requests.iter().filter(|request| request.starts_with(&format!("POST /v1/workspaces/{WORKSPACE_ID}/root-bindings HTTP/1.1"))).count();
        assert_eq!(binds, usize::from(index == 0 || index == 3));
    }
}

#[tokio::test]
async fn protected_bind_ncr_resends_once_with_the_retained_carrier_then_exhausts() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(workspace_server(listener, vec![
        WorkspaceReply::Json(200, workspace_snapshot(WORKSPACE_ID, 1, false)),
        WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)),
        WorkspaceReply::Json(200, r#"{"disposition":"not_committed_retryable"}"#.into()),
        WorkspaceReply::Json(202, workspace_ack(WORKSPACE_ID, 2)),
        WorkspaceReply::Json(200, r#"{"disposition":"not_committed_retryable"}"#.into()),
    ], 5));
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core.prepare_open_selected_workspace(WORKSPACE_ID.parse().expect("workspace"), 1, protected_admission()).await.expect("prepare");
    let (bind, _, _) = prepared.parts_and_possible_send_mut();
    assert!(matches!(core.dispatch_prepared_mutation_under_operation(bind, None, false, false, false).await, Err(AppCoreError::RuntimeUnavailable)));
    assert!(matches!(core.dispatch_prepared_mutation_under_operation(bind, None, false, false, false).await, Err(AppCoreError::RuntimeUnavailable)));
    assert!(matches!(core.dispatch_prepared_mutation_under_operation(bind, None, false, false, false).await, Err(AppCoreError::MutationUnavailable)));
    let requests = server.await.expect("server");
    let bindings = requests.iter().filter(|request| request.starts_with(&format!("POST /v1/workspaces/{WORKSPACE_ID}/root-bindings HTTP/1.1"))).collect::<Vec<_>>();
    assert_eq!(bindings.len(), 2);
    assert_eq!(bindings[0], bindings[1], "resend must preserve the exact carrier wire");
    assert_eq!(requests.iter().filter(|request| request.starts_with("POST /v1/commands/reconcile HTTP/1.1")).count(), 2);
}

#[tokio::test]
async fn protected_bind_possible_send_loss_reconciles_without_a_blind_resend() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let (mut snapshot, _) = listener.accept().await.expect("snapshot");
        let mut bytes = [0; 8192];
        let used = snapshot.read(&mut bytes).await.expect("read snapshot");
        let snapshot_request = String::from_utf8_lossy(&bytes[..used]).into_owned();
        let body = workspace_snapshot(WORKSPACE_ID, 1, false);
        let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        snapshot.write_all(response.as_bytes()).await.expect("snapshot response");
        let (mut sent, _) = listener.accept().await.expect("bind");
        let used = sent.read(&mut bytes).await.expect("read bind");
        let bind = String::from_utf8_lossy(&bytes[..used]).into_owned();
        drop(sent);
        let (mut reconcile, _) = listener.accept().await.expect("reconcile");
        let used = reconcile.read(&mut bytes).await.expect("read reconcile");
        let reconciliation = String::from_utf8_lossy(&bytes[..used]).into_owned();
        let body = r#"{"disposition":"indeterminate"}"#;
        let response = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        reconcile.write_all(response.as_bytes()).await.expect("response");
        (snapshot_request, bind, reconciliation)
    });
    let directory = tempfile::tempdir().expect("directory");
    let core = protected_workspace_core(&origin, &directory).await;
    let mut prepared = core.prepare_open_selected_workspace(WORKSPACE_ID.parse().expect("workspace"), 1, protected_admission()).await.expect("prepare");
    let (bind, _, _) = prepared.parts_and_possible_send_mut();
    assert!(matches!(core.dispatch_prepared_mutation_under_operation(bind, None, false, false, false).await, Err(AppCoreError::RuntimeUnavailable)));
    let (snapshot, sent, reconcile) = server.await.expect("server");
    assert!(snapshot.starts_with(&format!("GET /v1/workspaces/{WORKSPACE_ID} HTTP/1.1")));
    assert!(sent.starts_with(&format!("POST /v1/workspaces/{WORKSPACE_ID}/root-bindings HTTP/1.1")));
    assert!(reconcile.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}
