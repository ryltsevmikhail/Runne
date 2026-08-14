async fn matrix_server(
    replies: Vec<(u16, String)>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body) in replies {
            let (mut stream, _) = listener.accept().await.expect("request");
            let mut bytes = [0; 8192];
            let used = stream.read(&mut bytes).await.expect("read");
            requests.push(String::from_utf8_lossy(&bytes[..used]).into_owned());
            let request_id = if status == 409 {
                "x-request-id: 018f2e3a-7000-7000-8000-000000000929\r\n"
            } else {
                ""
            };
            let reply = format!(
                "HTTP/1.1 {status} test\r\n{request_id}content-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.expect("reply");
        }
        requests
    });
    (origin, server)
}

fn matrix_values() -> (CanonicalId, CanonicalId, CanonicalId) {
    (
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000921").expect("project"),
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000922").expect("workspace"),
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000923").expect("conversation"),
    )
}

fn matrix_core(origin: &str) -> (tempfile::TempDir, AppCore) {
    let directory = tempfile::tempdir().expect("directory");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        reconcile_client(origin),
    )
    .expect("core");
    (directory, core)
}

#[tokio::test]
async fn each_non_bind_command_exercises_all_read_only_reconciliation_branches() {
    let (project, workspace, conversation) = matrix_values();
    let cases = [
        NetworkMutationCase::CreateProject,
        NetworkMutationCase::ArchiveProject,
        NetworkMutationCase::DeleteProject,
        NetworkMutationCase::CreateWorkspace,
        NetworkMutationCase::OpenWorkspace,
        NetworkMutationCase::CreateConversation,
        NetworkMutationCase::GenerateCompleted,
    ];
    for case in cases {
        let (path, ack_status, ack, _) = case.wire(project, workspace, conversation);
        let (origin, server) = matrix_server(vec![
            (ack_status, ack),
            (200, r#"{"disposition":"not_committed_retryable"}"#.into()),
            (ack_status, case.wire(project, workspace, conversation).2),
            (200, r#"{"disposition":"not_committed_retryable"}"#.into()),
        ])
        .await;
        let (_directory, core) = matrix_core(&origin);
        let request = case.request(project, workspace, conversation);
        let retry = request.clone();
        let exhausted = request.clone();
        let lease = core
            .prepare_mutation(request)
            .await
            .expect("prepare");
        assert!(matches!(
            core.dispatch_prepared_mutation(lease).await,
            Err(AppCoreError::RuntimeUnavailable)
        ));
        assert!(matches!(
            core
            .dispatch_prepared_mutation(core.prepare_mutation(retry).await.expect("retry"))
            .await,
            Err(AppCoreError::RuntimeUnavailable)
        ));
        assert!(matches!(
            core
                .dispatch_prepared_mutation(core.prepare_mutation(exhausted).await.expect("exhausted"))
                .await,
            Err(AppCoreError::MutationUnavailable)
        ));
        let requests = server.await.expect("server");
        assert_eq!(requests.len(), 4);
        assert!(requests[0].starts_with(&path));
        assert!(requests[1].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
        assert!(requests[2].starts_with(&path));
        assert_eq!(
            requests[0].split("\r\n").take(4).collect::<Vec<_>>(),
            requests[2].split("\r\n").take(4).collect::<Vec<_>>()
        );
        assert!(requests[3].starts_with("POST /v1/commands/reconcile HTTP/1.1"));

        let (origin, server) = matrix_server(vec![(200, r#"{"disposition":"indeterminate"}"#.into())]).await;
        let (_directory, core) = matrix_core(&origin);
        let mut lease = core
            .prepare_mutation(case.request(project, workspace, conversation))
            .await
            .expect("prepare");
        core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Dispatching { timestamp: 1 }).expect("dispatching");
        core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Indeterminate { timestamp: 2 }).expect("reconciling");
        assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::RuntimeUnavailable)));
        let requests = server.await.expect("server");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("POST /v1/commands/reconcile HTTP/1.1"));

        let conflict_id = "018f2e3a-7000-7000-8000-000000000929";
        let (origin, server) = matrix_server(vec![(409, format!(r#"{{"code":"command_conflict","requestId":"{conflict_id}"}}"#))]).await;
        let (_directory, core) = matrix_core(&origin);
        let request = case.request(project, workspace, conversation);
        let retry = request.clone();
        let mut lease = core.prepare_mutation(request).await.expect("prepare");
        core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Dispatching { timestamp: 1 }).expect("dispatching");
        core.transition_v7_under_operation(&mut lease, gocode_local_store::V7MutationTransition::Indeterminate { timestamp: 2 }).expect("reconciling");
        assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::MutationUnavailable)));
        assert_eq!(core.prepare_mutation(retry).await.expect("manual").anchored_record.disposition(), gocode_local_store::ClientMutationDisposition::ManualResolution);
        assert_eq!(server.await.expect("server").len(), 1);

        let (_, ack_status, ack, durable) = case.wire(project, workspace, conversation);
        let wrong = match case {
            NetworkMutationCase::CreateProject | NetworkMutationCase::ArchiveProject | NetworkMutationCase::DeleteProject => "018f2e3a-7000-7000-8000-000000000921",
            NetworkMutationCase::CreateWorkspace | NetworkMutationCase::OpenWorkspace => "018f2e3a-7000-7000-8000-000000000922",
            NetworkMutationCase::CreateConversation | NetworkMutationCase::GenerateCompleted => "018f2e3a-7000-7000-8000-000000000923",
            _ => unreachable!(),
        };
        let changed = durable.replacen(wrong, "018f2e3a-7000-7000-8000-000000000928", 1);
        let (origin, server) = matrix_server(vec![(ack_status, ack), (200, durable), (200, changed)]).await;
        let (_directory, core) = matrix_core(&origin);
        let request = case.request(project, workspace, conversation);
        let replay = request.clone();
        assert!(core.dispatch_prepared_mutation(core.prepare_mutation(request).await.expect("prepare")).await.is_ok());
        assert!(matches!(core.dispatch_prepared_mutation(core.prepare_mutation(replay).await.expect("canonical")).await, Err(AppCoreError::MutationUnavailable)));
        let requests = server.await.expect("server");
        assert_eq!(requests.len(), 3);
        assert!(requests[2].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    }
}

#[tokio::test]
async fn semantic_duplicate_with_a_fresh_command_id_reuses_the_original_anchor() {
    let (project, _, _) = matrix_values();
    let durable = format!(
        r#"{{"disposition":"durably_recorded","outcome":{{"operation":"create_project","projectId":"{project}","newVersion":1}}}}"#
    );
    let (origin, server) = matrix_server(vec![
        (202, format!(r#"{{"projectId":"{project}","newVersion":1}}"#)),
        (200, durable.clone()),
        (200, durable),
    ])
    .await;
    let (_directory, core) = matrix_core(&origin);
    let first = core
        .prepare_mutation(MutationRequest::create_project(project, "Project".into()).expect("first"))
        .await
        .expect("first anchor");
    assert!(core.dispatch_prepared_mutation(first).await.is_ok());
    let duplicate = core
        .prepare_mutation(MutationRequest::create_project(project, "Project".into()).expect("duplicate"))
        .await
        .expect("reuse anchor");
    assert!(core.dispatch_prepared_mutation(duplicate).await.is_ok());
    let requests = server.await.expect("server");
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests.iter().filter(|request| request.starts_with("POST /v1/projects HTTP/1.1")).count(),
        1,
    );
    assert!(requests[1].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert!(requests[2].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
}

#[tokio::test]
async fn each_non_bind_possible_send_loss_reconciles_without_a_blind_resend() {
    let (project, workspace, conversation) = matrix_values();
    let cases = [
        NetworkMutationCase::CreateProject,
        NetworkMutationCase::ArchiveProject,
        NetworkMutationCase::DeleteProject,
        NetworkMutationCase::CreateWorkspace,
        NetworkMutationCase::OpenWorkspace,
        NetworkMutationCase::CreateConversation,
        NetworkMutationCase::GenerateCompleted,
    ];
    for case in cases {
        let (path, _, _, _) = case.wire(project, workspace, conversation);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sent, _) = listener.accept().await.expect("possible send");
            let mut bytes = [0; 8192];
            let used = sent.read(&mut bytes).await.expect("read possible send");
            let mutation = String::from_utf8_lossy(&bytes[..used]).into_owned();
            drop(sent);
            let (mut reconcile, _) = listener.accept().await.expect("reconcile");
            let used = reconcile.read(&mut bytes).await.expect("read reconcile");
            let reconciliation = String::from_utf8_lossy(&bytes[..used]).into_owned();
            let body = r#"{"disposition":"indeterminate"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            reconcile.write_all(response.as_bytes()).await.expect("response");
            (mutation, reconciliation)
        });
        let (_directory, core) = matrix_core(&origin);
        assert!(matches!(
            core.dispatch_prepared_mutation(
                core.prepare_mutation(case.request(project, workspace, conversation))
                    .await
                    .expect("prepare"),
            )
            .await,
            Err(AppCoreError::RuntimeUnavailable)
        ));
        let (mutation, reconciliation) = server.await.expect("server");
        assert!(mutation.starts_with(&path));
        assert!(reconciliation.starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    }
}
