fn unknown_successor_ids() -> (CanonicalId, CanonicalId) {
    (
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000931").expect("predecessor"),
        CanonicalId::parse("018f2e3a-7000-7000-8000-000000000932").expect("successor"),
    )
}

fn successor_ack_wire(predecessor: CanonicalId, successor: CanonicalId) -> String {
    format!(r#"{{"taskRunId":"{successor}","streamVersion":2,"transition":"unknown_successor_created","attemptId":null,"terminalResult":null,"predecessorTaskRunId":"{predecessor}","predecessorVersion":5}}"#)
}

fn successor_reconciliation_wire(predecessor: CanonicalId, successor: CanonicalId) -> String {
    format!(r#"{{"disposition":"durably_recorded","outcome":{{"operation":"supersede_unknown_task_run","predecessorTaskRunId":"{predecessor}","successorTaskRunId":"{successor}","newVersion":5}}}}"#)
}

async fn successor_server(
    replies: Vec<Option<(u16, String)>>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    use tokio::io::AsyncWriteExt as _;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut stream, _) = listener.accept().await.expect("request");
            requests.push(read_http_request(&mut stream).await);
            if let Some((status, body)) = reply {
                let response = format!(
                    "HTTP/1.1 {status} test\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.expect("response");
            }
        }
        requests
    });
    (origin, task)
}

fn successor_request(predecessor: CanonicalId) -> MutationRequest {
    MutationRequest::supersede_unknown_task_run(
        predecessor,
        4,
        runne_runtime_client::UnknownSuccessorAcknowledgment::DuplicateExecutionAndCostV1,
    )
    .expect("explicit successor acknowledgment")
}

fn request_header<'a>(request: &'a str, name: &str) -> &'a str {
    request
        .split("\r\n\r\n")
        .next()
        .expect("HTTP headers")
        .lines()
        .skip(1)
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
        .expect("required identity header")
}

fn request_json(request: &str) -> serde_json::Value {
    let body = request.split_once("\r\n\r\n").expect("HTTP body").1;
    serde_json::from_str(body.trim_end_matches('\0')).expect("request JSON")
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt as _;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(stream.read_u8().await.expect("read header byte"));
        assert!(headers.len() <= 8192, "bounded test request headers");
    }
    let head = std::str::from_utf8(&headers).expect("HTTP headers are UTF-8");
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("content length"))
        })
        .unwrap_or(0);
    assert!(length <= 16 * 1024, "bounded test request body");
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.expect("read full body");
    headers.extend(body);
    String::from_utf8(headers).expect("test HTTP request is UTF-8")
}

#[tokio::test]
async fn lost_successor_ack_reconciles_exact_command_to_the_same_typed_result() {
    let (predecessor, successor) = unknown_successor_ids();
    let (direct_origin, direct_server) = successor_server(vec![
        Some((202, successor_ack_wire(predecessor, successor))),
        Some((200, successor_reconciliation_wire(predecessor, successor))),
    ]).await;
    let direct_dir = tempfile::tempdir().expect("direct profile");
    let direct_core = AppCore::open_with_mock_runtime(
        &direct_dir.path().join("profile.sqlite3"),
        reconcile_client(&direct_origin),
    ).expect("direct core");
    let direct = direct_core.dispatch_prepared_mutation(
        direct_core.prepare_mutation(successor_request(predecessor)).await.expect("prepare direct"),
    ).await.expect("direct ack");
    let direct_requests = direct_server.await.expect("direct server");
    assert_eq!(direct_requests.len(), 2);
    assert_eq!(request_header(&direct_requests[0], "x-command-id"), request_header(&direct_requests[1], "x-command-id"));
    assert_eq!(request_header(&direct_requests[0], "idempotency-key"), request_header(&direct_requests[1], "idempotency-key"));

    let (reconcile_origin, reconcile_server) = successor_server(vec![
        None,
        Some((200, successor_reconciliation_wire(predecessor, successor))),
    ]).await;
    let reconcile_dir = tempfile::tempdir().expect("reconcile profile");
    let reconcile_core = AppCore::open_with_mock_runtime(
        &reconcile_dir.path().join("profile.sqlite3"),
        reconcile_client(&reconcile_origin),
    ).expect("reconcile core");
    let request = successor_request(predecessor);
    let replay = request.clone();
    let recovered = reconcile_core.dispatch_prepared_mutation(
        reconcile_core.prepare_mutation(request).await.expect("prepare lost ack"),
    ).await.expect("reconcile lost ack");

    let runne_local_store::CanonicalMutationOutcome::TaskRunUnknownSuccessorCreated {
        predecessor_task_run_id,
        successor_task_run_id,
        predecessor_version,
        successor_version,
    } = reconcile_core.prepare_mutation(replay).await.expect("canonical replay")
        .anchored_record.canonical_outcome().expect("persisted typed outcome").clone()
    else {
        panic!("successor outcome is durably anchored")
    };
    let MutationDispatchResult::TaskRunUnknownSuccessorCreated(direct) = direct else {
        panic!("direct ACK has successor type")
    };
    let MutationDispatchResult::TaskRunUnknownSuccessorCreated(recovered) = recovered else {
        panic!("reconciled ACK has successor type")
    };
    assert_eq!(direct, recovered, "direct and reconciled typed ACKs converge");
    assert_eq!(direct.predecessor_task_run_id(), predecessor);
    assert_eq!(direct.successor_task_run_id(), successor);
    assert_eq!((direct.predecessor_version(), direct.stream_version()), (5, 2));
    assert_eq!(predecessor_task_run_id.as_bytes(), predecessor.to_string().as_bytes());
    assert_eq!(successor_task_run_id.as_bytes(), successor.to_string().as_bytes());
    assert_eq!((predecessor_version, successor_version), (5, 2));
    let requests = reconcile_server.await.expect("reconcile server");
    assert_eq!(requests.len(), 2, "one POST plus same-command reconcile");
    assert!(requests[0].starts_with(&format!("POST /v1/task-runs/{predecessor}/successor HTTP/1.1")));
    assert!(requests[1].starts_with("POST /v1/commands/reconcile HTTP/1.1"));
    assert_eq!(request_header(&requests[0], "x-command-id"), request_header(&requests[1], "x-command-id"));
    assert_eq!(request_header(&requests[0], "idempotency-key"), request_header(&requests[1], "idempotency-key"));
    let successor_post = request_json(&requests[0]);
    assert_eq!(successor_post["expectedVersion"], 4);
    assert_eq!(successor_post["acknowledgment"], "duplicate_execution_and_cost_v1");
    let reconciliation = request_json(&requests[1]);
    assert_eq!(reconciliation["operation"], "supersede_unknown_task_run");
    assert_eq!(reconciliation["predecessorTaskRunId"], predecessor.to_string());
    assert_eq!(reconciliation["expectedVersion"], 4);
}

#[tokio::test]
async fn authority_switch_while_successor_ack_is_held_keeps_command_indeterminate() {
    use tokio::io::AsyncWriteExt as _;
    let (predecessor, successor) = unknown_successor_ids();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let received = std::sync::Arc::new(tokio::sync::Notify::new());
    let server_received = std::sync::Arc::clone(&received);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("successor POST");
        let request = read_http_request(&mut stream).await;
        server_received.notify_one();
        release_rx.await.expect("release held ACK");
        let body = successor_ack_wire(predecessor, successor);
        let response = format!(
            "HTTP/1.1 202 Accepted\r\ncontent-type: application/json\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.expect("write ACK");
        request
    });
    let directory = tempfile::tempdir().expect("profile");
    let original_client = reconcile_client(&origin);
    let core = std::sync::Arc::new(AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        original_client.clone(),
    ).expect("core"));
    let request = successor_request(predecessor);
    let replay = request.clone();
    let lease = core.prepare_mutation(request).await.expect("prepare");
    let operation = {
        let core = std::sync::Arc::clone(&core);
        tokio::spawn(async move { core.dispatch_prepared_mutation(lease).await })
    };
    received.notified().await;
    core.replace_runtime_client(Some(mutation_test_client("authority-switched", "lineage-b", 2)))
        .expect("switch runtime authority");
    let _ = release_tx.send(());
    assert!(matches!(operation.await.expect("dispatch join"), Err(AppCoreError::RuntimeUnavailable)));
    core.replace_runtime_client(Some(original_client)).expect("restore original runtime");
    let anchored = core.prepare_mutation(replay).await.expect("same command retained");
    assert_eq!(
        anchored.anchored_record.disposition(),
        runne_local_store::ClientMutationDisposition::Reconciling,
        "late ACK cannot become canonical under a changed authority"
    );
    assert!(server.await.expect("server").starts_with(&format!(
        "POST /v1/task-runs/{predecessor}/successor HTTP/1.1"
    )));
}

#[tokio::test]
async fn successor_prepared_under_old_authority_is_not_sent_after_switch() {
    let (predecessor, _) = unknown_successor_ids();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let directory = tempfile::tempdir().expect("profile");
    let core = AppCore::open_with_mock_runtime(
        &directory.path().join("profile.sqlite3"),
        reconcile_client(&origin),
    ).expect("core");
    let lease = core.prepare_mutation(successor_request(predecessor)).await.expect("prepare");
    core.replace_runtime_client(Some(mutation_test_client("authority-switched", "lineage-b", 2)))
        .expect("switch runtime authority");
    assert!(matches!(core.dispatch_prepared_mutation(lease).await, Err(AppCoreError::RuntimeUnavailable)));
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(50),
        listener.accept(),
    ).await.is_err(), "no successor POST crosses the authority switch");
}
