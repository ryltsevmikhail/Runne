// Lifecycle journey: submit → duplicate submit → get → list → replay →
// cancel, each against exact wire fixtures.

#[tokio::test]
async fn submit_get_list_replay_cancel_happy_path() {
    let (address, requests) = {
        let submit_body = submit_ack_body(TASK_RUN_ID, 2, "submitted");
        let cancel_body = submit_ack_body(TASK_RUN_ID, 3, "cancellation_requested");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in [
                response(202, "Accepted", &submit_body),
                response(200, "OK", &snapshot_body("queued", 2, false)),
                response(
                    200,
                    "OK",
                    &format!("{{\"taskRuns\":[{}]}}", snapshot_body("queued", 2, false)),
                ),
                response(202, "Accepted", &cancel_body),
            ] {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2048];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.expect("read");
                    assert_ne!(read, 0, "request headers");
                    request.extend_from_slice(&buffer[..read]);
                }
                requests.push(String::from_utf8(request).expect("request UTF-8"));
                stream.write_all(response.as_bytes()).await.expect("response");
            }
            requests
        });
        (origin, server)
    };
    let client = mock_authenticated_runtime_client(&address, session()).expect("client");

    // Submit: one authenticated command, ack at committed version 2.
    let submit_ack = client
        .submit_task_run(SubmitTaskRunRequest::new(
            identity(COMMAND_ID, "lifecycle-submit"),
            conversation_id(),
            workspace_id(),
        ))
        .await
        .expect("submit acknowledgement");
    assert_eq!(submit_ack.task_run_id(), task_run_id());
    assert_eq!(submit_ack.stream_version(), 2);

    // Get: committed snapshot readback after the ack.
    let snapshot = client.get_task_run(task_run_id()).await.expect("snapshot");
    assert_eq!(snapshot.task_run_id(), task_run_id());
    assert_eq!(snapshot.state(), TaskRunState::Queued);
    assert_eq!(snapshot.stream_version(), 2);
    assert_eq!(snapshot.terminal_result(), None);

    // List: exactly the submitted run.
    let list = client.list_task_runs().await.expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].task_run_id(), task_run_id());
    assert_eq!(list[0].state(), TaskRunState::Queued);

    // Cancel: runtime-owned transition acknowledged with the next version.
    let cancel_ack = client
        .cancel_task_run(CancelTaskRunRequest::new(
            identity(CANCEL_COMMAND_ID, "lifecycle-cancel"),
            task_run_id(),
            2,
        ))
        .await
        .expect("cancel acknowledgement");
    assert_eq!(cancel_ack.task_run_id(), task_run_id());
    assert_eq!(cancel_ack.stream_version(), 3);

    let requests = requests.await.expect("server task");
    // Wire contract: command identity headers travel on every mutation
    // (submit at 0, cancel at 3); read requests (get at 1, list at 2) carry
    // only authentication. Header names are case-insensitive.
    for (index, raw) in requests.iter().enumerate() {
        let lower = format!("\r\n{}", raw.to_ascii_lowercase());
        let is_mutation = matches!(index, 0 | 3);
        if is_mutation {
            assert!(
                lower.contains("\r\nx-command-id:"),
                "request {index} command identity header; raw: {raw:?}"
            );
            assert!(
                lower.contains("\r\nidempotency-key: lifecycle-"),
                "request {index} idempotency key header; raw: {raw:?}"
            );
        } else {
            assert!(
                !lower.contains("\r\nx-command-id:"),
                "read request {index} must not carry command identity; raw: {raw:?}"
            );
        }
    }

    server_replay_created_then_queued().await;
}

/// Raw HTTP fixture responses for the replay journey.
fn replay_responses() -> Vec<(String, String)> {
    fn json_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }
    let open = serde_json::json!({
        "sessionId": "018f2e3a7000700080000000000002a6",
        "highWaterRef": "aa",
        "events": [
            task_run_event("018f2e3a-7000-7000-8000-0000000002a7", 1, "taskRun.created"),
            task_run_event("018f2e3a-7000-7000-8000-0000000002a8", 2, "taskRun.queued"),
        ],
        "hasMore": false
    });
    let body = serde_json::to_vec(&open).unwrap();
    let open_response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        String::from_utf8(body).unwrap()
    );
    let ack_body = "{\"acknowledged\":true}";
    let complete_body = "{\"catchUpProof\":\"aa\",\"sessionState\":\"catch_up_complete\"}";
    let live_body =
        "{\"liveDeliveryId\":\"018f2e3a-7000-7000-8000-0000000002a9\",\"sessionState\":\"live\"}";
    vec![
        ("open-session".to_owned(), open_response),
        // Two events, each acknowledged before the next request.
        ("acknowledge".to_owned(), json_response(ack_body)),
        ("acknowledge".to_owned(), json_response(ack_body)),
        ("complete-catch-up".to_owned(), json_response(complete_body)),
        ("continue-live".to_owned(), json_response(live_body)),
    ]
}

/// Canonical event fixture for the aggregate replay stream.
fn task_run_event(event_id: &str, sequence: u64, event_type: &str) -> serde_json::Value {
    let cursor_value = cursor_hex(&format!(r#"{{"s":{sequence}}}"#));
    serde_json::json!({
        "aggregateId": TASK_RUN_ID,
        "aggregateType": "taskRun",
        "causationEventId": serde_json::Value::Null,
        "correlationId": CONVERSATION_ID,
        "correlationType": "conversation",
        "cursor": format!("gocode-replay-cursor-v1.{cursor_value}"),
        "eventId": event_id,
        "eventType": event_type,
        "integrityDigest": "1111111111111111111111111111111111111111111111111111111111111111",
        "payload": {"type": event_type},
        "replayBindingId": REPLAY_BINDING,
        "schemaVersion": 1,
        "sensitivity": "public",
        "sequence": sequence,
        "timestampUnixMicros": 1_722_330_000_000_000_i64
    })
}

/// Serves the replay journey fixture on a fresh loopback listener.
async fn replay_fixture_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("listener");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        for (path_check, body) in replay_responses() {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 2048];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.expect("read");
                assert_ne!(read, 0, "request headers");
                request.extend_from_slice(&buffer[..read]);
            }
            let raw = String::from_utf8(request).expect("request UTF-8");
            if path_check == "open-session" {
                assert!(raw.starts_with("POST /v1/replay/open-session"));
                assert!(raw.contains(&format!("\"aggregateId\":\"{TASK_RUN_ID}\"")));
                assert!(raw.contains("\"aggregateType\":\"taskRun\""));
            } else {
                assert!(raw.contains(&path_check), "expected {path_check} request");
            }
            stream.write_all(body.as_bytes()).await.expect("response");
        }
    });
    (origin, server)
}

/// Replay leg: the aggregate stream for a submitted run is exactly
/// `taskRun.created` + `taskRun.queued`; the client decodes both as typed
/// timeline kinds and never observes a Created-only tail.
async fn server_replay_created_then_queued() {
    let (origin, session_id) = replay_fixture_server().await;
    let client = mock_authenticated_runtime_client(&origin, session()).expect("client");
    let scope = ReplayScope::new(ReplayAggregateKind::TaskRun, task_run_id());
    let mut timeline = Vec::new();
    let live = client
        .catch_up(scope, None, |delivery| {
            if let runne_runtime_client::CanonicalReplayPayload::TaskRun(payload) =
                delivery.event().payload()
            {
                timeline.push((payload.kind(), payload.attempt_id()));
            }
            Ok::<_, ()>(())
        })
        .await
        .expect("replay catch-up");

    assert_eq!(
        timeline,
        vec![
            (runne_runtime_client::TaskRunTimelineKind::Created, None),
            (runne_runtime_client::TaskRunTimelineKind::Queued, None),
        ],
        "submit stream is exactly Created then Queued"
    );
    assert_eq!(live.scope(), scope);
    session_id.await.expect("replay server task");
}
