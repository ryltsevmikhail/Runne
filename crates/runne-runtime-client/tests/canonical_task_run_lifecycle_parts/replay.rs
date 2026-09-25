use runne_runtime_client::{ReplayAggregateKind, ReplayScope};

#[tokio::test]
async fn replay_exposes_created_then_queued_as_typed_events() {
    let task_run = id(TASK_RUN_ID);
    let events = serde_json::json!({
        "sessionId": "018f2e3a7000700080000000000002a6",
        "highWaterRef": "aa",
        "events": [
            event(task_run, CONVERSATION_ID, 1, "taskRun.created"),
            event(task_run, CONVERSATION_ID, 2, "taskRun.queued"),
        ],
        "hasMore": false
    });
    let body = serde_json::to_string(&events).expect("event response");
    let responses = vec![
        support::RawResponse::json(200, "OK", body),
        support::RawResponse::json(200, "OK", "{\"acknowledged\":true}"),
        support::RawResponse::json(200, "OK", "{\"acknowledged\":true}"),
        support::RawResponse::json(
            200,
            "OK",
            "{\"catchUpProof\":\"aa\",\"sessionState\":\"catch_up_complete\"}",
        ),
        support::RawResponse::json(
            200,
            "OK",
            "{\"liveDeliveryId\":\"018f2e3a-7000-7000-8000-0000000002a9\",\"sessionState\":\"live\"}",
        ),
    ];
    let (origin, server) = support::serve(responses).await;
    let client = mock_authenticated_runtime_client(&origin, session()).expect("client");
    let scope = ReplayScope::new(ReplayAggregateKind::TaskRun, task_run);
    let mut timeline = Vec::new();
    let live = client
        .catch_up(scope, None, |delivery| {
            if let runne_runtime_client::CanonicalReplayPayload::TaskRun(payload) =
                delivery.event().payload()
            {
                timeline.push(payload.kind());
            }
            Ok::<_, ()>(())
        })
        .await
        .expect("replay");
    assert_eq!(
        timeline,
        vec![
            runne_runtime_client::TaskRunTimelineKind::Created,
            runne_runtime_client::TaskRunTimelineKind::Queued,
        ]
    );
    assert_eq!(live.scope(), scope);
    let requests = server.await.expect("fixture");
    assert!(
        requests[0]
            .start_line
            .starts_with("POST /v1/replay/open-session")
    );
    assert_eq!(requests.len(), 5);
}

fn event(
    task_run: CanonicalId,
    conversation: &str,
    sequence: u64,
    event_type: &str,
) -> serde_json::Value {
    serde_json::json!({
        "aggregateId": task_run,
        "aggregateType": "taskRun",
        "causationEventId": null,
        "correlationId": conversation,
        "correlationType": "conversation",
        "cursor": format!("gocode-replay-cursor-v1.{}", cursor_hex(&format!(r#"{{"s":{sequence}}}"#))),
        "eventId": format!("018f2e3a-7000-7000-8000-{sequence:012x}"),
        "eventType": event_type,
        "integrityDigest": "1111111111111111111111111111111111111111111111111111111111111111",
        "payload": {"type": event_type},
        "replayBindingId": "018f2e3a7000700080000000000002a5",
        "schemaVersion": 1,
        "sensitivity": "public",
        "sequence": sequence,
        "timestampUnixMicros": 1_722_330_000_000_000_i64
    })
}

fn cursor_hex(value: &str) -> String {
    value.bytes().fold(String::new(), |mut output, byte| {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
        output
    })
}
