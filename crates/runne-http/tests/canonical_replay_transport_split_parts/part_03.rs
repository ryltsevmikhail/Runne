#[tokio::test]
async fn live_classification_denial_preserves_session_and_delivery_progress() {
    for denied_mode in [SwitchMode::Marker, SwitchMode::Unavailable] {
        let guard = Arc::new(SwitchableGuard::new(SwitchMode::Available));
        let (app, directory) = setup_with(
            "replay-live-initial",
            Arc::clone(&guard) as Arc<dyn ProhibitedContentPort>,
        );
        let session_id = open_and_continue_live(&app).await;
        append_taskrun_event(&directory, 2, PROHIBITED_MARKER);
        let before = replay_progress(&directory, &session_id);
        guard.set(denied_mode);

        let response = app
            .oneshot(get(&format!("/v1/replay/{session_id}/events")))
            .await
            .unwrap();

        assert!(!response.status().is_success());
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(
            !bytes
                .windows(PROHIBITED_MARKER.len())
                .any(|window| window == PROHIBITED_MARKER.as_bytes()),
            "canonical error contained prohibited replay representation"
        );
        assert_eq!(replay_progress(&directory, &session_id), before);
    }
}

fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(
            "authorization",
            session_authorization_header(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SESSION_AUTHORITY),
            )
            .unwrap(),
        )
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(
            "authorization",
            session_authorization_header(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SESSION_AUTHORITY),
            )
            .unwrap(),
        )
        .header("accept", "text/event-stream")
        .body(Body::empty())
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn issued_cursor_is_opaque_and_round_trips_through_acknowledge() {
    let (app, directory) = setup();
    let response = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": "taskRun",
                "aggregateId": aggregate_id_wire(),
                "fromCursor": null,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let opened = json_body(response).await;
    let session_id = opened["sessionId"].as_str().unwrap();
    let event = &opened["events"][0];
    assert_eq!(event["aggregateType"], "taskRun");
    assert_eq!(event["aggregateId"], aggregate_id_wire());
    assert_eq!(event["eventType"], "taskRun.created");
    assert_eq!(event["sequence"], 1);
    assert_eq!(event["schemaVersion"], 1);
    assert_eq!(event["sensitivity"], "public");
    assert_eq!(event["causationEventId"], Value::Null);
    assert_eq!(
        event["integrityDigest"],
        hex::encode(taskrun_row(1, 1, "replay-test".to_owned()).integrity_digest)
    );
    assert_eq!(event["correlationId"], aggregate_id_wire());
    assert_eq!(event["correlationType"], "taskRun");
    assert_eq!(event["payload"], json!({"type": "taskRun.created"}));
    assert_eq!(event["timestampUnixMicros"], 0);
    assert_eq!(event["replayBindingId"].as_str().unwrap().len(), 32);
    for forbidden in [
        "globalPosition",
        "commandId",
        "idempotencyKey",
        "actor",
        "integrityProfile",
    ] {
        assert!(event.get(forbidden).is_none(), "event leaked {forbidden}");
    }
    assert!(
        !event
            .to_string()
            .contains("runne-durable-event-codec-v1-hex")
    );
    let cursor = opened["events"][0]["cursor"]
        .as_str()
        .expect("cursor must be one opaque transport string");

    let response = app
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": cursor}),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await, json!({"acknowledged": true}));

    let connection = directory.open_reader();
    let (authority, generation): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT authority_id, session_generation
             FROM _replay_subscriptions
             WHERE session_id = ?1",
            [hex::decode(session_id).unwrap()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(authority, AUTHORITY);
    assert_eq!(generation, GENERATION);
}

#[tokio::test]
async fn tampered_cursor_returns_redacted_canonical_error() {
    let (app, _directory) = setup();
    let opened = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": "taskRun",
                "aggregateId": aggregate_id_wire(),
                "fromCursor": null,
            }),
        ))
        .await
        .unwrap();
    let opened = json_body(opened).await;
    let session_id = opened["sessionId"].as_str().unwrap();
    let cursor = opened["events"][0]["cursor"].as_str().unwrap();
    let tampered = format!("{cursor}00");

    let response = app
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": tampered}),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let body = json_body(response).await;
    assert_eq!(
        body,
        json!({
            "code": "invalid_replay_cursor",
            "requestId": request_id,
        })
    );
    assert!(!body.to_string().contains(cursor));
    assert!(uuid::Uuid::parse_str(&request_id).is_ok());
}

#[tokio::test]
async fn unsupported_scope_spellings_return_one_closed_error() {
    for aggregate_type in ["taskRunFeed", "auditFeed", "unknown"] {
        let (app, directory) = setup();
        let response = app
            .oneshot(post(
                "/v1/replay/open-session",
                json!({
                    "aggregateType": aggregate_type,
                    "aggregateId": aggregate_id_wire(),
                    "fromCursor": null,
                }),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(response).await["code"],
            "unsupported_replay_scope"
        );
        assert_eq!(subscription_count(&directory), 0);
    }
}

#[tokio::test]
async fn replay_body_and_page_count_are_bounded_at_the_published_values() {
    let (app, _directory) = setup();
    let oversized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/replay/open-session")
                .header(
                    "authorization",
                    session_authorization_header(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SESSION_AUTHORITY),
                    )
                    .unwrap(),
                )
                .header("content-type", "application/json")
                .body(Body::from(vec![b'x'; 8 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let opened = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": "taskRun",
                "aggregateId": aggregate_id_wire(),
                "fromCursor": null,
            }),
        ))
        .await
        .unwrap();
    let session_id = json_body(opened).await["sessionId"]
        .as_str()
        .unwrap()
        .to_owned();
    let excessive_page = app
        .oneshot(post(
            &format!("/v1/replay/{session_id}/read-page"),
            json!({"limit": 257}),
        ))
        .await
        .unwrap();
    assert_eq!(excessive_page.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(excessive_page).await["code"],
        "invalid_replay_page_limit"
    );
}
