#[tokio::test]
async fn live_sse_delivers_event_committed_after_catch_up() {
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
    let cursor = opened["events"][0]["cursor"].as_str().unwrap();
    let replay_binding_id = opened["events"][0]["replayBindingId"]
        .as_str()
        .unwrap()
        .to_owned();

    let acknowledged = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": cursor}),
        ))
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let completed = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/complete-catch-up"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let continued = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/continue-live"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(continued.status(), StatusCode::OK);

    let response = app
        .oneshot(get(&format!("/v1/replay/{session_id}/events")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    let database_path = directory.path().join("replay.sqlite");
    let writer = open_with_pragmas(database_path.to_str().unwrap()).unwrap();
    let row = taskrun_row(2, 2, "replay-live-test".to_owned());
    writer
        .execute(
            "INSERT INTO events \
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
             VALUES (?1, 1, ?2, 2, 2, 0, 0, 1, NULL, ?1, ?3, ?4, ?5, ?6, ?2, 1, 1)",
            rusqlite::params![
                row.event_id.as_slice(),
                AGGREGATE.as_slice(),
                row.idempotency_key,
                b"test-actor".as_slice(),
                row.payload,
                row.integrity_digest.as_slice(),
            ],
        )
        .unwrap();
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 2, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![row.event_id.as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();

    let mut body = response.into_body().into_data_stream();
    let delivery = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let frame = body.next().await.unwrap().unwrap();
            let frame = String::from_utf8(frame.to_vec()).unwrap();
            if frame.contains("event: delivery") {
                break frame;
            }
        }
    })
    .await
    .expect("live event must arrive before timeout");

    assert!(delivery.contains("\"eventType\":\"taskRun.created\""));
    assert!(delivery.contains("\"payload\":{\"type\":\"taskRun.created\"}"));
    assert!(delivery.contains(&format!("\"replayBindingId\":\"{replay_binding_id}\"")));
    assert!(!delivery.contains("\"globalPosition\":"));
    assert!(!delivery.contains("\"idempotencyKey\":"));
    assert!(!delivery.contains("gocode-durable-event-codec-v1-hex"));
    assert!(delivery.contains("\"replayCursor\":\"gocode-replay-cursor-v1."));
}

#[tokio::test]
async fn slow_live_consumer_closes_session_without_advancing_ack() {
    let (app, directory) = setup();
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
    let session_id = opened["sessionId"].as_str().unwrap().to_owned();
    let cursor = opened["events"][0]["cursor"].as_str().unwrap();
    let acknowledged = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": cursor}),
        ))
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let completed = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/complete-catch-up"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let continued = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/continue-live"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(continued.status(), StatusCode::OK);

    let unconsumed_stream = app
        .oneshot(get(&format!("/v1/replay/{session_id}/events")))
        .await
        .unwrap();
    assert_eq!(unconsumed_stream.status(), StatusCode::OK);

    let database_path = directory.path().join("replay.sqlite");
    let writer = open_with_pragmas(database_path.to_str().unwrap()).unwrap();
    for position in 2_i64..=80 {
        let row = taskrun_row(
            position,
            position,
            format!("replay-backpressure-{position}"),
        );
        writer
            .execute(
                "INSERT INTO events \
                 (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
                  sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
                  payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
                 VALUES (?1, 1, ?2, ?3, ?3, 0, 0, 1, NULL, ?1, ?4, ?5, ?6, ?7, ?2, 1, 1)",
                rusqlite::params![
                    row.event_id.as_slice(),
                    AGGREGATE.as_slice(),
                    position,
                    row.idempotency_key,
                    b"test-actor".as_slice(),
                    row.payload,
                    row.integrity_digest.as_slice(),
                ],
            )
            .unwrap();
    }
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 80, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![event_id(80).as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();
    drop(writer);

    let session_bytes = hex::decode(&session_id).unwrap();
    let last_acked = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let connection = open_with_pragmas(database_path.to_str().unwrap()).unwrap();
            let (state, last_acked): (String, Option<i64>) = connection
                .query_row(
                    "SELECT state, last_acked_position
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    [&session_bytes],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            drop(connection);
            if state == "closed" {
                break last_acked;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded live channel must close a stalled session");

    assert_eq!(last_acked, Some(1));
    drop(unconsumed_stream);
}
