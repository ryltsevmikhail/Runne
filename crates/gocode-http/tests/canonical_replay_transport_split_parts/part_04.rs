#[tokio::test]
async fn ninth_principal_session_is_rejected_and_close_releases_quota() {
    let (app, _directory) = setup();
    let mut session_ids = Vec::new();
    for _ in 0..8 {
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
        session_ids.push((
            opened["sessionId"].as_str().unwrap().to_owned(),
            opened["events"][0]["cursor"].as_str().unwrap().to_owned(),
        ));
    }

    let rejected = app
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
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json_body(rejected).await["code"], "replay_backpressure");

    let acknowledged = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{}/acknowledge", session_ids[0].0),
            json!({"cursor": session_ids[0].1}),
        ))
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let completed = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{}/complete-catch-up", session_ids[0].0),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let closed = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{}/close", session_ids[0].0),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(closed.status(), StatusCode::NO_CONTENT);

    let admitted = app
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
    assert_eq!(admitted.status(), StatusCode::OK);
}

#[tokio::test]
async fn terminal_errors_from_every_control_endpoint_release_session_quota() {
    let (app, directory) = setup();
    let mut sessions = Vec::new();
    for _ in 0..8 {
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
        assert_eq!(opened.status(), StatusCode::OK);
        let opened = json_body(opened).await;
        sessions.push((
            opened["sessionId"].as_str().unwrap().to_owned(),
            opened["events"][0]["cursor"].as_str().unwrap().to_owned(),
        ));
    }

    directory
        .open_writer()
        .execute(
            "UPDATE _replay_subscriptions SET session_generation = ?1",
            [GENERATION + 1],
        )
        .unwrap();

    for (index, (session_id, cursor)) in sessions.into_iter().enumerate() {
        let (endpoint, body) = match index {
            0 | 5 => ("read-page", json!({"limit": 1})),
            1 | 6 => ("acknowledge", json!({"cursor": cursor})),
            2 => ("complete-catch-up", json!({})),
            3 => ("continue-live", json!({})),
            4 | 7 => ("close", json!({})),
            _ => unreachable!("the test opens exactly eight sessions"),
        };
        let terminal = app
            .clone()
            .oneshot(post(&format!("/v1/replay/{session_id}/{endpoint}"), body))
            .await
            .unwrap();
        assert_eq!(terminal.status(), StatusCode::GONE, "{endpoint}");
        assert_eq!(
            json_body(terminal).await["code"],
            "replay_session_expired",
            "{endpoint}"
        );
    }

    let admitted = app
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
    assert_eq!(admitted.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_public_event_schema_stops_before_session_commit() {
    let (app, directory) = setup();
    let row = taskrun_row_with_schema(1, 1, "replay-test".to_owned(), 2);
    directory
        .open_writer()
        .execute(
            "UPDATE events
             SET schema_version = 2, integrity_digest = ?1
             WHERE global_position = 1",
            [row.integrity_digest.as_slice()],
        )
        .unwrap();

    let response = app
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

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await["code"],
        "replay_unsupported_schema"
    );
    assert_eq!(subscription_count(&directory), 0);
}
