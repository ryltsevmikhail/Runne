fn authenticated_json_request(
    method: &str,
    uri: String,
    body: serde_json::Value,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header(
            "authorization",
            session_authorization_header(&URL_SAFE_NO_PAD.encode(SESSION_AUTHORITY)).unwrap(),
        )
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn resume_into_live(
    fixture: &RetentionGapFixture,
    app: &axum::Router,
) -> (String, axum::response::Response) {
    let baseline = signed_v2_baseline(fixture, app).await;
    let resumed = app
        .clone()
        .oneshot(resume_request(&baseline))
        .await
        .unwrap();
    assert_eq!(resumed.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resumed.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let session_id = body["sessionId"].as_str().unwrap().to_owned();
    let completed = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            format!("/v1/replay/{session_id}/complete-catch-up"),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), axum::http::StatusCode::OK);
    let continued = app
        .clone()
        .oneshot(authenticated_json_request(
            "POST",
            format!("/v1/replay/{session_id}/continue-live"),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(continued.status(), axum::http::StatusCode::OK);
    (session_id, continued)
}

async fn wait_for_session_state(
    fixture: &RetentionGapFixture,
    session_id: &str,
    expected: &str,
) {
    let session_id = uuid::Uuid::parse_str(session_id).unwrap().into_bytes();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let connection = rusqlite::Connection::open(fixture.database_path()).unwrap();
            let state: String = connection
                .query_row(
                    "SELECT state FROM _replay_subscriptions WHERE session_id = ?1",
                    [session_id.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            if state == expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("session state transition timeout");
}

#[tokio::test(start_paused = true)]
async fn delivered_v2_stream_wins_atomically_over_expiry_reaper() {
    let fixture = retention_gap_fixture().await;
    let app = fixture.v2_app();
    let (session_id, _) = resume_into_live(&fixture, &app).await;
    let stream = app
        .clone()
        .oneshot(authenticated_json_request(
            "GET",
            format!("/v1/replay/{session_id}/events"),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(stream.status(), axum::http::StatusCode::OK);
    assert_eq!(stream.headers()["content-type"], "text/event-stream");
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    tokio::task::yield_now().await;
    assert_eq!(fixture.subscriptions(), 1);
    drop(stream);
}

#[tokio::test(start_paused = true)]
async fn expiry_reaper_winner_never_delivers_a_v2_stream() {
    let fixture = retention_gap_fixture().await;
    let app = fixture.v2_app();
    let (session_id, _) = resume_into_live(&fixture, &app).await;
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    wait_for_session_state(&fixture, &session_id, "closed").await;
    let stream = app
        .clone()
        .oneshot(authenticated_json_request(
            "GET",
            format!("/v1/replay/{session_id}/events"),
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_ne!(stream.status(), axum::http::StatusCode::OK);
    let baseline = signed_v2_baseline(&fixture, &app).await;
    for _ in 0..8 {
        assert_eq!(
            app.clone().oneshot(resume_request(&baseline)).await.unwrap().status(),
            axum::http::StatusCode::OK
        );
    }
    assert_eq!(
        app.oneshot(resume_request(&baseline)).await.unwrap().status(),
        axum::http::StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test(start_paused = true)]
async fn blocked_admission_cannot_extend_the_original_delivery_deadline() {
    let fixture = retention_gap_fixture().await;
    let app = fixture.v2_app();
    let baseline = signed_v2_baseline(&fixture, &app).await;
    let lock = rusqlite::Connection::open(fixture.database_path()).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE;").unwrap();
    let request = tokio::spawn(app.clone().oneshot(resume_request(&baseline)));
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert!(!request.is_finished());
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    lock.execute_batch("ROLLBACK;").unwrap();
    let response = request.await.unwrap().unwrap();
    assert_ne!(response.status(), axum::http::StatusCode::OK);
    wait_for_subscription_count(&fixture, 0).await;
}
