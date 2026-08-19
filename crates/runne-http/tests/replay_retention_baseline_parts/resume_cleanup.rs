async fn signed_v2_baseline(
    fixture: &RetentionGapFixture,
    app: &axum::Router,
) -> serde_json::Value {
    let gap = app
        .clone()
        .oneshot(open_request(
            fixture.taskrun_id,
            Some(SESSION_AUTHORITY),
            Some(&fixture.from_cursor),
        ))
        .await
        .unwrap();
    assert_eq!(gap.status(), axum::http::StatusCode::GONE);
    let body = axum::body::to_bytes(gap.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["baseline"].clone()
}

async fn wait_for_subscription_count(fixture: &RetentionGapFixture, expected: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if fixture.subscriptions() == expected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("subscription cleanup timeout");
}

async fn wait_for_cancelled_admission_cleanup(fixture: &RetentionGapFixture) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            // Test-only audit table this test injects; managed reopens reject
            // extra objects, so the probe stays on a raw test connection.
            let connection = rusqlite::Connection::open(fixture.database_path()).unwrap();
            let inserted: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM resume_cleanup_audit WHERE action='insert'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let deleted: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM resume_cleanup_audit WHERE action='delete'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            if inserted == 1 && deleted == 1 && fixture.subscriptions() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled admission cleanup timeout");
}

async fn wait_for_inserted_subscription(fixture: &RetentionGapFixture) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while fixture.subscriptions() != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("resume admission insertion timeout");
}

async fn wait_for_cleanup_audit(
    fixture: &RetentionGapFixture,
    table: &str,
    action: &str,
) {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            // The audited tables are test-only DDL this test injects; managed
            // reopens reject non-released objects, so read via raw connection.
            let connection = rusqlite::Connection::open(fixture.database_path()).unwrap();
            let count: i64 = connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE action = ?1"),
                    [action],
                    |row| row.get(0),
                )
                .unwrap();
            if count == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("resume cleanup audit timeout");
}

#[tokio::test]
async fn cancelled_blocked_resume_releases_durable_session_and_ninth_quota_slot() {
    let fixture = retention_gap_fixture().await;
    let app = fixture.v2_app();
    let baseline = signed_v2_baseline(&fixture, &app).await;
    // Race-simulation lock also injecting test-only audit tables/triggers;
    // managed reopens reject them, so the DDL runs on a raw test connection.
    let lock = rusqlite::Connection::open(fixture.database_path()).unwrap();
    lock.execute_batch(
        "CREATE TABLE resume_cleanup_audit(action TEXT NOT NULL);
         CREATE TRIGGER audit_resume_insert AFTER INSERT ON _replay_subscriptions BEGIN
           INSERT INTO resume_cleanup_audit(action) VALUES('insert');
         END;
         CREATE TRIGGER audit_resume_delete AFTER DELETE ON _replay_subscriptions BEGIN
           INSERT INTO resume_cleanup_audit(action) VALUES('delete');
         END;
         CREATE TRIGGER reject_first_cancelled_resume_delete
         BEFORE DELETE ON _replay_subscriptions BEGIN
           INSERT INTO resume_cleanup_audit(action) VALUES('rejected_delete');
           SELECT RAISE(IGNORE);
         END;
         BEGIN IMMEDIATE;",
    )
    .unwrap();
    let request = tokio::spawn(app.clone().oneshot(resume_request(&baseline)));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!request.is_finished(), "resume must be blocked by writer lock");
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    lock.execute_batch("ROLLBACK").unwrap();
    wait_for_inserted_subscription(&fixture).await;
    wait_for_cleanup_audit(&fixture, "resume_cleanup_audit", "rejected_delete").await;
    lock.execute_batch("DROP TRIGGER reject_first_cancelled_resume_delete;")
        .unwrap();
    wait_for_cancelled_admission_cleanup(&fixture).await;

    for admission in 1..=8 {
        let response = app
            .clone()
            .oneshot(resume_request(&baseline))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::OK,
            "admission {admission} should retain its quota slot"
        );
    }
    assert_eq!(fixture.subscriptions(), 8);
}

#[tokio::test]
async fn denied_final_resume_response_aborts_session_and_releases_quota() {
    let fixture = retention_gap_fixture().await;
    let available = fixture.v2_app();
    let baseline = signed_v2_baseline(&fixture, &available).await;
    let denied = fixture.v2_app_with_guard(std::sync::Arc::new(ResumeResponseDeniedGuard));
    // Injects test-only audit table/trigger; managed reopens reject these
    // non-released objects, so the DDL runs on a raw test connection.
    let connection = rusqlite::Connection::open(fixture.database_path()).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE denied_resume_cleanup_audit(action TEXT NOT NULL);
             CREATE TRIGGER reject_first_denied_resume_delete
             BEFORE DELETE ON _replay_subscriptions BEGIN
               INSERT INTO denied_resume_cleanup_audit(action) VALUES('rejected_delete');
               SELECT RAISE(IGNORE);
             END;",
        )
        .unwrap();
    let response = denied.oneshot(resume_request(&baseline)).await.unwrap();
    assert_ne!(response.status(), axum::http::StatusCode::OK);
    wait_for_inserted_subscription(&fixture).await;
    wait_for_cleanup_audit(
        &fixture,
        "denied_resume_cleanup_audit",
        "rejected_delete",
    )
    .await;
    connection
        .execute_batch("DROP TRIGGER reject_first_denied_resume_delete;")
        .unwrap();
    wait_for_subscription_count(&fixture, 0).await;
}

#[tokio::test]
async fn v2_resume_auth_and_validation_errors_are_never_cacheable() {
    let fixture = retention_gap_fixture().await;
    let app = fixture.v2_app();
    let mut unauthorized = resume_request(&serde_json::json!({}));
    unauthorized.headers_mut().remove("authorization");
    let unauthorized = app.clone().oneshot(unauthorized).await.unwrap();
    assert_eq!(unauthorized.status(), axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized.headers()["cache-control"], "no-store");

    let invalid = resume_request(&serde_json::json!({}));
    let invalid = app.oneshot(invalid).await.unwrap();
    assert_eq!(invalid.status(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(invalid.headers()["cache-control"], "no-store");
}

#[tokio::test(start_paused = true)]
async fn lost_v2_success_body_expires_admission_and_releases_all_quota() {
    let fixture = retention_gap_fixture().await;
    let app = fixture.v2_app();
    let baseline = signed_v2_baseline(&fixture, &app).await;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, app.clone()).into_future());
    let body = serde_json::json!({"baseline": baseline}).to_string();
    let authorization = runne_http::auth::session_authorization_header(
        &URL_SAFE_NO_PAD.encode(SESSION_AUTHORITY),
    )
    .unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    use tokio::io::AsyncWriteExt as _;
    stream
        .write_all(
            format!(
                "POST /v1/replay/resume-from-baseline HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nAuthorization: {}\r\nContent-Length: {}\r\n\r\n{body}",
                authorization.to_str().unwrap(),
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    for _ in 0..1_000 {
        if fixture.subscriptions() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(fixture.subscriptions(), 1);
    drop(stream);
    for _ in 1..8 {
        assert_eq!(
            app.clone().oneshot(resume_request(&baseline)).await.unwrap().status(),
            axum::http::StatusCode::OK
        );
    }
    assert_eq!(fixture.subscriptions(), 8);
    assert_eq!(
        app.clone().oneshot(resume_request(&baseline)).await.unwrap().status(),
        axum::http::StatusCode::TOO_MANY_REQUESTS
    );

    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    wait_for_subscription_count(&fixture, 0).await;
    let fresh = signed_v2_baseline(&fixture, &app).await;
    for _ in 0..8 {
        assert_eq!(
            app.clone().oneshot(resume_request(&fresh)).await.unwrap().status(),
            axum::http::StatusCode::OK
        );
    }
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn v2_delivery_lease_retries_a_failed_server_close() {
    let fixture = retention_gap_fixture().await;
    let app = fixture.v2_app();
    let baseline = signed_v2_baseline(&fixture, &app).await;
    let response = app
        .clone()
        .oneshot(resume_request(&baseline))
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    drop(response);
    // Injects a test-only trigger; managed reopens reject non-released objects,
    // so the DDL runs on a raw test connection.
    let connection = rusqlite::Connection::open(fixture.database_path()).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_expired_resume_delete
             BEFORE DELETE ON _replay_subscriptions BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();

    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    tokio::task::yield_now().await;
    assert_eq!(fixture.subscriptions(), 1);
    connection
        .execute_batch("DROP TRIGGER reject_expired_resume_delete;")
        .unwrap();
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    wait_for_subscription_count(&fixture, 0).await;

    let fresh = signed_v2_baseline(&fixture, &app).await;
    for _ in 0..8 {
        assert_eq!(
            app.clone().oneshot(resume_request(&fresh)).await.unwrap().status(),
            axum::http::StatusCode::OK
        );
    }
}
