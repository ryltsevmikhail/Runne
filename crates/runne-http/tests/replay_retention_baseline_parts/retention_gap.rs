use base64::Engine as _;

#[tokio::test]
async fn authenticated_prefix_gap_returns_a_signed_taskrun_baseline_without_session_state() {
    let fixture = retention_gap_fixture().await;
    let response = fixture.open_authenticated().await;

    let status = response.status();
    let content_type = response.headers().get("content-type").cloned();
    let cache_control = response.headers().get("cache-control").cloned();
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        uuid::Uuid::parse_str(&request_id)
            .unwrap()
            .get_version_num(),
        7
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        status,
        axum::http::StatusCode::GONE,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(content_type.unwrap(), "application/json");
    assert_eq!(cache_control.unwrap(), "no-store");
    assert!(bytes.len() <= 1024 * 1024);
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "replay_retention_gap");
    assert_eq!(body["requestId"], request_id);
    assert!(body.get("sessionId").is_none());
    assert!(body.get("highWaterRef").is_none());
    let baseline = &body["baseline"];
    assert_eq!(baseline["aggregateKind"], "taskRun");
    assert_eq!(
        baseline["aggregateId"],
        hex::encode(fixture.taskrun_id.as_bytes())
    );
    assert_eq!(baseline["sequence"], 2);
    assert_eq!(baseline["version"], 2);
    assert_eq!(baseline["baselineGlobalPosition"], 3);
    assert_eq!(baseline["retainedFloor"], 3);
    assert_eq!(baseline["capturedHighWater"], 3);
    assert_eq!(baseline["retentionGeneration"], 1);
    for field in [
        "projectionBytes",
        "projectionDigest",
        "retentionWitness",
        "witnessMac",
    ] {
        assert!(
            baseline[field]
                .as_str()
                .is_some_and(|value| !value.is_empty() && value.chars().any(|c| c != '0'))
        );
    }
    let projection = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(baseline["projectionBytes"].as_str().unwrap())
        .unwrap();
    let projection =
        runne_api::UnauthenticatedReplayProjectionV1::decode_task_run_bytes(&projection).unwrap();
    assert_eq!(projection.aggregate_id(), *fixture.taskrun_id.as_bytes());
    assert_eq!(fixture.subscriptions(), 0);
}

#[tokio::test]
async fn retention_gap_and_unauthorized_requests_release_every_open_session_permit() {
    let fixture = retention_gap_fixture().await;
    for _ in 0..9 {
        assert_eq!(
            fixture.open_authenticated().await.status(),
            axum::http::StatusCode::GONE
        );
        let response = fixture.open_unauthenticated().await;
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "unauthorized");
        for field in ["baseline", "projectionBytes", "retainedFloor"] {
            assert!(body.get(field).is_none(), "unauthorized response leaked {field}");
        }
    }
    assert_eq!(fixture.subscriptions(), 0);
}

#[tokio::test]
async fn negotiated_v2_resumes_from_the_accepted_current_snapshot() {
    let fixture = retention_gap_fixture().await;
    let v2 = fixture.v2_app();
    let gap = v2
        .clone()
        .oneshot(open_request(fixture.taskrun_id, Some(SESSION_AUTHORITY), Some(&fixture.from_cursor)))
        .await
        .unwrap();
    assert_eq!(gap.status(), axum::http::StatusCode::GONE);
    let gap: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(gap.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(gap["baseline"]["schemaVersion"], 2);
    let response = v2.oneshot(resume_request(&gap["baseline"])).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["acceptedPromotion"]["sequence"], 2);
    assert_eq!(body["acceptedPromotion"]["globalPosition"], 3);
    assert_eq!(body["events"].as_array().unwrap().len(), 0);
    assert_eq!(fixture.subscriptions(), 1);
}

#[tokio::test]
async fn unnegotiated_v2_route_is_absent() {
    let fixture = retention_gap_fixture().await;
    let response = fixture.app.clone().oneshot(resume_request(&serde_json::json!({}))).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    assert_eq!(fixture.subscriptions(), 0);
}

#[tokio::test]
async fn authenticated_interior_gap_preserves_v17_snapshot_binding_and_signs_baseline() {
    let fixture = retention_interior_gap_fixture().await;
    let response = fixture.open_authenticated().await;
    assert_eq!(response.status(), axum::http::StatusCode::GONE);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let baseline = &body["baseline"];
    assert_eq!(baseline["aggregateId"], hex::encode(fixture.taskrun_id.as_bytes()));
    assert_eq!(baseline["sequence"], 2);
    assert_eq!(baseline["version"], 2);
    assert_eq!(baseline["baselineGlobalPosition"], 3);
    assert_eq!(baseline["retainedFloor"], 1);
    assert_eq!(baseline["capturedHighWater"], 3);
    assert!(baseline["retentionWitness"].as_str().is_some_and(|value| value != "0".repeat(64)));
    assert_eq!(fixture.subscriptions(), 0);
}

#[tokio::test]
async fn denied_or_unavailable_baseline_content_returns_closed_error_without_baseline_fields() {
    for guard in [BaselineGuard::Denied, BaselineGuard::Unavailable] {
        let fixture = retention_gap_fixture_with(std::sync::Arc::new(guard)).await;
        let response = fixture.open_authenticated().await;
        assert_ne!(response.status(), axum::http::StatusCode::GONE);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        for field in [
            "baseline",
            "retainedFloor",
            "projectionBytes",
            "projectionDigest",
        ] {
            assert!(body.get(field).is_none(), "closed response leaked {field}");
        }
        assert_eq!(fixture.subscriptions(), 0);
    }
}
