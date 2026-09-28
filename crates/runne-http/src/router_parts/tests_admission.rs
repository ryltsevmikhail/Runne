// Exact-model admission router tests (D1.4b): mismatch conflicts before
// the host, matching/absent passes validation, unpinned runtime fails
// closed.

#[tokio::test]
async fn task_run_submit_model_mismatch_conflicts_before_reaching_the_host() {
    const CAPABILITIES: &[&str] = &["task_run.submit.v2"];
    let app = host_with_pinned_task_run_model(CAPABILITIES, Some("fixture-model"))
        .router_for_test();
    let binding = binding_with_capabilities(CAPABILITIES);
    let authority = bootstrap_authority(&app, &binding).await;
    let session = format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/task-runs/submit")
                .header("authorization", session)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"conversationId":"01900000-0000-7000-8000-000000000001",
                        "workspaceId":"01900000-0000-7000-8000-000000000002",
                        "prompt":"x","model":"other-model"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "model mismatch is admitted before the host is reached: {}",
        String::from_utf8_lossy(&bytes)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["code"], "model_mismatch");
}

#[tokio::test]
async fn task_run_submit_matching_or_absent_model_reaches_validation() {
    const CAPABILITIES: &[&str] = &["task_run.submit.v2"];
    let app = host_with_pinned_task_run_model(CAPABILITIES, Some("fixture-model"))
        .router_for_test();
    let binding = binding_with_capabilities(CAPABILITIES);
    let authority = bootstrap_authority(&app, &binding).await;
    let session = format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority));

    for (label, body) in [
        (
            "matching model",
            r#"{"conversationId":"01900000-0000-7000-8000-000000000001",
                "workspaceId":"01900000-0000-7000-8000-000000000002",
                "prompt":"x","model":"fixture-model"}"#,
        ),
        (
            "absent model",
            r#"{"conversationId":"01900000-0000-7000-8000-000000000001",
                "workspaceId":"01900000-0000-7000-8000-000000000002",
                "prompt":"x"}"#,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v2/task-runs/submit")
                    .header("authorization", session.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{label}: admission passes and the request reaches id validation"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            envelope["code"], "invalid_command_id",
            "{label}: admission passed and the request reached command validation"
        );
    }
}

#[tokio::test]
async fn task_run_submit_explicit_model_on_unpinned_runtime_conflicts() {
    const CAPABILITIES: &[&str] = &["task_run.submit.v2"];
    let app = host_with_pinned_task_run_model(CAPABILITIES, None).router_for_test();
    let binding = binding_with_capabilities(CAPABILITIES);
    let authority = bootstrap_authority(&app, &binding).await;
    let session = format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority));
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/task-runs/submit")
                .header("authorization", session)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"conversationId":"01900000-0000-7000-8000-000000000001",
                        "workspaceId":"01900000-0000-7000-8000-000000000002",
                        "prompt":"x","model":"any-model"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "an explicit model cannot be honored without a pinned provider model"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["code"], "model_mismatch");
}
