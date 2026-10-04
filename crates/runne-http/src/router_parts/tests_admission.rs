// Exact-model admission router tests (D1.4b): mismatch conflicts before
// the host, matching/absent passes validation, unpinned runtime fails
// closed.

#[tokio::test]
async fn task_run_submit_model_mismatch_conflicts_before_reaching_the_host() {
    const CAPABILITIES: &[&str] = &["task_run.submit.v2"];
    let app =
        host_with_pinned_task_run_model(CAPABILITIES, Some("fixture-model")).router_for_test();
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
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
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
    let app =
        host_with_pinned_task_run_model(CAPABILITIES, Some("fixture-model")).router_for_test();
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

#[tokio::test]
async fn task_run_submit_rejects_client_selected_profile_without_server_authorization() {
    const CAPABILITIES: &[&str] = &["task_run.submit.v2"];
    let (host, submissions) =
        host_with_submit_capture(CAPABILITIES, Some("fixture-model"), Vec::new());
    let app = host.router_for_test();
    let binding = binding_with_capabilities(CAPABILITIES);
    let authority = bootstrap_authority(&app, &binding).await;
    let response = app.oneshot(Request::builder()
        .method("POST")
        .uri("/v2/task-runs/submit")
        .header("authorization", format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority)))
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"conversationId":"01900000-0000-7000-8000-000000000001","workspaceId":"01900000-0000-7000-8000-000000000002","prompt":"x","model":"fixture-model","profile":{{"profileId":"profile/a","profileDigest":"{}"}}}}"#,
            "01".repeat(32)
        )))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(envelope["code"], "profile_not_available");
    assert!(submissions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn background_model_admission_uses_the_exact_selected_profile_pin() {
    const CAPABILITIES: &[&str] = &["task_run.submit.v2"];
    let profile = runne_domain::task_run::SelectedProviderProfile::new(
        "gocode-openai-responses-background-text/1".to_owned(),
        [
            0xf8, 0x2a, 0xab, 0xfa, 0x25, 0xea, 0xfe, 0x26, 0x12, 0xc3, 0xf3, 0x06, 0x42, 0xcc,
            0x53, 0xe7, 0x51, 0xe0, 0xfc, 0x7d, 0xff, 0xb7, 0x05, 0xe5, 0x91, 0xa9, 0x35, 0x32,
            0xcc, 0x1e, 0xe7, 0xa7,
        ],
    )
    .unwrap();
    let (host, submissions) = host_with_submit_capture(
        CAPABILITIES,
        Some("gpt-5.4"),
        vec![(profile.clone(), "gpt-5.5".to_owned())],
    );
    let app = host.router_for_test();
    let authority = bootstrap_authority(&app, &binding_with_capabilities(CAPABILITIES)).await;
    let session = format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority));
    let submit = |model: &str,
                  profile_digest: &str,
                  include_profile: bool,
                  command_suffix: &str| {
        let profile_json = if include_profile {
            format!(
                r#","profile":{{"profileId":"{}","profileDigest":"{}"}}"#,
                profile.profile_id(),
                profile_digest
            )
        } else {
            String::new()
        };
        Request::builder()
            .method("POST")
            .uri("/v2/task-runs/submit")
            .header("authorization", session.clone())
            .header("content-type", "application/json")
            .header(
                "x-command-id",
                format!("01900000-0000-7000-8000-000000000{command_suffix}"),
            )
            .header("idempotency-key", format!("model-admission-{command_suffix}"))
            .body(Body::from(format!(
                r#"{{"conversationId":"01900000-0000-7000-8000-000000000001","workspaceId":"01900000-0000-7000-8000-000000000002","prompt":"x","model":"{model}"{profile_json}}}"#
            )))
            .unwrap()
    };

    let background = app
        .clone()
        .oneshot(submit(
            "gpt-5.5",
            "f82aabfa25eafe2612c3f30642cc53e751e0fc7dffb705e591a93532cc1ee7a7",
            true,
            "010",
        ))
        .await
        .unwrap();
    assert_eq!(background.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(submissions.lock().unwrap().len(), 1);
    assert_eq!(
        submissions.lock().unwrap()[0].input.requested_model(),
        Some("gpt-5.5")
    );
    assert_eq!(
        submissions.lock().unwrap()[0].input.selected_profile(),
        Some(&profile)
    );

    let mismatch = app
        .clone()
        .oneshot(submit(
            "gpt-5.4",
            "f82aabfa25eafe2612c3f30642cc53e751e0fc7dffb705e591a93532cc1ee7a7",
            true,
            "011",
        ))
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(mismatch.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
        "model_mismatch"
    );
    assert_eq!(submissions.lock().unwrap().len(), 1);

    let stale_profile = app
        .clone()
        .oneshot(submit(
            "gpt-5.5",
            "f82aabfa25eafe2612c3f30642cc53e751e0fc7dffb705e591a93532cc1ee7a6",
            true,
            "012",
        ))
        .await
        .unwrap();
    assert_eq!(stale_profile.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(stale_profile.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
        "profile_not_available"
    );
    assert_eq!(submissions.lock().unwrap().len(), 1);

    let wrong_primary = app
        .clone()
        .oneshot(submit("gpt-5.5", "", false, "013"))
        .await
        .unwrap();
    assert_eq!(wrong_primary.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(wrong_primary.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["code"],
        "model_mismatch"
    );
    assert_eq!(submissions.lock().unwrap().len(), 1);

    let primary = app
        .oneshot(submit("gpt-5.4", "", false, "014"))
        .await
        .unwrap();
    assert_eq!(primary.status(), StatusCode::SERVICE_UNAVAILABLE);
    let submissions = submissions.lock().unwrap();
    assert_eq!(submissions.len(), 2);
    assert!(submissions[1].input.selected_profile().is_none());
    assert_eq!(submissions[1].input.requested_model(), Some("gpt-5.4"));
}
