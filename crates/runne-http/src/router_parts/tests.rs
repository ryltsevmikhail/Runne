#[tokio::test]
async fn sealed_host_contour_shares_bootstrap_service_with_profile_auth() {
    let app = host().router_for_test();
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    for (method, uri) in [
        ("GET", "/v1/runtime/profile"),
        ("POST", "/v1/task-runs/submit"),
        (
            "GET",
            "/v1/conversations/018f2e3a-7000-7000-8000-000000000001/messages",
        ),
        ("POST", "/v1/replay/open-session"),
        ("PUT", "/v1/providers/openai/credential"),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} must be protected by SessionAuthLayer"
        );
    }

    let authority = bootstrap_authority(&app, &binding()).await;
    let profile = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/runtime/profile")
                .header(
                    "authorization",
                    format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority)),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(profile.status(), StatusCode::OK);

    let unsupported = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/providers/openai/credential")
                .header(
                    "authorization",
                    format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority)),
                )
                .body(Body::from("credential=must-not-be-read"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unsupported.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(unsupported.into_body(), 1024).await.unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("provider_credential_control_v1_unsupported")
    );
}

#[tokio::test]
async fn operational_telemetry_is_capability_gated_and_auth_no_store() {
    const TELEMETRY_CAPABILITIES: &[&str] = &[OPERATIONAL_TELEMETRY_CAPABILITY_V1];
    let telemetry = OperationalTelemetryHttpState::new(Arc::new(UnavailableOperationalTelemetry));
    let response = host_with_operational_telemetry(TELEMETRY_CAPABILITIES, Some(telemetry))
        .unwrap()
        .router_for_test()
        .oneshot(
            Request::builder()
                .uri("/v1/runtime/operational-telemetry")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );

    let absent = host_with_operational_telemetry(CAPABILITIES, None).unwrap();
    let app = absent.router_for_test();
    let binding = binding_with_capabilities(CAPABILITIES);
    let authority = bootstrap_authority(&app, &binding).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/runtime/operational-telemetry")
                .header(
                    "authorization",
                    format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority)),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response.headers().get("cache-control").is_none());

    let telemetry = OperationalTelemetryHttpState::new(Arc::new(UnavailableOperationalTelemetry));
    assert!(matches!(
        host_with_operational_telemetry(CAPABILITIES, Some(telemetry)),
        Err(SecureLocalHttpHostError::OperationalTelemetryCapabilityMissing)
    ));
}

#[test]
fn provider_credential_enrollment_v2_capability_requires_authenticated_admission() {
    const UNADMITTED_CAPABILITIES: &[&str] = &[
        OPERATIONAL_TELEMETRY_CAPABILITY_V1,
        runne_api::PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2,
    ];
    let telemetry = OperationalTelemetryHttpState::new(Arc::new(UnavailableOperationalTelemetry));
    assert!(matches!(
        host_with_operational_telemetry(UNADMITTED_CAPABILITIES, Some(telemetry)),
        Err(SecureLocalHttpHostError::ProviderCredentialEnrollmentAdmissionMissing)
    ));
}

#[tokio::test]
async fn local_client_contour_mounts_only_the_canonical_task_run_surface() {
    let app = host().router_for_test();
    let binding = binding();
    let authority = bootstrap_authority(&app, &binding).await;
    let session = format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority));

    // The runtime-owned create/queue/admit/attempt/complete transitions are
    // authority surface only; the local client contour must not mount them.
    // `/v1/task-runs` itself stays mounted for GET (list), so its POST is
    // rejected with 405; every transition subpath is absent entirely (404).
    for (method, uri, expected) in [
        ("POST", "/v1/task-runs", StatusCode::METHOD_NOT_ALLOWED),
        (
            "POST",
            "/v1/task-runs/018f2e3a-7000-7000-8000-000000000040/queue",
            StatusCode::NOT_FOUND,
        ),
        (
            "POST",
            "/v1/task-runs/018f2e3a-7000-7000-8000-000000000040/admit",
            StatusCode::NOT_FOUND,
        ),
        (
            "POST",
            "/v1/task-runs/018f2e3a-7000-7000-8000-000000000040/attempts",
            StatusCode::NOT_FOUND,
        ),
        (
            "POST",
            "/v1/task-runs/018f2e3a-7000-7000-8000-000000000040/complete",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("authorization", &session)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{method} {uri}");
    }

    // The client-facing atomic submit is mounted and reaches validation.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/task-runs/submit")
                .header("authorization", &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .oneshot(Request::builder().method("POST").uri("/v2/task-runs/submit")
            .header("authorization", &session).body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "legacy profile must not mount prompted submit v2");
}

#[tokio::test]
async fn prompted_submit_v2_is_mounted_when_profile_advertises_capability() {
    const CAPABILITIES: &[&str] = &["conversation.create.v1", "conversation.list.v1", "task_run.submit.v2"];
    let host = host_with_capabilities(CAPABILITIES);
    let app = host.router_for_test();
    let authority = bootstrap_authority(&app, &binding_with_capabilities(CAPABILITIES)).await;
    let session = format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority));
    let response = app.oneshot(Request::builder().method("POST").uri("/v2/task-runs/submit")
        .header("authorization", session).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "advertised v2 route should reach request validation");
}
