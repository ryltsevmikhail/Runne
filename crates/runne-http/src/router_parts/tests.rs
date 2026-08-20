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
            ("POST", "/v1/task-runs"),
            (
                "GET",
                "/v1/conversations/018f2e3a-7000-7000-8000-000000000001/messages",
            ),
            ("POST", "/v1/replay/open-session"),
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
        assert!(to_bytes(response.into_body(), 1024).await.unwrap().is_empty());

        let absent = host_with_operational_telemetry(CAPABILITIES, None).unwrap();
        let app = absent.router_for_test();
        let binding = binding_with_capabilities(CAPABILITIES);
        let authority = bootstrap_authority(&app, &binding).await;
        let response = app
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
