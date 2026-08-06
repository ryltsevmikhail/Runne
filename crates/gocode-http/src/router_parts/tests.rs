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

        let client_nonce = [9; 32];
        let server_nonce = [8; 32];
        let challenge = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "clientNonce": URL_SAFE_NO_PAD.encode(client_nonce),
                            "serverNonce": URL_SAFE_NO_PAD.encode(server_nonce),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge.status(), StatusCode::OK);
        let challenge: serde_json::Value =
            serde_json::from_slice(&to_bytes(challenge.into_body(), 8192).await.unwrap()).unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(&[7; 32]).unwrap();
        mac.update(&bootstrap_proof_transcript(
            &binding(),
            server_nonce,
            client_nonce,
        ));
        let authority = [10; 32];
        let authenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/authenticate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "challengeId": challenge["challengeId"],
                            "proof": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
                            "authority": URL_SAFE_NO_PAD.encode(authority),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);
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
        let client_nonce = [9; 32];
        let server_nonce = [8; 32];
        let challenge = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "clientNonce": URL_SAFE_NO_PAD.encode(client_nonce),
                            "serverNonce": URL_SAFE_NO_PAD.encode(server_nonce),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let challenge: serde_json::Value =
            serde_json::from_slice(&to_bytes(challenge.into_body(), 8192).await.unwrap()).unwrap();
        let binding = binding_with_capabilities(CAPABILITIES);
        let mut mac = Hmac::<Sha256>::new_from_slice(&[7; 32]).unwrap();
        mac.update(&bootstrap_proof_transcript(
            &binding,
            server_nonce,
            client_nonce,
        ));
        let authority = [10; 32];
        let authenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/authenticate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "challengeId": challenge["challengeId"],
                            "proof": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
                            "authority": URL_SAFE_NO_PAD.encode(authority),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);
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
