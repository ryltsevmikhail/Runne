use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum EntropyFailureMode {
    Empty,
    ClockRegression,
    Capacity,
    Storage,
}

#[tokio::test]
async fn bootstrap_rejections_use_zero_csprng_calls() {
    let (accepted, _directory, accepted_calls) = entropy_state(EntropyFailureMode::Empty);
    let accepted = local_session_router(accepted)
        .oneshot(json_request(
            "/v1/local-session/challenges",
            valid_preallocation_request(),
        ))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(accepted_calls.load(Ordering::SeqCst), 2);

    let mut unknown_key = valid_preallocation_request();
    unknown_key["keyVersion"] = serde_json::json!(2);
    let mut bad_mac = valid_preallocation_request();
    bad_mac["preallocationProof"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0; 32]));
    let cases = [
        (EntropyFailureMode::Empty, "{".to_owned()),
        (EntropyFailureMode::Empty, unknown_key.to_string()),
        (EntropyFailureMode::Empty, bad_mac.to_string()),
        (
            EntropyFailureMode::ClockRegression,
            valid_preallocation_request().to_string(),
        ),
        (
            EntropyFailureMode::Capacity,
            valid_preallocation_request().to_string(),
        ),
        (
            EntropyFailureMode::Storage,
            valid_preallocation_request().to_string(),
        ),
        (
            EntropyFailureMode::Empty,
            "x".repeat(MAX_LOCAL_SESSION_BODY_BYTES + 1),
        ),
    ];

    for (mode, body) in cases {
        let (app, _directory, calls) = entropy_state(mode);
        let response = local_session_router(app)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/local-session/challenges")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

fn entropy_state(
    mode: EntropyFailureMode,
) -> (LocalSessionHttpState, tempfile::TempDir, Arc<AtomicUsize>) {
    let directory = tempfile::tempdir().unwrap();
    let connection = open_managed_connection(
        &directory.path().join("entropy.sqlite"),
        ConnectionMode::Writer,
    )
    .unwrap();
    if !matches!(mode, EntropyFailureMode::Storage) {
        apply_migrations(&connection).unwrap();
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let store = SqliteBootstrapReservationStore::with_entropy_audit(
        connection,
        Arc::clone(&calls),
    );
    if matches!(mode, EntropyFailureMode::ClockRegression) {
        store.observe_clock(200).unwrap();
    }
    if matches!(mode, EntropyFailureMode::Capacity) {
        for key in 0..32_u8 {
            store.preallocate(entropy_input(key)).unwrap();
        }
    }
    calls.store(0, Ordering::SeqCst);
    let service = LocalSessionService::with_reservation_store(
        binding(),
        *binding().stable().authority_id(),
        EXECUTABLE_SHA256,
        [7; 32],
        Arc::new(store),
    );
    let state = LocalSessionHttpState::with_clock(
        Arc::new(Mutex::new(service)),
        Arc::new(|| Some(BootstrapClock::new(100, Duration::ZERO))),
        VerifiedLocalTls::from_verified_listener(),
    );
    (state, directory, calls)
}

fn entropy_input(key: u8) -> PreallocateReservation {
    PreallocateReservation {
        reservation_key: [key; 32],
        binding_proof: [2; 32],
        key_version: 1,
        client_nonce: [3; 32],
        not_before_rfc3339_utc_microseconds: "1970-01-01T00:00:00.000000Z".into(),
        expiry_rfc3339_utc_microseconds: "1970-01-01T00:00:01.000000Z".into(),
        not_before_unix_microseconds: 0,
        expiry_unix_microseconds: 1_000_000,
        observed_at_unix_microseconds: 100,
        fence: 7,
    }
}
