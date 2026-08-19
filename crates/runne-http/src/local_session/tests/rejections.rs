use runne_application::local_session::{
    BootstrapReservationError, BootstrapReservationStore, ConsumeReservation,
    ConsumedReservation, PreallocateReservation, Reservation,
};

struct ForcedFailureStore(BootstrapReservationError);

impl BootstrapReservationStore for ForcedFailureStore {
    fn preallocate(
        &self,
        _: PreallocateReservation,
    ) -> Result<Reservation, BootstrapReservationError> {
        Err(self.0)
    }

    fn consume_final(
        &self,
        _: ConsumeReservation<'_>,
    ) -> Result<ConsumedReservation, BootstrapReservationError> {
        Err(self.0)
    }

    fn observe_clock(&self, _: i64) -> Result<i64, BootstrapReservationError> {
        Err(self.0)
    }
}

#[tokio::test]
async fn both_bootstrap_endpoints_have_one_exact_rejection_contract() {
    let valid_preallocation = valid_preallocation_request();
    let valid_final = serde_json::json!({
        "wireVersion":"3", "keyVersion":1,
        "challengeId":URL_SAFE_NO_PAD.encode([1;16]),
        "finalProof":URL_SAFE_NO_PAD.encode([7;32]),
        "authority":URL_SAFE_NO_PAD.encode([10;32]),
    });
    let mut unknown_preallocation = valid_preallocation.clone();
    unknown_preallocation["unknown"] = serde_json::json!(true);
    let mut wrong_version = valid_preallocation.clone();
    wrong_version["wireVersion"] = serde_json::json!("2");
    let mut wrong_key = valid_preallocation.clone();
    wrong_key["keyVersion"] = serde_json::json!(2);
    let mut bad_nonce = valid_preallocation.clone();
    bad_nonce["clientNonce"] = serde_json::json!("short");
    let mut bad_proof = valid_preallocation;
    bad_proof["preallocationProof"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0; 32]));
    let mut unknown_final = valid_final.clone();
    unknown_final["unknown"] = serde_json::json!(true);
    let mut wrong_final_version = valid_final.clone();
    wrong_final_version["wireVersion"] = serde_json::json!("2");
    let mut wrong_final_key = valid_final.clone();
    wrong_final_key["keyVersion"] = serde_json::json!(2);
    let mut bad_challenge = valid_final.clone();
    bad_challenge["challengeId"] = serde_json::json!("short");

    let cases = vec![
        rejection_case("challenge malformed", "/v1/local-session/challenges", "{".into(), BootstrapReservationError::Rejected),
        rejection_json_case("challenge unknown field", "/v1/local-session/challenges", unknown_preallocation, BootstrapReservationError::Rejected),
        rejection_json_case("challenge version", "/v1/local-session/challenges", wrong_version, BootstrapReservationError::Rejected),
        rejection_json_case("challenge key", "/v1/local-session/challenges", wrong_key, BootstrapReservationError::Rejected),
        rejection_json_case("challenge nonce", "/v1/local-session/challenges", bad_nonce, BootstrapReservationError::Rejected),
        rejection_json_case("challenge proof", "/v1/local-session/challenges", bad_proof, BootstrapReservationError::Rejected),
        rejection_json_case("challenge clock", "/v1/local-session/challenges", valid_preallocation_request(), BootstrapReservationError::ClockRegression),
        rejection_json_case("challenge capacity", "/v1/local-session/challenges", valid_preallocation_request(), BootstrapReservationError::Capacity),
        rejection_json_case("challenge storage", "/v1/local-session/challenges", valid_preallocation_request(), BootstrapReservationError::Storage),
        rejection_case("challenge oversized", "/v1/local-session/challenges", "x".repeat(MAX_LOCAL_SESSION_BODY_BYTES + 1), BootstrapReservationError::Rejected),
        rejection_case("final malformed", "/v1/local-session/authenticate", "{".into(), BootstrapReservationError::Rejected),
        rejection_json_case("final unknown field", "/v1/local-session/authenticate", unknown_final, BootstrapReservationError::Rejected),
        rejection_json_case("final version", "/v1/local-session/authenticate", wrong_final_version, BootstrapReservationError::Rejected),
        rejection_json_case("final key", "/v1/local-session/authenticate", wrong_final_key, BootstrapReservationError::Rejected),
        rejection_json_case("final nonce", "/v1/local-session/authenticate", bad_challenge, BootstrapReservationError::Rejected),
        rejection_json_case("final proof", "/v1/local-session/authenticate", valid_final.clone(), BootstrapReservationError::Rejected),
        rejection_json_case("final clock", "/v1/local-session/authenticate", valid_final.clone(), BootstrapReservationError::ClockRegression),
        rejection_json_case("final capacity", "/v1/local-session/authenticate", valid_final.clone(), BootstrapReservationError::Capacity),
        rejection_json_case("final storage", "/v1/local-session/authenticate", valid_final, BootstrapReservationError::Storage),
        rejection_case("final oversized", "/v1/local-session/authenticate", "x".repeat(MAX_LOCAL_SESSION_BODY_BYTES + 1), BootstrapReservationError::Rejected),
    ];

    for (name, app, request) in cases {
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(
            response
                .headers()
                .iter()
                .map(|(key, value)| (
                    key.as_str().to_owned(),
                    value.to_str().unwrap().to_owned(),
                ))
                .collect::<std::collections::BTreeMap<_, _>>(),
            std::collections::BTreeMap::from([
                ("cache-control".to_owned(), "no-store".to_owned()),
                ("content-length".to_owned(), "80".to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
                (
                    "x-request-id".to_owned(),
                    "00000000-0000-0000-0000-000000000000".to_owned(),
                ),
            ]),
            "{name}",
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"code":"BOOTSTRAP_REJECTED","requestId":"00000000-0000-0000-0000-000000000000"}"#,
            "{name}",
        );
    }
}

fn valid_preallocation_request() -> serde_json::Value {
    let client = [9; 32];
    serde_json::json!({
        "wireVersion":"3", "keyVersion":1,
        "clientNonce":URL_SAFE_NO_PAD.encode(client),
        "notBefore":"1970-01-01T00:00:00.000000Z",
        "expiry":"1970-01-01T00:00:01.000000Z",
        "preallocationProof":proof(&transcript(
            BOOTSTRAP_PREALLOCATION_ENDPOINT_V3,
            &client,
            None,
        )),
    })
}

fn rejection_json_case(
    name: &'static str,
    uri: &'static str,
    body: serde_json::Value,
    error: BootstrapReservationError,
) -> (&'static str, Router, Request<Body>) {
    rejection_case(name, uri, body.to_string(), error)
}

fn rejection_case(
    name: &'static str,
    uri: &'static str,
    body: String,
    error: BootstrapReservationError,
) -> (&'static str, Router, Request<Body>) {
    let service = LocalSessionService::with_reservation_store(
        binding(),
        *binding().stable().authority_id(),
        EXECUTABLE_SHA256,
        [7; 32],
        Arc::new(ForcedFailureStore(error)),
    );
    let state = LocalSessionHttpState::with_clock(
        Arc::new(Mutex::new(service)),
        Arc::new(|| Some(BootstrapClock::new(100, Duration::ZERO))),
        VerifiedLocalTls::from_verified_listener(),
    );
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    (name, local_session_router(state), request)
}
