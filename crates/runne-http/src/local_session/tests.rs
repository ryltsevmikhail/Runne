use super::*;
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use runne_application::local_session::{
    BOOTSTRAP_FINAL_ENDPOINT_V3, BOOTSTRAP_HTTP_METHOD_V3, BOOTSTRAP_PREALLOCATION_ENDPOINT_V3,
    BOOTSTRAP_PROTOCOL_V3, BootstrapClock, LocalSessionService,
};
use runne_domain::{event::Sensitivity, id::EventLogLineageId};
use runne_pairing_crypto::{
    BootstrapTranscriptV3, encode_final_transcript, encode_preallocation_transcript,
};
use runne_store::{
    local_session::SqliteBootstrapReservationStore,
    schema::{ConnectionMode, apply_migrations, open_managed_connection},
};
use hmac::{Hmac, Mac};
use tower::ServiceExt;

const EXECUTABLE_SHA256: [u8; 32] = [0x0e; 32];

fn binding() -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
            ApiPrincipalId::new("local-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000003"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "gocode-ui-client/2",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2]),
        7,
        [5; 16],
        3,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap()
}

fn state() -> (LocalSessionHttpState, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let connection = open_managed_connection(
        &directory.path().join("bootstrap.sqlite"),
        ConnectionMode::Writer,
    )
    .unwrap();
    apply_migrations(&connection).unwrap();
    let store = Arc::new(SqliteBootstrapReservationStore::new(connection));
    let launch_authority = *binding().stable().authority_id();
    let service = LocalSessionService::with_reservation_store(
        binding(),
        launch_authority,
        EXECUTABLE_SHA256,
        [7; 32],
        store,
    );
    let clock = Arc::new(|| Some(BootstrapClock::new(100, Duration::ZERO)));
    (
        LocalSessionHttpState::with_clock(
            Arc::new(Mutex::new(service)),
            clock,
            VerifiedLocalTls::from_verified_listener(),
        ),
        directory,
    )
}

fn transcript(endpoint: &[u8], client: &[u8; 32], server: Option<[u8; 32]>) -> Vec<u8> {
    let binding = binding();
    let stable = binding.stable();
    let instance = binding.ephemeral().daemon_instance_id().into_bytes();
    let generation = binding.ephemeral().launch_generation().to_be_bytes();
    let fields: [&[u8]; 16] = [
        BOOTSTRAP_PROTOCOL_V3,
        stable.authority_id(),
        stable.principal_id().as_str().as_bytes(),
        stable.lineage_id().as_bytes(),
        stable.profile_id().as_bytes(),
        stable.schema_hash(),
        &EXECUTABLE_SHA256,
        &instance,
        &generation,
        binding.ephemeral().session_id(),
        endpoint,
        BOOTSTRAP_HTTP_METHOD_V3,
        b"1970-01-01T00:00:00.000000Z",
        b"1970-01-01T00:00:01.000000Z",
        client,
        &[],
    ];
    let input = BootstrapTranscriptV3 {
        key_version: 1,
        fields,
    };
    server.map_or_else(
        || encode_preallocation_transcript(&input).unwrap(),
        |nonce| encode_final_transcript(&input, nonce).unwrap(),
    )
}

fn proof(transcript: &[u8]) -> String {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&[7; 32]).unwrap();
    mac.update(transcript);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[tokio::test]
async fn verified_tls_router_issues_and_consumes_a_challenge() {
    assert_verified_tls_router_issues_and_consumes_a_challenge().await;
}

pub(crate) async fn assert_verified_tls_router_issues_and_consumes_a_challenge() {
    let (state, _directory) = state();
    let app = local_session_router(state);
    let client = [9; 32];
    let request = serde_json::json!({
        "wireVersion":"3", "keyVersion":1,
        "clientNonce":URL_SAFE_NO_PAD.encode(client),
        "notBefore":"1970-01-01T00:00:00.000000Z",
        "expiry":"1970-01-01T00:00:01.000000Z",
        "preallocationProof":proof(&transcript(BOOTSTRAP_PREALLOCATION_ENDPOINT_V3, &client, None)),
    });
    let response = app
        .clone()
        .oneshot(json_request("/v1/local-session/challenges", request))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(challenge["wireVersion"], "3");
    assert_eq!(challenge["keyVersion"], 1);
    let server: [u8; 32] = URL_SAFE_NO_PAD
        .decode(challenge["serverNonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let final_request = serde_json::json!({
        "wireVersion":"3", "keyVersion":1,
        "challengeId":challenge["challengeId"],
        "finalProof":proof(&transcript(BOOTSTRAP_FINAL_ENDPOINT_V3, &client, Some(server))),
        "authority":URL_SAFE_NO_PAD.encode([10;32]),
    });
    let response = app
        .oneshot(json_request(
            "/v1/local-session/authenticate",
            final_request,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let authenticated: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(authenticated["wireVersion"], "3");
    assert_eq!(authenticated["keyVersion"], 1);
}

#[tokio::test]
async fn oversized_transport_body_has_canonical_rejection() {
    assert_oversized_transport_body_has_canonical_rejection().await;
}

#[tokio::test]
async fn downgrade_alias_and_unknown_fields_are_closed_rejections() {
    for value in [
        serde_json::json!({
            "wireVersion":"2", "keyVersion":1,
            "clientNonce":URL_SAFE_NO_PAD.encode([9;32]),
            "notBefore":"1970-01-01T00:00:00.000000Z",
            "expiry":"1970-01-01T00:00:01.000000Z",
            "preallocationProof":URL_SAFE_NO_PAD.encode([7;32]),
        }),
        serde_json::json!({
            "wireVersion":"3", "keyVersion":1,
            "clientNonce":URL_SAFE_NO_PAD.encode([9;32]),
            "serverNonce":URL_SAFE_NO_PAD.encode([8;32]),
            "notBefore":"1970-01-01T00:00:00.000000Z",
            "expiry":"1970-01-01T00:00:01.000000Z",
            "preallocationProof":URL_SAFE_NO_PAD.encode([7;32]),
        }),
        serde_json::json!({
            "keyVersion":1,
            "clientNonce":URL_SAFE_NO_PAD.encode([9;32]),
            "notBefore":"1970-01-01T00:00:00.000000Z",
            "expiry":"1970-01-01T00:00:01.000000Z",
            "preallocationProof":URL_SAFE_NO_PAD.encode([7;32]),
        }),
        serde_json::json!({
            "wire_version":"3", "key_version":1,
            "client_nonce":URL_SAFE_NO_PAD.encode([9;32]),
            "not_before":"1970-01-01T00:00:00.000000Z",
            "expiry":"1970-01-01T00:00:01.000000Z",
            "preallocation_proof":URL_SAFE_NO_PAD.encode([7;32]),
        }),
        serde_json::json!({
            "wireVersion":"3", "keyVersion":1,
            "clientNonce":URL_SAFE_NO_PAD.encode([9;32]),
            "notBefore":"1970-01-01T00:00:00Z",
            "expiry":"1970-01-01T00:00:01Z",
            "preallocationProof":URL_SAFE_NO_PAD.encode([7;32]),
        }),
    ] {
        let (state, _directory) = state();
        let response = local_session_router(state)
            .oneshot(json_request("/v1/local-session/challenges", value))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["code"], "BOOTSTRAP_REJECTED");
    }
}

pub(crate) async fn assert_oversized_transport_body_has_canonical_rejection() {
    let (state, _directory) = state();
    let response = local_session_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/local-session/challenges")
                .header("content-type", "application/json")
                .body(Body::from("x".repeat(MAX_LOCAL_SESSION_BODY_BYTES + 1)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["code"], "BOOTSTRAP_REJECTED");
}

fn json_request(uri: &str, value: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}

include!("tests/rejections.rs");
include!("tests/entropy.rs");
