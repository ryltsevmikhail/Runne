use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gocode_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use gocode_application::local_session::{
    BootstrapProof, LocalSessionService, bootstrap_proof_transcript,
};
use gocode_domain::{event::Sensitivity, id::EventLogLineageId};
use gocode_http::{
    auth::{SessionAuthLayer, session_authorization_header},
    local_session::LocalSessionHttpState,
    router::create_local_session_bootstrap_router,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::ServiceExt;

fn binding() -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
            ApiPrincipalId::new("local-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000003"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "gocode-ui-client/1",
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
fn service() -> LocalSessionService {
    LocalSessionService::new(binding(), [7; 32])
}
fn clock(now: Arc<Mutex<Duration>>) -> Arc<dyn Fn() -> Duration + Send + Sync> {
    Arc::new(move || *now.lock().unwrap())
}
fn proof(server: [u8; 32], client: [u8; 32]) -> BootstrapProof {
    let mut mac = Hmac::<Sha256>::new_from_slice(&[7; 32]).unwrap();
    mac.update(&bootstrap_proof_transcript(&binding(), server, client));
    BootstrapProof::new(mac.finalize().into_bytes().into())
}

#[tokio::test]
async fn actual_bootstrap_routes_are_tls_only_and_reject_unknown_and_oversized_bodies() {
    let now = Arc::new(Mutex::new(Duration::ZERO));
    let app = create_local_session_bootstrap_router(LocalSessionHttpState::for_test(
        service(),
        clock(now),
    ));
    let response = app.clone().oneshot(Request::builder().method("POST").uri("/v1/local-session/challenges").header("content-type", "application/json").body(Body::from(r#"{"clientNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","serverNonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","nowMillis":0,"unexpected":true}"#)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/local-session/challenges")
                .header("content-type", "application/json")
                .body(Body::from(vec![b'x'; 8 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let app = create_local_session_bootstrap_router(LocalSessionHttpState::for_test(
        service(),
        clock(Arc::new(Mutex::new(Duration::ZERO))),
    ));
    let client_nonce = URL_SAFE_NO_PAD.encode([9; 32]);
    let server_nonce = URL_SAFE_NO_PAD.encode([8; 32]);
    let challenge_payload =
        serde_json::json!({"clientNonce": client_nonce, "serverNonce": server_nonce});
    let request = Request::builder()
        .method("POST")
        .uri("/v1/local-session/challenges")
        .header("content-type", "application/json")
        .body(Body::from(challenge_payload.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    let payload = serde_json::json!({"challengeId": challenge["challengeId"], "proof": URL_SAFE_NO_PAD.encode(proof([8; 32], [9; 32]).as_bytes()), "authority": URL_SAFE_NO_PAD.encode([10; 32])});
    let authenticate = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/local-session/authenticate")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authenticate.status(), StatusCode::OK);
    let replay_payload = serde_json::json!({"challengeId": challenge["challengeId"], "proof": URL_SAFE_NO_PAD.encode([0; 32]), "authority": URL_SAFE_NO_PAD.encode([11; 32])});
    let replay_request = Request::builder()
        .method("POST")
        .uri("/v1/local-session/authenticate")
        .header("content-type", "application/json")
        .body(Body::from(replay_payload.to_string()))
        .unwrap();
    let replay = app.oneshot(replay_request).await.unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn issued_authority_is_required_and_redacted_by_service_backed_layer() {
    let mut local = service();
    let challenge = local
        .issue_challenge([9; 32], [8; 32], Duration::ZERO)
        .unwrap();
    local
        .authenticate(
            challenge.id,
            proof([8; 32], [9; 32]),
            [10; 32],
            Duration::ZERO,
        )
        .unwrap();
    let shared = Arc::new(Mutex::new(local));
    let encoded = URL_SAFE_NO_PAD.encode([10; 32]);
    let header = session_authorization_header(&encoded).unwrap();
    assert!(header.is_sensitive());
    assert!(!format!("{header:?}").contains(&encoded));
    let redacted_request = Request::builder()
        .uri("/")
        .header("authorization", header.clone())
        .body(Body::empty())
        .unwrap();
    assert!(!format!("{redacted_request:?}").contains(&encoded));
    let app = Router::new()
        .route(
            "/",
            get(|request: Request<Body>| async move {
                assert!(
                    request
                        .headers()
                        .get("authorization")
                        .unwrap()
                        .is_sensitive()
                );
                assert!(
                    request
                        .extensions()
                        .get::<gocode_application::local_session::AuthenticatedRuntimeSession>()
                        .is_some()
                );
                "ok"
            }),
        )
        .layer(SessionAuthLayer::new(
            shared,
            binding(),
            clock(Arc::new(Mutex::new(Duration::ZERO))),
        ));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("authorization", header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    for request in [
        Request::builder().uri("/").body(Body::empty()).unwrap(),
        Request::builder()
            .uri("/")
            .header("authorization", "GocodeSession invalid=")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/")
            .header("authorization", "GocodeSession first")
            .header("authorization", "GocodeSession second")
            .body(Body::empty())
            .unwrap(),
    ] {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(std::str::from_utf8(&body).unwrap().contains("unauthorized"));
    }
}
