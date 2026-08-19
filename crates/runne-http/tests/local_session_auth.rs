use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    middleware,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use runne_application::local_session::{
    BootstrapProof, LocalSessionService, bootstrap_proof_transcript,
};
use runne_domain::{event::Sensitivity, id::EventLogLineageId};
use runne_http::auth::{SessionAuthLayer, session_authorization_header};
use runne_http::middleware::request_id_middleware;
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
            "runne-ui-client/2",
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
    let marker = format!("RunneSession {encoded}");
    let header: axum::http::HeaderValue = format!("RunneSession {encoded}").parse().unwrap();
    assert!(!header.is_sensitive());
    let outbound = session_authorization_header(&encoded).unwrap();
    assert!(outbound.is_sensitive());
    assert!(!format!("{outbound:?}").contains(&encoded));
    let captured = Arc::new(Mutex::new(String::new()));
    let captured_handler = captured.clone();
    let app = Router::new()
        .route(
            "/",
            get(move |request: Request<Body>| {
                let captured = captured_handler.clone();
                async move {
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
                            .get::<runne_application::local_session::AuthenticatedRuntimeSession>()
                            .is_some()
                    );
                    *captured.lock().unwrap() = format!("{request:?}");
                    "ok"
                }
            }),
        )
        .layer(SessionAuthLayer::new(
            shared,
            binding(),
            clock(Arc::new(Mutex::new(Duration::ZERO))),
        ))
        .layer(middleware::from_fn(request_id_middleware));
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
    assert!(!captured.lock().unwrap().contains(&marker));
    for request in [
        Request::builder().uri("/").body(Body::empty()).unwrap(),
        Request::builder()
            .uri("/")
            .header("authorization", "RunneSession invalid=")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/")
            .header("authorization", "RunneSession first")
            .header("authorization", "RunneSession second")
            .body(Body::empty())
            .unwrap(),
    ] {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let request_id = response
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(
            uuid::Uuid::parse_str(&request_id)
                .unwrap()
                .get_version_num()
                == 7
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "unauthorized");
        assert_eq!(body["requestId"], request_id);
    }
}
