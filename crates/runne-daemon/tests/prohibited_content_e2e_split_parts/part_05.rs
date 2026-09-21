// NM-06 replay-e2e helpers (shared test surface for the delivery re-check
// scenarios in part_04): echo provider, trust sidecar writes, replay requests
// and the bytes-absence assertion.

/// Runs one replay request and asserts (without leaking bytes) it is denied.
async fn expect_replay_denied(
    replay: axum::Router,
    request: Request<Body>,
    representations: &[(&'static str, Vec<u8>)],
    label: &str,
) {
    let response = replay.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_ne!(status, StatusCode::OK, "{label} must be denied");
    assert_absent(label, &body, representations);
}

struct CleanProvider {
    calls: Arc<AtomicUsize>,
}

impl LocalTextProvider for CleanProvider {
    fn generate(&self, input: &MessageText) -> Result<MessageText, LocalTextProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        MessageText::new(format!("clean reply to: {}", input.as_str()))
            .map_err(|_| LocalTextProviderError::InvalidOutput)
    }
}

const TRUST_AUTHORITY: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x6e, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const NM06_PROJECT: &str = "018f2e3a-7000-7000-8000-000000000773";


fn set_project_trust(db_path: &std::path::Path, status: ProjectTrustStatus) {
    use runne_application::project_trust::{
        ProjectTrustPersistence, ProjectTrustProjectId, TrustToken,
    };
    let store = runne_store::ProjectTrustStore::open(db_path, TRUST_AUTHORITY).unwrap();
    let project =
        ProjectTrustProjectId::from_bytes(*NM06_PROJECT.parse::<ProjectId>().unwrap().as_bytes());
    let token = match status {
        ProjectTrustStatus::Trusted => TrustToken::new(store.instance_epoch().unwrap(), 0),
        _ => store.load(project).unwrap().token(),
    };
    store.commit(project, status, 0, token).unwrap();
}

fn open_session_request(conversation_id: &ConversationId) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/replay/open-session")
        .header("authorization", session_header())
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "aggregateType": "conversation",
                "aggregateId": hex::encode(conversation_id.as_bytes()),
            }))
            .unwrap(),
        ))
        .unwrap()
}

fn session_header() -> axum::http::HeaderValue {
    session_authorization_header(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SESSION_AUTHORITY),
    )
    .unwrap()
}

fn continue_live_request(session_hex: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/v1/replay/{session_hex}/continue-live"))
        .header("authorization", session_header())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap()
}

fn read_page_request(session_hex: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/v1/replay/{session_hex}/read-page"))
        .header("authorization", session_header())
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap()
}

