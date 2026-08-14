use gocode_application::{commands::BeginConversationTextInput, conversation_text_service::ConversationTextService};
use gocode_domain::message::MessageText;
use gocode_security::SecretBroker;
use std::sync::Arc;

use axum::{body::Body, http::Request};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use gocode_api::CreateConversationInput;
use gocode_application::{conversation_service::ConversationService, ports::RuntimeAuthorityId};
use gocode_domain::id::{ConversationId, EventLogLineageId, WorkspaceId};
use gocode_http::auth::session_authorization_header;
use gocode_store::{schema::{apply_migrations, ensure_authority_id, ensure_exact_event_log_lineage_id}, store::StoreTransaction};
use tower::ServiceExt;

#[tokio::test]
async fn registered_historical_conversation_marker_at_raw_unaligned_offset_closes_gap_response() {
    let marker = "marker-replay-secret";
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("gocode-daemon");
    std::fs::create_dir(&daemon).unwrap();
    let path = daemon.join("replay.sqlite");
    let connection = rusqlite::Connection::open(&path).unwrap();
    apply_migrations(&connection).unwrap();
    ensure_authority_id(&connection, &AUTHORITY).unwrap();
    ensure_exact_event_log_lineage_id(&connection, EventLogLineageId::from_bytes(LINEAGE)).unwrap();
    drop(connection);
    let authority = RuntimeAuthorityId("retention-http-marker".into());
    let store = StoreTransaction::open(
        &path.to_string_lossy(), authority.clone(), Arc::new(AvailableGuard),
    ).unwrap();
    let workspace_id = WorkspaceId::from_bytes(uuid_v7(0x61));
    seed_workspace(&store, workspace_id);
    let conversation_id = ConversationId::from_bytes(uuid_v7(0x62));
    ConversationService::new(store.clone(), store.clone(), authority.clone()).create(&api_context(), CreateConversationInput { conversation_id, workspace_id, command_id: command(7), idempotency_key: key(7) }).unwrap();
    ConversationTextService::new(store.clone(), store.clone(), authority, Arc::new(AvailableGuard)).begin(&context(8), BeginConversationTextInput { conversation_id, expected_version: 1, text: MessageText::new(format!("x{marker}")).unwrap() }).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let projection: Vec<u8> = connection
        .query_row(
            "SELECT projection_bytes FROM aggregate_state_snapshots WHERE aggregate_type = 2 AND aggregate_id = ?1",
            [conversation_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let marker_offset = projection
        .windows(marker.len())
        .position(|bytes| bytes == marker.as_bytes())
        .unwrap();
    assert_ne!(marker_offset % 3, 0, "marker must cross base64 alignment");
    drop(connection);
    let app = replay_app(&path, binding(), Arc::new(AvailableGuard));
    let response = app.clone().oneshot(conversation_open_request(conversation_id, None)).await.unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let cursor = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["events"][0]["cursor"].as_str().unwrap().to_owned();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute("DELETE FROM events WHERE global_position = 1", []).unwrap();
    connection.execute("DELETE FROM _replay_subscriptions", []).unwrap();
    drop(connection);
    let mut broker = SecretBroker::new();
    broker.register("historical marker", marker.as_bytes().to_vec()).unwrap();
    let app = replay_app(&path, binding(), Arc::new(broker.prohibited_content_guard()));
    let response = app.oneshot(conversation_open_request(conversation_id, Some(&cursor))).await.unwrap();
    assert_ne!(response.status(), axum::http::StatusCode::GONE);
    let body = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("baseline"));
    assert_eq!(rusqlite::Connection::open(&path).unwrap().query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| row.get::<_, i64>(0)).unwrap(), 0);
}

fn conversation_open_request(conversation_id: ConversationId, cursor: Option<&str>) -> Request<Body> {
    Request::builder().method("POST").uri("/v1/replay/open-session")
        .header("content-type", "application/json")
        .header("authorization", session_authorization_header(&URL_SAFE_NO_PAD.encode(SESSION_AUTHORITY)).unwrap())
        .body(Body::from(serde_json::json!({"aggregateType":"conversation","aggregateId":conversation_id.to_string(),"fromCursor":cursor}).to_string())).unwrap()
}
