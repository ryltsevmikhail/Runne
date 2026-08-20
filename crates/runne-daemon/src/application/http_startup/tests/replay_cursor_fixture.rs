mod support;

use super::replay_cursor_integrity_secret;
use crate::replay_key::ReplayIntegrityKeyManager;
use runne_application::replay_service::ReplayService;
use runne_domain::id::EventLogLineageId;
use serde_json::json;
use std::sync::Arc;
use support::*;
use tower::ServiceExt;

const FROZEN_CURSOR: &str = "gocode-replay-cursor-v1.7b226576656e745f6964223a5b312c3134332c34362c35382c3131322c302c3131322c302c3132382c302c302c302c302c302c302c38315d2c226167677265676174655f6964223a7b22436f6e766572736174696f6e223a5b312c3134332c34362c35382c3131322c302c3131322c302c3132382c302c302c302c302c302c302c38325d7d2c2273657175656e6365223a332c22676c6f62616c5f706f736974696f6e223a392c226c696e656167655f6964223a5b312c3134332c34362c35382c3131322c302c3131322c302c3132382c302c302c302c302c302c302c38335d2c2273636f7065223a7b22416767726567617465223a7b226167677265676174655f74797065223a322c226167677265676174655f6964223a5b312c3134332c34362c35382c3131322c302c3131322c302c3132382c302c302c302c302c302c302c38325d7d7d2c22736368656d615f76657273696f6e223a312c2273656e7369746976697479223a22496e7465726e616c222c226576656e745f74797065223a22636f6e766572736174696f6e2e6d6573736167652e63726561746564222c22696e74656772697479223a5b3235322c32302c3131382c35352c382c3131352c3132312c35392c3136332c3134312c3139362c31372c3132332c37382c3135312c3231312c38322c3232302c3130312c38382c35342c3130362c3234382c3132342c3231362c32392c3136322c36352c39372c3139392c3139302c31365d7d";

#[tokio::test]
async fn pre_rename_cursor_fixture_survives_key_reload_and_rejects_runne_domain() {
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("replay-integrity.key");
    std::fs::write(&key_path, ROOT_KEY).unwrap();
    let first_key = ReplayIntegrityKeyManager::load_existing(&key_path).unwrap();
    let restarted_key = ReplayIntegrityKeyManager::load_existing(&key_path).unwrap();
    let store = Arc::new(FixtureStore::default());
    let first = ReplayService::new(
        store.clone(),
        replay_cursor_integrity_secret(&first_key),
        EventLogLineageId::from_bytes(LINEAGE),
        Arc::new(AllowAuthorization),
    );
    let cursor = first
        .build_cursor_from_event(&fixture_event(), &fixture_scope())
        .unwrap();
    let serialized = encode_cursor(&cursor);
    assert_eq!(serialized, FROZEN_CURSOR);

    let app = fixture_router(ReplayService::new(
        store.clone(),
        replay_cursor_integrity_secret(&restarted_key),
        EventLogLineageId::from_bytes(LINEAGE),
        Arc::new(AllowAuthorization),
    ));
    let opened = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": "conversation",
                "aggregateId": aggregate_id_wire(),
                "fromCursor": serialized,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(opened.status(), axum::http::StatusCode::OK);
    let opened = json_body(opened).await;
    let session_id = opened["sessionId"].as_str().unwrap();
    let acknowledged = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": FROZEN_CURSOR}),
        ))
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), axum::http::StatusCode::OK);
    assert_eq!(
        store.cursors(),
        (Some(cursor.clone()), Some(cursor.clone()))
    );

    let stale = ReplayService::new(
        store,
        restarted_key.derive_hmac(b"runne/replay-cursor-hmac/v1\0"),
        EventLogLineageId::from_bytes(LINEAGE),
        Arc::new(AllowAuthorization),
    )
    .build_cursor_from_event(&fixture_event(), &fixture_scope())
    .unwrap();
    let rejected = app
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": "conversation",
                "aggregateId": aggregate_id_wire(),
                "fromCursor": encode_cursor(&stale),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(rejected.status(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(json_body(rejected).await["code"], "invalid_replay_cursor");
}
