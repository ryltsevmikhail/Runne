//! Behavioral contract for authenticated replay transport over real SQLite.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use futures::StreamExt;
use gocode_application::ports::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
};
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use gocode_application::replay_service::ReplayService;
use gocode_domain::event::{Actor, EventEnvelope, Sensitivity};
use gocode_domain::id::{
    AggregateId, CommandId, EventId, EventLogLineageId, IdempotencyKey, IntegrityDigest, TaskRunId,
};
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use gocode_http::auth::AuthLayer;
use gocode_http::limits::LimitsConfig;
use gocode_http::middleware::request_id_middleware;
use gocode_http::replay::{ReplayHttpBinding, ReplayHttpState, replay_router};
use gocode_store::codec::{StoreCodec, TaskRunEventCodec};
use gocode_store::integrity::compute_integrity_digest_with_global_position;
use gocode_store::replay_store::ReplayStore;
use gocode_store::schema::{apply_migrations, open_with_pragmas};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const TOKEN: [u8; 32] = [0xAB; 32];
const AGGREGATE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0xbb,
];
const LINEAGE: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0xcc,
];
const AUTHORITY: [u8; 16] = [0xAA; 16];
const GENERATION: i64 = 7;
const PROHIBITED_MARKER: &str = "task-seven-replay-marker";

struct AvailableGuard;

struct AvailableReplayAuthorization;

impl ReplayAuthorizationPort for AvailableReplayAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            request.expected_epoch,
            Sensitivity::Sensitive,
        )
    }
}

impl ProhibitedContentPort for AvailableGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

enum DenyMode {
    Marker,
    Unavailable,
}

struct DenyGuard(DenyMode);

impl ProhibitedContentPort for DenyGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        match self.0 {
            DenyMode::Unavailable => Err(ContentGuardError::Unavailable),
            DenyMode::Marker
                if bytes
                    .windows(PROHIBITED_MARKER.len())
                    .any(|window| window == PROHIBITED_MARKER.as_bytes()) =>
            {
                Ok(ContentDisposition::Prohibited { policy_epoch: 2 })
            }
            DenyMode::Marker => Ok(ContentDisposition::Allowed { policy_epoch: 2 }),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum SwitchMode {
    Available = 0,
    Marker = 1,
    Unavailable = 2,
}

struct SwitchableGuard(AtomicU8);

impl SwitchableGuard {
    fn new(mode: SwitchMode) -> Self {
        Self(AtomicU8::new(mode as u8))
    }

    fn set(&self, mode: SwitchMode) {
        self.0.store(mode as u8, Ordering::SeqCst);
    }
}

impl ProhibitedContentPort for SwitchableGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        match self.0.load(Ordering::SeqCst) {
            value if value == SwitchMode::Available as u8 => {
                Ok(ContentDisposition::Allowed { policy_epoch: 1 })
            }
            value
                if value == SwitchMode::Marker as u8
                    && bytes
                        .windows(PROHIBITED_MARKER.len())
                        .any(|window| window == PROHIBITED_MARKER.as_bytes()) =>
            {
                Ok(ContentDisposition::Prohibited { policy_epoch: 2 })
            }
            value if value == SwitchMode::Marker as u8 => {
                Ok(ContentDisposition::Allowed { policy_epoch: 2 })
            }
            _ => Err(ContentGuardError::Unavailable),
        }
    }
}

struct TaskRunRow {
    event_id: [u8; 16],
    idempotency_key: Vec<u8>,
    payload: Vec<u8>,
    integrity_digest: [u8; 32],
}

fn event_id(global_position: i64) -> [u8; 16] {
    let mut bytes = [
        0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x01, 0, 0, 0, 0, 0, 0,
    ];
    bytes[14..].copy_from_slice(
        &u16::try_from(global_position)
            .expect("test position fits u16")
            .to_be_bytes(),
    );
    bytes
}

fn taskrun_row(sequence: i64, global_position: i64, key: String) -> TaskRunRow {
    let event_id_bytes = event_id(global_position);
    let taskrun_id = TaskRunId::from_bytes(AGGREGATE);
    let idempotency_key = IdempotencyKey::new(key).unwrap();
    let payload = TaskRunEvent::TaskRunCreated;
    let payload_bytes = TaskRunEventCodec.encode(&payload).unwrap();
    let envelope = EventEnvelope::from_parts(
        EventId::from_bytes(event_id_bytes),
        AggregateId::TaskRun(taskrun_id),
        AggregateId::TaskRun(taskrun_id),
        None,
        CommandId::from_bytes(event_id_bytes),
        idempotency_key.clone(),
        1,
        Actor::new("test-actor").unwrap(),
        Sensitivity::Public,
        payload,
        u64::try_from(sequence).unwrap(),
        Timestamp::from_unix_micros(0),
        IntegrityDigest::from_bytes([0; 32]),
    );
    let integrity_digest =
        compute_integrity_digest_with_global_position(&envelope, global_position, &payload_bytes)
            .unwrap()
            .into_bytes();
    TaskRunRow {
        event_id: event_id_bytes,
        idempotency_key: idempotency_key.as_str().as_bytes().to_vec(),
        payload: payload_bytes,
        integrity_digest,
    }
}

fn setup() -> (axum::Router, TempDir) {
    setup_with("replay-test", Arc::new(AvailableGuard))
}

fn setup_with(
    idempotency_key: &str,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
) -> (axum::Router, TempDir) {
    setup_with_events(vec![idempotency_key.to_owned()], prohibited_content)
}

fn setup_with_events(
    idempotency_keys: Vec<String>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
) -> (axum::Router, TempDir) {
    assert!(!idempotency_keys.is_empty());
    let directory = tempfile::tempdir().unwrap();
    let database_path = directory.path().join("replay.sqlite");
    let connection = open_with_pragmas(database_path.to_str().unwrap()).unwrap();
    apply_migrations(&connection).unwrap();
    let event_count = i64::try_from(idempotency_keys.len()).unwrap();
    connection
        .execute(
            "INSERT INTO aggregate_streams \
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at) \
             VALUES (1, ?1, ?2, ?3, 0, 0)",
            rusqlite::params![
                AGGREGATE.as_slice(),
                event_count,
                event_id(event_count).as_slice()
            ],
        )
        .unwrap();
    for (index, idempotency_key) in idempotency_keys.into_iter().enumerate() {
        let position = i64::try_from(index + 1).unwrap();
        let row = taskrun_row(position, position, idempotency_key);
        connection
            .execute(
                "INSERT INTO events \
                 (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
                  sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
                  payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
                 VALUES (?1, 1, ?2, ?3, ?3, 0, 0, 1, NULL, ?1, ?4, ?5, ?6, ?7, ?2, 1, 1)",
                rusqlite::params![
                    row.event_id.as_slice(),
                    AGGREGATE.as_slice(),
                    position,
                    row.idempotency_key,
                    b"test-actor".as_slice(),
                    row.payload,
                    row.integrity_digest.as_slice(),
                ],
            )
            .unwrap();
    }

    let service = ReplayService::new(
        Arc::new(ReplayStore::new(connection)),
        [0xDD; 32],
        EventLogLineageId::from_bytes(LINEAGE),
        Arc::new(AvailableReplayAuthorization),
    );
    let state = ReplayHttpState::new(
        service,
        ReplayHttpBinding::new(AUTHORITY, GENERATION, 0).unwrap(),
        LimitsConfig::default(),
        prohibited_content,
    );
    let router = replay_router(state)
        .layer(AuthLayer::new(TOKEN))
        .layer(axum::middleware::from_fn(request_id_middleware));
    (router, directory)
}

fn replay_connection(directory: &TempDir) -> rusqlite::Connection {
    let database_path = directory.path().join("replay.sqlite");
    open_with_pragmas(database_path.to_str().unwrap()).unwrap()
}

fn subscription_count(directory: &TempDir) -> i64 {
    replay_connection(directory)
        .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn replay_progress(
    directory: &TempDir,
    session_id: &str,
) -> (String, Option<i64>, Option<i64>, Option<i64>) {
    replay_connection(directory)
        .query_row(
            "SELECT state, next_page_position, last_delivered_position, last_acked_position
             FROM _replay_subscriptions
             WHERE session_id = ?1",
            [hex::decode(session_id).unwrap()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

#[tokio::test]
async fn open_session_classification_denial_leaves_no_durable_session() {
    for guard in [
        Arc::new(DenyGuard(DenyMode::Marker)) as Arc<dyn ProhibitedContentPort>,
        Arc::new(DenyGuard(DenyMode::Unavailable)) as Arc<dyn ProhibitedContentPort>,
    ] {
        let (app, directory) = setup_with(PROHIBITED_MARKER, guard);
        let response = app
            .oneshot(post(
                "/v1/replay/open-session",
                json!({
                    "aggregateType": 1,
                    "aggregateId": hex::encode(AGGREGATE),
                }),
            ))
            .await
            .unwrap();
        assert!(!response.status().is_success());
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(
            !bytes
                .windows(PROHIBITED_MARKER.len())
                .any(|window| window == PROHIBITED_MARKER.as_bytes()),
            "canonical error contained prohibited replay representation"
        );
        assert_eq!(subscription_count(&directory), 0);
    }
}

#[tokio::test]
async fn read_page_classification_denial_preserves_delivery_progress() {
    for denied_mode in [SwitchMode::Marker, SwitchMode::Unavailable] {
        let guard = Arc::new(SwitchableGuard::new(SwitchMode::Available));
        let mut keys = (1..=100)
            .map(|position| format!("replay-page-{position}"))
            .collect::<Vec<_>>();
        keys.push(PROHIBITED_MARKER.to_owned());
        let (app, directory) =
            setup_with_events(keys, Arc::clone(&guard) as Arc<dyn ProhibitedContentPort>);
        let opened = app
            .clone()
            .oneshot(post(
                "/v1/replay/open-session",
                json!({
                    "aggregateType": 1,
                    "aggregateId": hex::encode(AGGREGATE),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(opened.status(), StatusCode::OK);
        let opened = json_body(opened).await;
        let session_id = opened["sessionId"].as_str().unwrap();
        let before = replay_progress(&directory, session_id);
        guard.set(denied_mode);

        let response = app
            .oneshot(post(
                &format!("/v1/replay/{session_id}/read-page"),
                json!({"limit": 1}),
            ))
            .await
            .unwrap();

        assert!(!response.status().is_success());
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(
            !bytes
                .windows(PROHIBITED_MARKER.len())
                .any(|window| window == PROHIBITED_MARKER.as_bytes()),
            "canonical error contained prohibited replay representation"
        );
        assert_eq!(replay_progress(&directory, session_id), before);
    }
}

async fn open_and_continue_live(app: &axum::Router) -> String {
    let opened = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": 1,
                "aggregateId": hex::encode(AGGREGATE),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    let opened = json_body(opened).await;
    let session_id = opened["sessionId"].as_str().unwrap().to_owned();
    let cursor = opened["events"][0]["cursor"].as_str().unwrap();
    let acknowledged = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": cursor}),
        ))
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let completed = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/complete-catch-up"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let continued = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/continue-live"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(continued.status(), StatusCode::OK);
    session_id
}

fn append_taskrun_event(directory: &TempDir, position: i64, idempotency_key: &str) {
    let writer = replay_connection(directory);
    let row = taskrun_row(position, position, idempotency_key.to_owned());
    writer
        .execute(
            "INSERT INTO events \
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
             VALUES (?1, 1, ?2, ?3, ?3, 0, 0, 1, NULL, ?1, ?4, ?5, ?6, ?7, ?2, 1, 1)",
            rusqlite::params![
                row.event_id.as_slice(),
                AGGREGATE.as_slice(),
                position,
                row.idempotency_key,
                b"test-actor".as_slice(),
                row.payload,
                row.integrity_digest.as_slice(),
            ],
        )
        .unwrap();
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = ?1, last_event_id = ?2
             WHERE aggregate_type = 1 AND aggregate_id = ?3",
            rusqlite::params![position, row.event_id.as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();
}

#[tokio::test]
async fn live_classification_denial_preserves_session_and_delivery_progress() {
    for denied_mode in [SwitchMode::Marker, SwitchMode::Unavailable] {
        let guard = Arc::new(SwitchableGuard::new(SwitchMode::Available));
        let (app, directory) = setup_with(
            "replay-live-initial",
            Arc::clone(&guard) as Arc<dyn ProhibitedContentPort>,
        );
        let session_id = open_and_continue_live(&app).await;
        append_taskrun_event(&directory, 2, PROHIBITED_MARKER);
        let before = replay_progress(&directory, &session_id);
        guard.set(denied_mode);

        let response = app
            .oneshot(get(&format!("/v1/replay/{session_id}/events")))
            .await
            .unwrap();

        assert!(!response.status().is_success());
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        assert!(
            !bytes
                .windows(PROHIBITED_MARKER.len())
                .any(|window| window == PROHIBITED_MARKER.as_bytes()),
            "canonical error contained prohibited replay representation"
        );
        assert_eq!(replay_progress(&directory, &session_id), before);
    }
}

fn post(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
        .header("accept", "text/event-stream")
        .body(Body::empty())
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn issued_cursor_is_opaque_and_round_trips_through_acknowledge() {
    let (app, directory) = setup();
    let response = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": 1,
                "aggregateId": hex::encode(AGGREGATE),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let opened = json_body(response).await;
    let session_id = opened["sessionId"].as_str().unwrap();
    let event = &opened["events"][0];
    assert_eq!(event["eventType"], "TaskRunCreated");
    assert_eq!(event["sequence"], 1);
    assert_eq!(event["schemaVersion"], 1);
    assert_eq!(event["sensitivity"], "public");
    assert_eq!(event["causationId"], Value::Null);
    assert_eq!(event["commandId"], hex::encode(event_id(1)));
    assert_eq!(event["idempotencyKey"], "replay-test");
    assert_eq!(event["actor"], "test-actor");
    assert_eq!(
        event["integrityDigest"],
        hex::encode(taskrun_row(1, 1, "replay-test".to_owned()).integrity_digest)
    );
    assert_eq!(event["correlationId"], hex::encode(AGGREGATE));
    assert_eq!(event["correlationType"], 1);
    assert_eq!(event["integrityProfile"], 1);
    assert_eq!(
        event["payload"],
        json!({
            "encoding": "gocode-durable-event-codec-v1-hex",
            "data": "000101",
        })
    );
    let cursor = opened["events"][0]["cursor"]
        .as_str()
        .expect("cursor must be one opaque transport string");

    let response = app
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": cursor}),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await, json!({"acknowledged": true}));

    let database_path = directory.path().join("replay.sqlite");
    let connection = open_with_pragmas(database_path.to_str().unwrap()).unwrap();
    let (authority, generation): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT authority_id, session_generation
             FROM _replay_subscriptions
             WHERE session_id = ?1",
            [hex::decode(session_id).unwrap()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(authority, AUTHORITY);
    assert_eq!(generation, GENERATION);
}

#[tokio::test]
async fn tampered_cursor_returns_redacted_canonical_error() {
    let (app, _directory) = setup();
    let opened = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": 1,
                "aggregateId": hex::encode(AGGREGATE),
            }),
        ))
        .await
        .unwrap();
    let opened = json_body(opened).await;
    let session_id = opened["sessionId"].as_str().unwrap();
    let cursor = opened["events"][0]["cursor"].as_str().unwrap();
    let tampered = format!("{cursor}00");

    let response = app
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": tampered}),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let body = json_body(response).await;
    assert_eq!(
        body,
        json!({
            "code": "invalid_replay_cursor",
            "requestId": request_id,
        })
    );
    assert!(!body.to_string().contains(cursor));
    assert!(uuid::Uuid::parse_str(&request_id).is_ok());
}

#[tokio::test]
async fn live_sse_delivers_event_committed_after_catch_up() {
    let (app, directory) = setup();
    let response = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": 1,
                "aggregateId": hex::encode(AGGREGATE),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let opened = json_body(response).await;
    let session_id = opened["sessionId"].as_str().unwrap();
    let cursor = opened["events"][0]["cursor"].as_str().unwrap();

    let acknowledged = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": cursor}),
        ))
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let completed = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/complete-catch-up"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let continued = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/continue-live"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(continued.status(), StatusCode::OK);

    let response = app
        .oneshot(get(&format!("/v1/replay/{session_id}/events")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    let database_path = directory.path().join("replay.sqlite");
    let writer = open_with_pragmas(database_path.to_str().unwrap()).unwrap();
    let row = taskrun_row(2, 2, "replay-live-test".to_owned());
    writer
        .execute(
            "INSERT INTO events \
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
             VALUES (?1, 1, ?2, 2, 2, 0, 0, 1, NULL, ?1, ?3, ?4, ?5, ?6, ?2, 1, 1)",
            rusqlite::params![
                row.event_id.as_slice(),
                AGGREGATE.as_slice(),
                row.idempotency_key,
                b"test-actor".as_slice(),
                row.payload,
                row.integrity_digest.as_slice(),
            ],
        )
        .unwrap();
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 2, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![row.event_id.as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();

    let mut body = response.into_body().into_data_stream();
    let delivery = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let frame = body.next().await.unwrap().unwrap();
            let frame = String::from_utf8(frame.to_vec()).unwrap();
            if frame.contains("event: delivery") {
                break frame;
            }
        }
    })
    .await
    .expect("live event must arrive before timeout");

    assert!(delivery.contains("\"globalPosition\":2"));
    assert!(delivery.contains("\"replayCursor\":\"gocode-replay-cursor-v1."));
}

#[tokio::test]
async fn slow_live_consumer_closes_session_without_advancing_ack() {
    let (app, directory) = setup();
    let opened = app
        .clone()
        .oneshot(post(
            "/v1/replay/open-session",
            json!({
                "aggregateType": 1,
                "aggregateId": hex::encode(AGGREGATE),
            }),
        ))
        .await
        .unwrap();
    let opened = json_body(opened).await;
    let session_id = opened["sessionId"].as_str().unwrap().to_owned();
    let cursor = opened["events"][0]["cursor"].as_str().unwrap();
    let acknowledged = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/acknowledge"),
            json!({"cursor": cursor}),
        ))
        .await
        .unwrap();
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let completed = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/complete-catch-up"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let continued = app
        .clone()
        .oneshot(post(
            &format!("/v1/replay/{session_id}/continue-live"),
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(continued.status(), StatusCode::OK);

    let unconsumed_stream = app
        .oneshot(get(&format!("/v1/replay/{session_id}/events")))
        .await
        .unwrap();
    assert_eq!(unconsumed_stream.status(), StatusCode::OK);

    let database_path = directory.path().join("replay.sqlite");
    let writer = open_with_pragmas(database_path.to_str().unwrap()).unwrap();
    for position in 2_i64..=80 {
        let row = taskrun_row(
            position,
            position,
            format!("replay-backpressure-{position}"),
        );
        writer
            .execute(
                "INSERT INTO events \
                 (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp, \
                  sensitivity, schema_version, causation_id, command_id, idempotency_key, actor, \
                  payload, integrity_digest, correlation_id, correlation_type, integrity_profile) \
                 VALUES (?1, 1, ?2, ?3, ?3, 0, 0, 1, NULL, ?1, ?4, ?5, ?6, ?7, ?2, 1, 1)",
                rusqlite::params![
                    row.event_id.as_slice(),
                    AGGREGATE.as_slice(),
                    position,
                    row.idempotency_key,
                    b"test-actor".as_slice(),
                    row.payload,
                    row.integrity_digest.as_slice(),
                ],
            )
            .unwrap();
    }
    writer
        .execute(
            "UPDATE aggregate_streams
             SET current_version = 80, last_event_id = ?1
             WHERE aggregate_type = 1 AND aggregate_id = ?2",
            rusqlite::params![event_id(80).as_slice(), AGGREGATE.as_slice()],
        )
        .unwrap();
    drop(writer);

    let session_bytes = hex::decode(&session_id).unwrap();
    let last_acked = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let connection = open_with_pragmas(database_path.to_str().unwrap()).unwrap();
            let (state, last_acked): (String, Option<i64>) = connection
                .query_row(
                    "SELECT state, last_acked_position
                     FROM _replay_subscriptions
                     WHERE session_id = ?1",
                    [&session_bytes],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            drop(connection);
            if state == "closed" {
                break last_acked;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded live channel must close a stalled session");

    assert_eq!(last_acked, Some(1));
    drop(unconsumed_stream);
}
