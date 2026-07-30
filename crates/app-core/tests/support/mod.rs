#![allow(dead_code)]

use std::convert::Infallible;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{Response, StatusCode, header};
use axum::routing::{get, post};
use gocode_app_core::{AppCore, ConversationTimelineUpdate};
use gocode_runtime_client::{
    AuthenticatedRuntimeClient, GOLDEN_BUNDLE_HASH, REQUIRED_RUNTIME_CAPABILITIES,
    RuntimeSessionInfo, mock_authenticated_runtime_client,
};
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc};
use tokio_stream::{StreamExt, wrappers::UnboundedReceiverStream};

const SESSION_ID: &str = "018f2e3a700070008000000000000118";
const LIVE_DELIVERY_ID: &str = "018f2e3a-7000-7000-8000-000000000117";
const AUTHORITY_ID: &str = "018f2e3a700070008000000000000001";
const LINEAGE_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
const INSTANCE_ID: &str = "018f2e3a-7000-7000-8000-000000000002";

#[derive(Clone)]
pub struct MockRuntime {
    state: Arc<MockState>,
    origin: String,
}

struct MockState {
    inner: Mutex<MockInner>,
    create_count: AtomicUsize,
    open_count: AtomicUsize,
    ack_count: AtomicUsize,
    live_count: AtomicUsize,
    generate_count: AtomicUsize,
    block_generate: AtomicBool,
    open_changed: Notify,
    live_changed: Notify,
    generate_changed: Notify,
    release_generate: Notify,
}

#[derive(Default)]
struct MockInner {
    conversation_id: Option<String>,
    workspace_id: Option<String>,
    events: Vec<Value>,
    live_senders: Vec<(mpsc::UnboundedSender<Bytes>, u64)>,
}

impl MockRuntime {
    pub async fn start() -> Self {
        let state = Arc::new(MockState {
            inner: Mutex::new(MockInner::default()),
            create_count: AtomicUsize::new(0),
            open_count: AtomicUsize::new(0),
            ack_count: AtomicUsize::new(0),
            live_count: AtomicUsize::new(0),
            generate_count: AtomicUsize::new(0),
            block_generate: AtomicBool::new(false),
            open_changed: Notify::new(),
            live_changed: Notify::new(),
            generate_changed: Notify::new(),
            release_generate: Notify::new(),
        });
        let router = Router::new()
            .route("/v1/conversations", post(create_conversation))
            .route(
                "/v1/conversations/{conversation_id}/messages",
                post(generate_text),
            )
            .route("/v1/replay/open-session", post(open_session))
            .route("/v1/replay/{session_id}/acknowledge", post(acknowledge))
            .route(
                "/v1/replay/{session_id}/complete-catch-up",
                post(complete_catch_up),
            )
            .route("/v1/replay/{session_id}/continue-live", post(continue_live))
            .route("/v1/replay/{session_id}/events", get(live_events))
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("mock runtime listener");
        let address = listener.local_addr().expect("mock address");
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock runtime server");
        });
        Self {
            state,
            origin: format!("http://{address}"),
        }
    }

    pub fn client(&self) -> AuthenticatedRuntimeClient {
        mock_authenticated_runtime_client(
            &self.origin,
            RuntimeSessionInfo {
                profile_id: "gocode-ui-client/1".to_owned(),
                schema_hash: GOLDEN_BUNDLE_HASH.to_owned(),
                runtime_version: "test".to_owned(),
                capabilities: REQUIRED_RUNTIME_CAPABILITIES
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                authority_id: AUTHORITY_ID.to_owned(),
                principal_id: "local-owner".to_owned(),
                event_log_lineage_id: LINEAGE_ID.to_owned(),
                daemon_instance_id: INSTANCE_ID.to_owned(),
                launch_generation: 1,
                session_id: SESSION_ID.to_owned(),
                authorization_epoch: 0,
                sensitivity_ceiling: "sensitive".to_owned(),
                certificate_sha256: "11".repeat(32),
                capability_digest: "22".repeat(32),
            },
        )
        .expect("mock authenticated client")
    }

    pub fn create_count(&self) -> usize {
        self.state.create_count.load(Ordering::SeqCst)
    }

    pub fn open_count(&self) -> usize {
        self.state.open_count.load(Ordering::SeqCst)
    }

    pub fn ack_count(&self) -> usize {
        self.state.ack_count.load(Ordering::SeqCst)
    }

    pub fn block_generate(&self) {
        self.state.block_generate.store(true, Ordering::SeqCst);
    }

    pub fn release_generate(&self) {
        self.state.block_generate.store(false, Ordering::SeqCst);
        self.state.release_generate.notify_waiters();
    }

    pub async fn wait_for_generate(&self, count: usize) {
        wait_for(
            &self.state.generate_count,
            &self.state.generate_changed,
            count,
        )
        .await;
    }

    pub async fn wait_for_open(&self, count: usize) {
        wait_for(&self.state.open_count, &self.state.open_changed, count).await;
    }

    pub async fn wait_for_live(&self, count: usize) {
        wait_for(&self.state.live_count, &self.state.live_changed, count).await;
    }

    pub fn append_generation_failed(&self) {
        let mut inner = self.state.inner.lock().expect("mock state");
        let conversation_id = inner
            .conversation_id
            .as_ref()
            .expect("conversation")
            .clone();
        let sequence = u64::try_from(inner.events.len() + 1).expect("sequence");
        let event = event(
            &conversation_id,
            sequence,
            "conversation.generation.failed",
            &json!({
                "type": "conversation.generation.failed",
                "taskRunId": "018f2e3a-7000-7000-8000-000000000130",
                "attemptId": "018f2e3a-7000-7000-8000-000000000131",
                "reason": "forced"
            }),
        );
        inner.events.push(event.clone());
        broadcast(&mut inner.live_senders, &event, sequence);
    }
}

pub struct Fixture {
    pub directory: tempfile::TempDir,
    pub database_path: std::path::PathBuf,
    pub project_id: i64,
    pub core: Arc<AppCore>,
    pub runtime: MockRuntime,
}

impl Fixture {
    pub async fn opened() -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let database_path = directory.path().join("profile.sqlite3");
        let project_path = directory.path().join("project");
        std::fs::create_dir(&project_path).expect("project");
        let runtime = MockRuntime::start().await;
        let core = Arc::new(
            AppCore::open_with_mock_runtime(&database_path, runtime.client())
                .expect("core with mock runtime"),
        );
        let project_id = core
            .open_local_project(&project_path)
            .expect("open project")
            .id;
        core.open_project_conversation(project_id)
            .await
            .expect("open conversation");
        Self {
            directory,
            database_path,
            project_id,
            core,
            runtime,
        }
    }

    pub fn subscribe(
        &self,
        updates: Arc<Mutex<Vec<ConversationTimelineUpdate>>>,
    ) -> tokio::task::JoinHandle<Result<(), gocode_app_core::AppCoreError>> {
        let core = Arc::clone(&self.core);
        let project_id = self.project_id;
        tokio::spawn(async move {
            core.subscribe_project_conversation(project_id, move |update| {
                updates.lock().expect("updates").push(update);
            })
            .await
        })
    }
}

async fn wait_for(counter: &AtomicUsize, notify: &Notify, expected: usize) {
    loop {
        let notified = notify.notified();
        if counter.load(Ordering::SeqCst) >= expected {
            return;
        }
        notified.await;
    }
}

async fn create_conversation(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> (StatusCode, axum::Json<Value>) {
    state.create_count.fetch_add(1, Ordering::SeqCst);
    let conversation_id = body["conversationId"].as_str().expect("conversation ID");
    let workspace_id = body["workspaceId"].as_str().expect("workspace ID");
    let mut inner = state.inner.lock().expect("mock state");
    if inner.events.is_empty() {
        inner.events.push(event(
            conversation_id,
            1,
            "conversation.created",
            &json!({"type": "conversation.created", "workspaceId": workspace_id}),
        ));
    }
    inner.conversation_id = Some(conversation_id.to_owned());
    inner.workspace_id = Some(workspace_id.to_owned());
    drop(inner);
    (
        StatusCode::ACCEPTED,
        axum::Json(json!({
            "conversationId": conversation_id,
            "workspaceId": workspace_id,
            "streamVersion": 1,
            "committedAt": 1
        })),
    )
}

async fn generate_text(
    State(state): State<Arc<MockState>>,
    Path(conversation_id): Path<String>,
    axum::Json(body): axum::Json<Value>,
) -> axum::Json<Value> {
    let count = state.generate_count.fetch_add(1, Ordering::SeqCst) + 1;
    state.generate_changed.notify_waiters();
    if state.block_generate.load(Ordering::SeqCst) {
        state.release_generate.notified().await;
    }
    let text = body["text"].as_str().expect("text").to_owned();
    let task_run_id = "018f2e3a-7000-7000-8000-000000000130";
    let attempt_id = "018f2e3a-7000-7000-8000-000000000131";
    let user_message_id = format!("018f2e3a-7000-7000-8000-{count:012x}");
    let assistant_message_id = format!("018f2e3a-7000-7000-8001-{count:012x}");
    let mut inner = state.inner.lock().expect("mock state");
    let user_sequence = u64::try_from(inner.events.len() + 1).expect("sequence");
    let user = event(
        &conversation_id,
        user_sequence,
        "conversation.message.appended",
        &json!({
            "type": "conversation.message.appended",
            "role": "user",
            "messageId": user_message_id,
            "taskRunId": task_run_id,
            "attemptId": attempt_id,
            "text": text
        }),
    );
    inner.events.push(user.clone());
    broadcast(&mut inner.live_senders, &user, user_sequence);
    let assistant_sequence = user_sequence + 1;
    let assistant_text = format!("mock response: {text}");
    let assistant = event(
        &conversation_id,
        assistant_sequence,
        "conversation.message.appended",
        &json!({
            "type": "conversation.message.appended",
            "role": "assistant",
            "messageId": assistant_message_id,
            "taskRunId": task_run_id,
            "attemptId": attempt_id,
            "text": assistant_text
        }),
    );
    inner.events.push(assistant.clone());
    broadcast(&mut inner.live_senders, &assistant, assistant_sequence);
    drop(inner);
    axum::Json(json!({
        "conversationId": conversation_id,
        "taskRunId": task_run_id,
        "attemptId": attempt_id,
        "conversationStreamVersion": assistant_sequence,
        "taskRunStreamVersion": 1,
        "userMessage": {
            "messageId": user_message_id,
            "role": "user",
            "taskRunId": task_run_id,
            "attemptId": attempt_id,
            "text": text,
            "committedAt": 2
        },
        "assistantMessage": {
            "messageId": assistant_message_id,
            "role": "assistant",
            "taskRunId": task_run_id,
            "attemptId": attempt_id,
            "text": assistant_text,
            "committedAt": 3
        }
    }))
}

async fn open_session(
    State(state): State<Arc<MockState>>,
    axum::Json(body): axum::Json<Value>,
) -> axum::Json<Value> {
    state.open_count.fetch_add(1, Ordering::SeqCst);
    state.open_changed.notify_waiters();
    let events = {
        let inner = state.inner.lock().expect("mock state");
        let start = body
            .get("fromCursor")
            .and_then(Value::as_str)
            .and_then(|cursor| {
                inner
                    .events
                    .iter()
                    .position(|event| event_cursor(event) == cursor)
            })
            .unwrap_or(0);
        inner.events[start..]
            .iter()
            .cloned()
            .map(|mut event| {
                let cursor = event_cursor(&event);
                event
                    .as_object_mut()
                    .expect("event object")
                    .insert("cursor".to_owned(), Value::String(cursor));
                event
            })
            .collect::<Vec<_>>()
    };
    axum::Json(json!({
        "sessionId": SESSION_ID,
        "highWaterRef": "aa",
        "events": events,
        "hasMore": false
    }))
}

async fn acknowledge(
    State(state): State<Arc<MockState>>,
    Path(_session_id): Path<String>,
) -> axum::Json<Value> {
    state.ack_count.fetch_add(1, Ordering::SeqCst);
    axum::Json(json!({"acknowledged": true}))
}

async fn complete_catch_up(Path(_session_id): Path<String>) -> axum::Json<Value> {
    axum::Json(json!({
        "catchUpProof": "aa",
        "sessionState": "catch_up_complete"
    }))
}

async fn continue_live(Path(_session_id): Path<String>) -> axum::Json<Value> {
    axum::Json(json!({
        "liveDeliveryId": LIVE_DELIVERY_ID,
        "sessionState": "live"
    }))
}

async fn live_events(
    State(state): State<Arc<MockState>>,
    Path(_session_id): Path<String>,
) -> Response<Body> {
    let (sender, receiver) = mpsc::unbounded_channel();
    state
        .inner
        .lock()
        .expect("mock state")
        .live_senders
        .push((sender, 1));
    state.live_count.fetch_add(1, Ordering::SeqCst);
    state.live_changed.notify_waiters();
    let stream = UnboundedReceiverStream::new(receiver).map(Ok::<Bytes, Infallible>);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(stream))
        .expect("SSE response")
}

fn event(conversation_id: &str, sequence: u64, event_type: &str, payload: &Value) -> Value {
    json!({
        "eventId": format!("018f2e3a-7000-7000-8002-{sequence:012x}"),
        "aggregateType": "conversation",
        "aggregateId": conversation_id,
        "sequence": sequence,
        "timestampUnixMicros": 1_722_330_000_000_000_i64 + i64::try_from(sequence).unwrap(),
        "sensitivity": "sensitive",
        "schemaVersion": 1,
        "eventType": event_type,
        "causationEventId": null,
        "integrityDigest": "11".repeat(32),
        "correlationId": conversation_id,
        "correlationType": "conversation",
        "payload": payload,
        "replayBindingId": "018f2e3a700070008000000000000121"
    })
}

fn event_cursor(event: &Value) -> String {
    let sequence = event["sequence"].as_u64().expect("sequence");
    let bytes = serde_json::to_vec(&json!({"sequence": sequence})).expect("cursor JSON");
    format!("gocode-replay-cursor-v1.{}", hex::encode(bytes))
}

fn broadcast(
    senders: &mut Vec<(mpsc::UnboundedSender<Bytes>, u64)>,
    event: &Value,
    _event_sequence: u64,
) {
    let cursor = event_cursor(event);
    senders.retain_mut(|(sender, delivery_sequence)| {
        let envelope = json!({
            "transportVersion": 1,
            "replaySessionId": SESSION_ID,
            "liveDeliveryId": LIVE_DELIVERY_ID,
            "deliverySequence": *delivery_sequence,
            "canonicalEvent": event,
            "replayCursor": cursor
        });
        let frame = Bytes::from(format!(
            "event: delivery\ndata: {}\n\n",
            serde_json::to_string(&envelope).expect("SSE JSON")
        ));
        let sent = sender.send(frame).is_ok();
        if sent {
            *delivery_sequence += 1;
        }
        sent
    });
}
