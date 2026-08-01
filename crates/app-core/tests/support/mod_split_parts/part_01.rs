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
    retention_gap_once: AtomicBool,
    reconnectable_open_failure_once: AtomicBool,
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
            retention_gap_once: AtomicBool::new(false),
            reconnectable_open_failure_once: AtomicBool::new(false),
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

    pub fn disconnect_live(&self) {
        self.state
            .inner
            .lock()
            .expect("mock state")
            .live_senders
            .clear();
    }

    pub fn force_retention_gap_once(&self) {
        self.state.retention_gap_once.store(true, Ordering::SeqCst);
    }

    pub fn fail_next_open_with_reconnectable_error(&self) {
        self.state
            .reconnectable_open_failure_once
            .store(true, Ordering::SeqCst);
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
