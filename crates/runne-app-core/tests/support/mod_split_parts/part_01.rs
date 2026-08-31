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
use runne_app_core::{AppCore, ConversationTimelineUpdate};
use runne_runtime_client::{
    AuthenticatedRuntimeClient, GOLDEN_BUNDLE_HASH, REQUIRED_RUNTIME_CAPABILITIES,
    RuntimeSessionInfo, mock_protected_authenticated_runtime_client,
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
    block_v2_resume: AtomicBool,
    retention_gap_once: AtomicBool,
    retention_v2_gap_once: AtomicBool,
    reconnectable_open_failure_once: AtomicBool,
    open_changed: Notify,
    live_changed: Notify,
    generate_changed: Notify,
    release_generate: Notify,
    resume_count: AtomicUsize,
    close_count: AtomicUsize,
    resume_failure_mode: AtomicUsize,
    bad_live_id_once: AtomicBool,
    resume_changed: Notify,
    close_changed: Notify,
    release_v2_resume: Notify,
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
            block_v2_resume: AtomicBool::new(false),
            retention_gap_once: AtomicBool::new(false),
            retention_v2_gap_once: AtomicBool::new(false),
            reconnectable_open_failure_once: AtomicBool::new(false),
            open_changed: Notify::new(),
            live_changed: Notify::new(),
            generate_changed: Notify::new(),
            release_generate: Notify::new(),
            resume_count: AtomicUsize::new(0),
            close_count: AtomicUsize::new(0),
            resume_failure_mode: AtomicUsize::new(0),
            bad_live_id_once: AtomicBool::new(false),
            resume_changed: Notify::new(),
            close_changed: Notify::new(),
            release_v2_resume: Notify::new(),
        });
        let router = Router::new()
            .route("/v1/conversations", post(create_conversation))
            .route(
                "/v1/conversations/{conversation_id}/messages",
                post(generate_text),
            )
            .route("/v1/commands/reconcile", post(reconcile_command))
            .route("/v1/replay/open-session", post(open_session))
            .route(
                "/v1/replay/resume-from-baseline",
                post(resume_from_baseline),
            )
            .route("/v1/replay/{session_id}/acknowledge", post(acknowledge))
            .route(
                "/v1/replay/{session_id}/complete-catch-up",
                post(complete_catch_up),
            )
            .route("/v1/replay/{session_id}/continue-live", post(continue_live))
            .route("/v1/replay/{session_id}/close", post(close_session))
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

    pub fn protected_client(&self) -> AuthenticatedRuntimeClient {
        let mut session = Self::session();
        session.capabilities = runne_runtime_client::PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(ToString::to_string)
            .collect();
        session.capability_digest = protected_capability_digest(&session.capabilities);
        mock_protected_authenticated_runtime_client(&self.origin, session)
            .expect("mock protected client")
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

    pub fn terminal_live(&self, code: &str) {
        let mut inner = self.state.inner.lock().expect("mock state");
        let frame = Bytes::from(format!(
            "event: terminal\ndata: {{\"transportVersion\":1,\"code\":\"{code}\"}}\n\n"
        ));
        inner
            .live_senders
            .retain_mut(|(sender, _)| sender.send(frame.clone()).is_ok());
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

    pub fn force_retention_v2_gap_once(&self) {
        self.state
            .retention_v2_gap_once
            .store(true, Ordering::SeqCst);
    }

    pub fn block_v2_resume(&self) {
        self.state.block_v2_resume.store(true, Ordering::SeqCst);
    }

    pub fn release_v2_resume(&self) {
        self.state.block_v2_resume.store(false, Ordering::SeqCst);
        self.state.release_v2_resume.notify_waiters();
    }

    pub async fn wait_for_v2_resume(&self, count: usize) {
        wait_for(&self.state.resume_count, &self.state.resume_changed, count).await;
    }

    pub fn malform_next_v2_resume_response(&self, mode: usize) {
        self.state.resume_failure_mode.store(mode, Ordering::SeqCst);
    }

    pub fn malform_next_live_delivery_id(&self) {
        self.state.bad_live_id_once.store(true, Ordering::SeqCst);
    }

    pub async fn wait_for_close(&self, count: usize) {
        wait_for(&self.state.close_count, &self.state.close_changed, count).await;
    }

    pub fn close_count(&self) -> usize {
        self.state.close_count.load(Ordering::SeqCst)
    }

    pub fn clear_close_count(&self) {
        self.state.close_count.store(0, Ordering::SeqCst);
    }

    pub async fn reset_close_count(&self) {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        self.state.close_count.store(0, Ordering::SeqCst);
    }

    pub fn fail_next_open_with_reconnectable_error(&self) {
        self.state
            .reconnectable_open_failure_once
            .store(true, Ordering::SeqCst);
    }
}
