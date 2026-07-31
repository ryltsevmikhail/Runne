use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use gocode_api::{
    ApiActor, ApiPrincipalId, CanonicalMessageText, ConversationCommandContext,
    ConversationCommandHostPort, ConversationHostError, CreateCanonicalConversationCommand,
    DaemonInstanceId, GenerateConversationTextCommand, RuntimeSessionBinding, StableRuntimeBinding,
};
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use gocode_application::local_session::AuthenticatedRuntimeSession;
use gocode_application::ports::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
    RuntimeAuthorityId,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::provider::{
    ProviderAdmissionError, ProviderCoordinatorRequest, ProviderDispatchCoordinator,
    ProviderEffectAdmission, ProviderEffectAuthorityRef, ProviderEffectRequest,
};
use gocode_application::replay_service::ReplayService;
use gocode_application::service::TaskRunService;
use gocode_application::verification::export_port::VerificationExporter;
use gocode_domain::event::Sensitivity;
use gocode_domain::id::{
    CommandId, ConversationId, EventLogLineageId, IdempotencyKey, WorkspaceId,
};
use gocode_domain::message::MessageText;
use gocode_domain::verification::backup::StreamInventory;
use gocode_domain::verification::digest::VerificationDigest;
use gocode_http::auth::AuthLayer;
use gocode_http::error::{RequestId, canonical_error_response};
use gocode_http::limits::LimitsConfig;
use gocode_http::middleware::request_id_middleware;
use gocode_http::replay::{ReplayHttpBinding, ReplayHttpState, replay_router};
use gocode_provider::{
    DispatchAttemptId, DispatchError, DispatchRequest, ModelRef, PrepareError,
    PreparedProviderRecord, PreparedRequest, ProviderCall, ProviderCallId, ProviderDispatchClaim,
    ProviderDispatchRepository, ProviderFuture, ProviderId, ProviderPort,
    ProviderRepositoryClaimOutcome, ProviderRepositoryError, ProviderStreamId,
};
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{ShutdownMode, ShutdownOutcome};
use gocode_runtime::{
    LocalTextProvider, LocalTextProviderError, Runtime, RuntimeCanonicalConversationHost,
};
use gocode_security::SecretBroker;
use gocode_store::replay_store::ReplayStore;
use gocode_store::schema::{ensure_event_log_lineage_id, open_with_pragmas};
use gocode_store::store::StoreTransaction;
use gocode_store::verification::backup_store::InMemoryBackupStore;
use serde_json::json;
use tower::ServiceExt;

const MARKER: &str = "task-seven-e2e-inert-marker";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000771";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000772";
const TOKEN: [u8; 32] = [0x77; 32];
const AUTHORITY: [u8; 16] = [
    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0x77,
];

type SqliteService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

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

#[derive(Clone)]
struct MarkerProvider {
    calls: Arc<AtomicUsize>,
}

impl LocalTextProvider for MarkerProvider {
    fn generate(&self, _input: &MessageText) -> Result<MessageText, LocalTextProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        MessageText::new(MARKER).map_err(|_| LocalTextProviderError::InvalidOutput)
    }
}

fn conversation_context(sequence: u8, key: &str) -> ConversationCommandContext {
    ConversationCommandContext {
        command_id: format!("018f2e3a-7000-7000-8000-0000000007{sequence:02x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal: ApiPrincipalId::new("local-owner").unwrap(),
        actor: ApiActor::new("prohibited-content-e2e").unwrap(),
    }
}

fn authenticated_runtime_session(lineage: EventLogLineageId) -> AuthenticatedRuntimeSession {
    AuthenticatedRuntimeSession {
        binding: RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                AUTHORITY,
                ApiPrincipalId::new("local-owner").unwrap(),
                lineage,
                "gocode-ui-client/1",
                [0x31; 32],
                [0x41; 32],
            )
            .unwrap(),
            DaemonInstanceId::from_bytes([
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0x78,
            ]),
            1,
            [
                0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0x79,
            ],
            0,
            Sensitivity::Sensitive,
            [0x51; 32],
        )
        .unwrap(),
        expires_at_monotonic: Duration::from_secs(600),
    }
}

fn representations() -> Vec<(&'static str, Vec<u8>)> {
    let raw = MARKER.as_bytes();
    let standard = base64::engine::general_purpose::STANDARD.encode(raw);
    vec![
        ("raw", raw.to_vec()),
        ("base64-padded", standard.as_bytes().to_vec()),
        (
            "base64-unpadded",
            standard.trim_end_matches('=').as_bytes().to_vec(),
        ),
        (
            "base64-url",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(raw)
                .into_bytes(),
        ),
        ("hex-lower", hex::encode(raw).into_bytes()),
        ("hex-upper", hex::encode_upper(raw).into_bytes()),
    ]
}

fn assert_absent(kind: &str, bytes: &[u8], representations: &[(&str, Vec<u8>)]) {
    for (representation_kind, marker) in representations {
        assert!(
            !bytes
                .windows(marker.len())
                .any(|window| window == marker.as_slice()),
            "{kind} contained prohibited {representation_kind} representation"
        );
    }
}

#[derive(Clone)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct RecordingProvider {
    prepared_bytes: Mutex<Vec<u8>>,
}

impl ProviderPort for RecordingProvider {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        *self.prepared_bytes.lock().unwrap() = serde_json::to_vec(call).unwrap();
        PreparedRequest::from_call(call)
    }

    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        digest_version: gocode_provider::ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        *self.prepared_bytes.lock().unwrap() = serde_json::to_vec(call).unwrap();
        PreparedRequest::from_call_for_digest_version(call, digest_version)
    }

    fn dispatch(
        &self,
        _request: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async { unreachable!("denied provider call must not dispatch") })
    }

    fn next<'a>(
        &'a self,
        _stream_id: &'a ProviderStreamId,
        _cursor: gocode_provider::StreamCursor,
    ) -> ProviderFuture<'a, Result<gocode_provider::ProviderStreamItem, gocode_provider::StreamError>>
    {
        Box::pin(async { unreachable!("denied provider call must not poll") })
    }

    fn cancel(
        &self,
        _request: gocode_provider::CancelRequest,
    ) -> ProviderFuture<'_, Result<gocode_provider::CancelDisposition, DispatchError>> {
        Box::pin(async { unreachable!("denied provider call must not cancel") })
    }

    fn reconcile(
        &self,
        _request: gocode_provider::ReconcileRequest,
    ) -> ProviderFuture<'_, Result<gocode_provider::ReconciliationDisposition, DispatchError>> {
        Box::pin(async { unreachable!("denied provider call must not reconcile") })
    }
}

#[derive(Default)]
struct UnreachableRepository;

impl ProviderDispatchRepository for UnreachableRepository {
    fn load_prepared(
        &self,
        _call_id: gocode_provider::ProviderCallId,
    ) -> Result<Option<PreparedProviderRecord>, ProviderRepositoryError> {
        unreachable!("denied provider call must not load prepared state")
    }

    fn persist_prepared(
        &self,
        _record: &PreparedProviderRecord,
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("denied provider call must not persist")
    }

    fn claim(
        &self,
        _claim: &ProviderDispatchClaim,
    ) -> Result<ProviderRepositoryClaimOutcome, ProviderRepositoryError> {
        unreachable!("denied provider call must not claim")
    }

    fn mark_streaming(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _stream_id: ProviderStreamId,
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("denied provider call must not mark streaming")
    }

    fn mark_rejected_before_effect(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _rejection: gocode_provider::ProviderPreEffectRejection,
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("denied provider call must not mark rejected")
    }

    fn mark_terminal_pending(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("denied provider call must not mark terminal")
    }

    fn settle(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
        _settlement_digest: [u8; 32],
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("denied provider call must not settle")
    }

    fn mark_uncertain(
        &self,
        _attempt_id: DispatchAttemptId,
        _fencing_token: u64,
    ) -> Result<(), ProviderRepositoryError> {
        unreachable!("denied provider call must not mark uncertain")
    }
}

struct UnreachableAdmission;

impl ProviderEffectAdmission for UnreachableAdmission {
    fn admit(&self, _request: &ProviderEffectRequest) -> Result<(), ProviderAdmissionError> {
        unreachable!("denied provider call must not reach admission")
    }
}

fn provider_request() -> ProviderCoordinatorRequest {
    ProviderCoordinatorRequest {
        call: ProviderCall::new(
            ProviderCallId::from_bytes([1; 16]),
            ModelRef::new(
                ProviderId::new("synthetic-provider").unwrap(),
                "synthetic-model",
                "2026-07-30",
            )
            .unwrap(),
            [2; 32],
            64,
            json!({"inert": MARKER}),
        )
        .unwrap(),
        authority_ref: ProviderEffectAuthorityRef::new([3; 16], 1).unwrap(),
        profile_digest: [5; 32],
        attempt_id: DispatchAttemptId::from_bytes([6; 16]),
        permit_id: [7; 16],
        token_reservation_id: [8; 16],
        cost_reservation_id: [9; 16],
        fencing_token: 1,
        owner_id: "local-owner".into(),
        scope: "provider.dispatch".into(),
        provider_idempotency_key: "task-seven-provider".into(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn prohibited_material_is_absent_from_current_durable_and_outbound_boundaries() {
    let tracing_bytes = Arc::new(Mutex::new(Vec::new()));
    let capture = Arc::clone(&tracing_bytes);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || CaptureWriter(Arc::clone(&capture)))
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);

    let representations = representations();
    let directory = tempfile::tempdir().unwrap();
    let db_path = directory.path().join("prohibited-content.sqlite");
    let authority = RuntimeAuthorityId("task-seven-e2e".into());
    let mut broker = SecretBroker::new();
    broker
        .register("task-seven-inert", MARKER.as_bytes().to_vec())
        .unwrap();
    let guard: Arc<dyn ProhibitedContentPort> = Arc::new(broker.prohibited_content_guard());
    let store = StoreTransaction::open(
        db_path.to_str().unwrap(),
        authority.clone(),
        Arc::clone(&guard),
    )
    .unwrap();
    let taskrun_service: Arc<SqliteService> = Arc::new(TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority.clone(),
    ));
    let text_service: Arc<dyn ConversationTextCommandService> =
        Arc::new(ConversationTextService::new(
            store.clone(),
            store.clone(),
            authority.clone(),
            Arc::clone(&guard),
        ));
    let (handle, mut controller) = Runtime::start_borrowed_with_conversations(
        gocode_runtime::TokioRuntimeContext::new_for_test(),
        taskrun_service,
        text_service,
        RuntimeConfig::default(),
    )
    .unwrap();
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let host = RuntimeCanonicalConversationHost::new(
        handle,
        Arc::new(ConversationService::new(
            store.clone(),
            store.clone(),
            authority,
        )),
        store.clone(),
        MarkerProvider {
            calls: Arc::clone(&provider_calls),
        },
        Arc::clone(&guard),
    );
    let conversation_id: ConversationId = CONVERSATION_ID.parse().unwrap();
    host.create_conversation(
        conversation_context(1, "create-e2e"),
        CreateCanonicalConversationCommand {
            conversation_id,
            workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        },
    )
    .await
    .unwrap();

    let prohibited_user = host
        .generate_text(
            conversation_context(2, "prohibited-user"),
            GenerateConversationTextCommand {
                conversation_id,
                expected_version: 1,
                text: CanonicalMessageText::new(MARKER).unwrap(),
            },
        )
        .await;
    assert_eq!(
        prohibited_user,
        Err(ConversationHostError::ProhibitedSecretMaterial)
    );

    let prohibited_assistant = host
        .generate_text(
            conversation_context(3, "prohibited-assistant"),
            GenerateConversationTextCommand {
                conversation_id,
                expected_version: 1,
                text: CanonicalMessageText::new("ordinary user input").unwrap(),
            },
        )
        .await;
    assert_eq!(
        prohibited_assistant,
        Err(ConversationHostError::ProviderOutputRejected)
    );
    assert_eq!(provider_calls.load(Ordering::SeqCst), 1);

    let connection = open_with_pragmas(db_path.to_str().unwrap()).unwrap();
    let mut statement = connection
        .prepare(
            "SELECT idempotency_key, command_outcome
             FROM command_receipts ORDER BY command_id",
        )
        .unwrap();
    let mut receipt_bytes = Vec::new();
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .unwrap();
    for row in rows {
        let (key, outcome) = row.unwrap();
        receipt_bytes.extend_from_slice(&key);
        receipt_bytes.extend_from_slice(&outcome);
    }
    assert_absent("receipt query", &receipt_bytes, &representations);
    drop(statement);

    let lineage = ensure_event_log_lineage_id(&connection).unwrap();
    let authenticated = authenticated_runtime_session(lineage);
    drop(connection);
    let replay_connection = open_with_pragmas(db_path.to_str().unwrap()).unwrap();
    let replay_service = ReplayService::new(
        Arc::new(ReplayStore::new(replay_connection)),
        [0x77; 32],
        lineage,
        Arc::new(AvailableReplayAuthorization),
    );
    let replay_state = ReplayHttpState::new(
        replay_service,
        ReplayHttpBinding::new(AUTHORITY, 1, 0).unwrap(),
        LimitsConfig::default(),
        Arc::clone(&guard),
    );
    let replay = replay_router(replay_state)
        .layer(axum::Extension(authenticated))
        .layer(AuthLayer::new(TOKEN))
        .layer(axum::middleware::from_fn(request_id_middleware));
    let response = replay
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/replay/open-session")
                .header("authorization", format!("Bearer {}", hex::encode(TOKEN)))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "aggregateType": "conversation",
                        "aggregateId": hex::encode(conversation_id.as_bytes()),
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let replay_status = response.status();
    let replay_bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "unexpected replay response: {}",
        String::from_utf8_lossy(&replay_bytes)
    );
    assert_absent("replay response", &replay_bytes, &representations);

    let exporter = VerificationExporter::new(Arc::clone(&guard));
    let export_bytes = exporter
        .export_run_json(
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            "completed",
            Some("passed"),
            0,
        )
        .unwrap();
    assert_absent("synthetic export", &export_bytes, &representations);
    assert!(
        exporter
            .export_run_json(uuid::Uuid::now_v7(), uuid::Uuid::now_v7(), MARKER, None, 0,)
            .is_err()
    );

    let backup = InMemoryBackupStore::new(Arc::clone(&guard));
    let manifest = backup
        .create_backup(
            vec![StreamInventory {
                stream_name: "verification_run".into(),
                event_count: 1,
                first_sequence: 1,
                last_sequence: 1,
            }],
            VerificationDigest::from_bytes([1; 32]),
        )
        .unwrap();
    let backup_bytes = backup.archive_bytes(&manifest.backup_id).unwrap();
    assert_absent("synthetic backup", &backup_bytes, &representations);
    assert!(
        backup
            .create_backup(
                vec![StreamInventory {
                    stream_name: MARKER.into(),
                    event_count: 1,
                    first_sequence: 1,
                    last_sequence: 1,
                }],
                VerificationDigest::from_bytes([1; 32]),
            )
            .is_err()
    );

    let recording_provider = RecordingProvider::default();
    let repository = UnreachableRepository;
    let admission = UnreachableAdmission;
    let coordinator = ProviderDispatchCoordinator::new(
        &repository,
        &admission,
        &recording_provider,
        guard.as_ref(),
    );
    assert_eq!(
        coordinator.dispatch(provider_request()).await,
        Err(ProviderAdmissionError::PolicyDenied)
    );
    assert_absent(
        "recording provider input",
        &recording_provider.prepared_bytes.lock().unwrap(),
        &representations,
    );

    let canonical_error = canonical_error_response(
        StatusCode::UNPROCESSABLE_ENTITY,
        "prohibited_secret_material",
        &RequestId::generate(),
    );
    let canonical_error_bytes = to_bytes(canonical_error.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_absent("canonical error", &canonical_error_bytes, &representations);

    assert_eq!(
        controller
            .shutdown(ShutdownMode::Graceful {
                timeout: Duration::from_secs(5),
            })
            .await,
        ShutdownOutcome::Quiesced
    );
    drop(host);
    drop(store);

    for (kind, path) in [
        ("database", db_path.clone()),
        ("wal", db_path.with_extension("sqlite-wal")),
        ("shm", db_path.with_extension("sqlite-shm")),
    ] {
        let bytes = std::fs::read(path).unwrap_or_default();
        assert_absent(kind, &bytes, &representations);
    }
    assert_absent(
        "tracing buffer",
        &tracing_bytes.lock().unwrap(),
        &representations,
    );
}
