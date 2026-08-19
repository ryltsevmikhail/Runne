use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use runne_api::{
    ApiActor, ApiPrincipalId, CanonicalMessageText, ConversationCommandContext,
    ConversationCommandHostPort, ConversationHostError, CreateCanonicalConversationCommand,
    DaemonInstanceId, GenerateConversationTextCommand, RuntimeSessionBinding, StableRuntimeBinding,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::local_session::{
    AuthenticatedRuntimeSession, BootstrapProof, LocalSessionService,
    bootstrap_proof_transcript,
};
use runne_application::ports::{
    ProjectWorkspaceRepository, ReplayAuthorizationLease, ReplayAuthorizationPort,
    ReplayAuthorizationRequest, ReplayError, RuntimeAuthorityId,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::replay_service::ReplayService;
use runne_application::service::TaskRunService;
use runne_application::verification::export_port::VerificationExporter;
use runne_domain::event::Sensitivity;
use runne_domain::id::{
    CommandId, ConversationId, EventLogLineageId, IdempotencyKey, ProjectId, WorkspaceId,
};
use runne_domain::message::MessageText;
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_domain::verification::backup::StreamInventory;
use runne_domain::verification::digest::VerificationDigest;
use runne_http::auth::{SessionAuthLayer, session_authorization_header};
use runne_http::error::{RequestId, canonical_error_response};
use runne_http::limits::LimitsConfig;
use runne_http::middleware::request_id_middleware;
use runne_http::replay::{ReplayHttpBinding, ReplayHttpState, replay_router};
use runne_runtime::config::RuntimeConfig;
use runne_runtime::controller::{ShutdownMode, ShutdownOutcome};
use runne_runtime::{
    LocalTextProvider, LocalTextProviderError, Runtime, RuntimeCanonicalConversationHost,
};
use runne_security::SecretBroker;
use runne_store::replay_store::ReplayStore;
use runne_store::schema::{
    ConnectionMode, ManagedConnection, apply_migrations, ensure_authority_id,
    ensure_event_log_lineage_id, open_managed_connection, publication_from_managed,
    read_authority_id, read_event_log_lineage_id, readiness_from_managed,
    reopen_managed_connection_validated,
};
use runne_store::store::StoreTransaction;
use runne_store::ProjectWorkspaceStore;
use runne_store::verification::backup_store::InMemoryBackupStore;
use hmac::{Hmac, Mac};
use serde_json::json;
use tower::ServiceExt;

const MARKER: &str = "task-seven-e2e-inert-marker";
const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000771";
const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000772";
const TOKEN: [u8; 32] = [0x77; 32];
const SESSION_AUTHORITY: [u8; 32] = [0x76; 32];
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

fn seed_canonical_workspace(store: &StoreTransaction) {
    let repository = ProjectWorkspaceStore::from_store(store.clone());
    let project_id: ProjectId = "018f2e3a-7000-7000-8000-000000000773"
        .parse()
        .unwrap();
    repository
        .create_project(
            "local-owner",
            "018f2e3a-7000-7000-8000-000000000774"
                .parse()
                .unwrap(),
            &IdempotencyKey::new("prohibited-content-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Prohibited content project".into()).unwrap(),
            ),
        )
        .unwrap();
    repository
        .create_workspace(
            "local-owner",
            "018f2e3a-7000-7000-8000-000000000775"
                .parse()
                .unwrap(),
            &IdempotencyKey::new("prohibited-content-workspace").unwrap(),
            Workspace::create(
                WORKSPACE_ID.parse().unwrap(),
                project_id,
                ProjectWorkspaceDisplayName::new("Prohibited content workspace".into()).unwrap(),
            ),
        )
        .unwrap();
}

fn authenticated_runtime_session(lineage: EventLogLineageId) -> AuthenticatedRuntimeSession {
    AuthenticatedRuntimeSession {
        binding: RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                AUTHORITY,
                ApiPrincipalId::new("local-owner").unwrap(),
                lineage,
                "runne-ui-client/2",
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

fn session_layer(lineage: EventLogLineageId) -> SessionAuthLayer {
    let authenticated = authenticated_runtime_session(lineage);
    let binding = authenticated.binding;
    let mut service = LocalSessionService::new(binding.clone(), TOKEN);
    let challenge = service
        .issue_challenge([0x61; 32], [0x62; 32], Duration::ZERO)
        .unwrap();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&TOKEN).unwrap();
    mac.update(&bootstrap_proof_transcript(
        &binding, [0x62; 32], [0x61; 32],
    ));
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            SESSION_AUTHORITY,
            Duration::ZERO,
        )
        .unwrap();
    SessionAuthLayer::new(
        Arc::new(Mutex::new(service)),
        binding,
        Arc::new(|| Duration::ZERO),
    )
}

fn open_admitted_fixture_connection(
    path: &std::path::Path,
    lineage: EventLogLineageId,
) -> ManagedConnection {
    open_admitted_fixture_connection_with_mode(path, lineage, ConnectionMode::ValidatedReopen)
}

fn open_admitted_fixture_connection_with_mode(
    path: &std::path::Path,
    lineage: EventLogLineageId,
    mode: ConnectionMode,
) -> ManagedConnection {
    let connection = reopen_managed_connection_validated(
        path,
        mode,
        |connection| validate_fixture_identity(connection, lineage),
    )
    .unwrap();
    readiness_from_managed(&connection).unwrap();
    publication_from_managed(&connection).unwrap();
    connection
}

fn validate_fixture_identity(
    connection: &rusqlite::Connection,
    lineage: EventLogLineageId,
) -> rusqlite::Result<()> {
    if read_authority_id(connection)? == Some(AUTHORITY)
        && read_event_log_lineage_id(connection)? == Some(lineage)
    {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
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
