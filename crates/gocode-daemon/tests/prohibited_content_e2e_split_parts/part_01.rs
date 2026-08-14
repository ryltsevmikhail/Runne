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
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{ShutdownMode, ShutdownOutcome};
use gocode_runtime::{
    LocalTextProvider, LocalTextProviderError, Runtime, RuntimeCanonicalConversationHost,
};
use gocode_security::SecretBroker;
use gocode_store::replay_store::ReplayStore;
use gocode_store::schema::{
    apply_migrations, ensure_authority_id, ensure_event_log_lineage_id,
    open_with_pragmas, read_authority_id, read_event_log_lineage_id,
};
#[cfg(unix)]
use gocode_store::schema::open_existing_with_pragmas_validated;
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
                "gocode-ui-client/2",
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

fn open_admitted_fixture_connection(
    path: &std::path::Path,
    lineage: EventLogLineageId,
) -> rusqlite::Connection {
    #[cfg(unix)]
    {
        open_existing_with_pragmas_validated(path, |connection| {
            validate_fixture_identity(connection, lineage)
        })
        .unwrap()
    }
    #[cfg(not(unix))]
    {
        use rusqlite::OpenFlags;

        let path_text = path.to_str().unwrap();
        let connection = rusqlite::Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        connection.execute_batch("PRAGMA query_only = ON;").unwrap();
        validate_fixture_identity(&connection, lineage).unwrap();
        connection
            .execute_batch(
                "PRAGMA query_only = OFF;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 5000;",
            )
            .unwrap();
        gocode_store::schema::run_startup_gates(&connection, path_text).unwrap();
        connection
    }
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
