use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gocode_api::{
    ApiActor, ApiPrincipalId, CompleteTaskRunCommand, ConversationCommandContext,
    ConversationCommandHostPort, ConversationCreatedAck, ConversationHostError,
    ConversationMessagesSnapshot, ConversationQueryHostPort, ConversationTextResult,
    CreateCanonicalConversationCommand, CreateTaskRunCommand, DaemonInstanceId,
    ExistingTaskRunCommand, GenerateConversationTextCommand, OperationalTelemetryQueryPort,
    RuntimeSessionBinding, StableRuntimeBinding, TaskRunCommandAck, TaskRunCommandContext,
    TaskRunCommandHostPort, TaskRunHostError, TaskRunQueryHostPort, TaskRunSnapshot,
};
use gocode_application::{
    local_session::{BootstrapProof, LocalSessionService, bootstrap_proof_transcript},
    ports::{
        ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
    },
    prohibited_content::{
        CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
    },
    replay_service::ReplayService,
};
use gocode_domain::{
    event::Sensitivity,
    id::{ConversationId, EventLogLineageId, TaskRunId},
};
use gocode_http::{
    admission::AdmissionState,
    conversations::ConversationHttpState,
    health::{HealthState, RecoveryState},
    operational_telemetry::OperationalTelemetryHttpState,
    replay::{ReplayHttpBinding, ReplayHttpState},
    runtime_profile::{RuntimeProfileHttpState, ordered_capability_digest},
    secure_local_host::{LocalRuntimeTlsHost, LocalRuntimeTlsHostError},
    task_runs::TaskRunHttpState,
};
use gocode_store::{replay_store::ReplayStore, schema::apply_migrations};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    gocode_api::OPERATIONAL_TELEMETRY_CAPABILITY_V1,
];

struct AvailableGuard;
struct AvailableReplayAuthorization;
#[derive(Clone)]
struct UnavailableTaskRunHost;
#[derive(Clone)]
struct UnavailableConversationHost;

impl ReplayAuthorizationPort for AvailableReplayAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            request.expected_epoch,
            Sensitivity::Internal,
        )
    }
}

impl ProhibitedContentPort for AvailableGuard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

impl TaskRunCommandHostPort for UnavailableTaskRunHost {
    async fn create_task_run(
        &self,
        _: TaskRunCommandContext,
        _: CreateTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
    async fn queue_task_run(
        &self,
        _: TaskRunCommandContext,
        _: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
    async fn admit_task_run(
        &self,
        _: TaskRunCommandContext,
        _: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
    async fn start_attempt(
        &self,
        _: TaskRunCommandContext,
        _: ExistingTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
    async fn complete_task_run(
        &self,
        _: TaskRunCommandContext,
        _: CompleteTaskRunCommand,
    ) -> Result<TaskRunCommandAck, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
}

impl TaskRunQueryHostPort for UnavailableTaskRunHost {
    async fn get_task_run(&self, _: TaskRunId) -> Result<TaskRunSnapshot, TaskRunHostError> {
        Err(TaskRunHostError::Unavailable)
    }
}

impl ConversationCommandHostPort for UnavailableConversationHost {
    async fn create_conversation(
        &self,
        _: ConversationCommandContext,
        _: CreateCanonicalConversationCommand,
    ) -> Result<ConversationCreatedAck, ConversationHostError> {
        Err(ConversationHostError::Unavailable)
    }
    async fn generate_text(
        &self,
        _: ConversationCommandContext,
        _: GenerateConversationTextCommand,
    ) -> Result<ConversationTextResult, ConversationHostError> {
        Err(ConversationHostError::Unavailable)
    }
}

impl ConversationQueryHostPort for UnavailableConversationHost {
    async fn list_messages(
        &self,
        _: ConversationId,
    ) -> Result<ConversationMessagesSnapshot, ConversationHostError> {
        Err(ConversationHostError::Unavailable)
    }
}

pub(super) async fn bind_with_counting_query(
    query: Arc<dyn OperationalTelemetryQueryPort>,
    server_config: Arc<rustls::ServerConfig>,
) -> Result<(LocalRuntimeTlsHost, axum::http::HeaderValue), LocalRuntimeTlsHostError> {
    let binding = binding();
    let service = Arc::new(Mutex::new(LocalSessionService::new(
        binding.clone(),
        [7; 32],
    )));
    let authorization = authenticated_header(&service, &binding);
    let host = LocalRuntimeTlsHost::bind_with_operational_telemetry(
        "127.0.0.1:0",
        server_config,
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        service,
        binding,
        false,
        Arc::new(|| Duration::ZERO),
        RuntimeProfileHttpState::new("test", "test", "test", CAPABILITIES),
        TaskRunHttpState::new(
            UnavailableTaskRunHost,
            ApiActor::new("gocode-daemon-test").unwrap(),
        ),
        ConversationHttpState::new(
            UnavailableConversationHost,
            ApiActor::new("gocode-daemon-test").unwrap(),
        ),
        replay_state(),
        OperationalTelemetryHttpState::new(query),
    )
    .await?;
    Ok((host, authorization))
}

fn authenticated_header(
    service: &Arc<Mutex<LocalSessionService>>,
    binding: &RuntimeSessionBinding,
) -> axum::http::HeaderValue {
    let mut service = service.lock().unwrap();
    let challenge = service
        .issue_challenge([8; 32], [9; 32], Duration::ZERO)
        .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&[7; 32]).unwrap();
    mac.update(&bootstrap_proof_transcript(binding, [9; 32], [8; 32]));
    service
        .authenticate(
            challenge.id,
            BootstrapProof::new(mac.finalize().into_bytes().into()),
            [10; 32],
            Duration::ZERO,
        )
        .unwrap();
    format!("GocodeSession {}", URL_SAFE_NO_PAD.encode([10; 32]))
        .parse()
        .unwrap()
}

fn binding() -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
            ApiPrincipalId::new("local-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000003"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "gocode-ui-client/1",
            [3; 32],
            ordered_capability_digest(CAPABILITIES),
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2]),
        1,
        [5; 16],
        0,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap()
}

fn replay_state() -> ReplayHttpState {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    apply_migrations(&connection).unwrap();
    let binding = binding();
    ReplayHttpState::new(
        ReplayService::new(
            Arc::new(ReplayStore::new(connection)),
            [11; 32],
            *binding.stable().lineage_id(),
            Arc::new(AvailableReplayAuthorization),
        ),
        ReplayHttpBinding::new(*binding.stable().authority_id(), 1, 0).unwrap(),
        gocode_http::limits::LimitsConfig::default(),
        Arc::new(AvailableGuard),
    )
}
