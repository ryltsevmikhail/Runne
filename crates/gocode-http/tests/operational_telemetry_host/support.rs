use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use gocode_api::{
    ApiActor, ApiPrincipalId, CompleteTaskRunCommand, ConversationCommandContext,
    ConversationCommandHostPort, ConversationCreatedAck, ConversationHostError,
    ConversationMessagesSnapshot, ConversationQueryHostPort, ConversationTextResult,
    CreateCanonicalConversationCommand, CreateTaskRunCommand, DaemonInstanceId,
    ExistingTaskRunCommand, GenerateConversationTextCommand, OperationalTelemetryQueryErrorV1,
    OperationalTelemetryQueryPort, RuntimeOperationalTelemetrySnapshotV1, RuntimeSessionBinding,
    StableRuntimeBinding, TaskRunCommandAck, TaskRunCommandContext, TaskRunCommandHostPort,
    TaskRunHostError, TaskRunQueryHostPort, TaskRunSnapshot,
};
use gocode_application::{
    local_session::LocalSessionService,
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
use gocode_store::{
    replay_store::ReplayStore,
    schema::{ConnectionMode, apply_migrations, open_managed_connection},
};

pub(super) const BASE_CAPABILITIES: &[&str] = &["conversation.create.v1"];
pub(super) const TELEMETRY_CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    gocode_api::OPERATIONAL_TELEMETRY_CAPABILITY_V1,
];

struct UnavailableTelemetry;
struct AvailableGuard;
struct AvailableReplayAuthorization;
#[derive(Clone)]
struct UnavailableTaskRunHost;
#[derive(Clone)]
struct UnavailableConversationHost;

impl OperationalTelemetryQueryPort for UnavailableTelemetry {
    fn query_operational_telemetry(
        &self,
    ) -> Result<RuntimeOperationalTelemetrySnapshotV1, OperationalTelemetryQueryErrorV1> {
        Err(OperationalTelemetryQueryErrorV1::Unavailable)
    }
}

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

pub(super) async fn bind_with_telemetry(
    capabilities: &'static [&'static str],
) -> Result<LocalRuntimeTlsHost, LocalRuntimeTlsHostError> {
    let binding = binding(capabilities);
    LocalRuntimeTlsHost::bind_with_operational_telemetry(
        "127.0.0.1:0",
        server_config(),
        HealthState {
            recovery_state: RecoveryState::Ready,
        },
        AdmissionState::new(RecoveryState::Ready),
        Arc::new(Mutex::new(LocalSessionService::new(
            binding.clone(),
            [7; 32],
        ))),
        binding,
        false,
        Arc::new(|| Duration::ZERO),
        RuntimeProfileHttpState::new("test", "test", "test", capabilities),
        TaskRunHttpState::new(
            UnavailableTaskRunHost,
            ApiActor::new("gocode-http-test").unwrap(),
        ),
        ConversationHttpState::new(
            UnavailableConversationHost,
            ApiActor::new("gocode-http-test").unwrap(),
        ),
        replay_state(),
        OperationalTelemetryHttpState::new(Arc::new(UnavailableTelemetry)),
    )
    .await
}

fn binding(capabilities: &[&str]) -> RuntimeSessionBinding {
    RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
            ApiPrincipalId::new("local-owner").unwrap(),
            "018f2e3a-7000-7000-8000-000000000003"
                .parse::<EventLogLineageId>()
                .unwrap(),
            "gocode-ui-client/2",
            [3; 32],
            ordered_capability_digest(capabilities),
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
    let connection =
        open_managed_connection(std::path::Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let binding = binding(BASE_CAPABILITIES);
    let service = ReplayService::new(
        Arc::new(ReplayStore::new(connection)),
        [11; 32],
        *binding.stable().lineage_id(),
        Arc::new(AvailableReplayAuthorization),
    );
    ReplayHttpState::new(
        service,
        ReplayHttpBinding::new(
            *binding.stable().authority_id(),
            binding.ephemeral().launch_generation() as i64,
            binding.ephemeral().authorization_epoch() as i64,
        )
        .unwrap(),
        gocode_http::limits::LimitsConfig::default(),
        Arc::new(AvailableGuard),
    )
}

fn server_config() -> Arc<rustls::ServerConfig> {
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new())),
    )
}
