//! Concrete daemon composition root.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bootstrap::{BootstrapOutcome, bootstrap};
use crate::client_profile::PublishedClientProfileV2;
use crate::config::ConfigurationSnapshot;
use crate::error::DaemonError;
use crate::recovery::{RecoveryState, enumerate_recovery_tasks};
use crate::shutdown::{RuntimeTaskSupervisor, graceful_shutdown};
use gocode_api::{
    ApiActor, ApiPrincipalId, ExecutableIdentityV1, ProtectedActivationKeys,
    ProtectedLaunchRequestV1, ProtectedLaunchRequestV2, ProtectedReadyV1, ProtectedReadyV2,
    RuntimeSessionBinding, StableRuntimeBinding, StableRuntimeBindingV1,
};
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use gocode_application::local_session::LocalSessionService;
use gocode_application::ports::RuntimeAuthorityId;
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::replay_service::{
    REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES, REPLAY_FRAME_CAPACITY_BYTES,
    REPLAY_PAGE_CAPACITY_BYTES, ReplayAuthorizationLease, ReplayAuthorizationPort,
    ReplayAuthorizationRequest, ReplayError, ReplayService, ReplayStorePort,
    validate_replay_reader_capacity,
};
use gocode_application::service::TaskRunService;
use gocode_domain::event::Sensitivity;
use gocode_http::admission::AdmissionState;
use gocode_http::conversations::ConversationHttpState;
use gocode_http::health::{HealthState, RecoveryState as HttpRecoveryState};
use gocode_http::limits::LimitsConfig;
use gocode_http::replay::{ReplayHttpBinding, ReplayHttpState};
use gocode_http::runtime_profile::RuntimeProfileHttpState;
use gocode_http::secure_local_host::LocalRuntimeTlsHost;
use gocode_http::task_runs::TaskRunHttpState;
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use gocode_runtime::{
    DeterministicTextProvider, Runtime, RuntimeCanonicalConversationHost, RuntimeGenerationId,
    RuntimeTaskRunHost, TokioRuntimeContext,
};
use gocode_security::SecretBroker;
use gocode_store::replay_store::ReplayStore;
use gocode_store::schema::{ensure_event_log_lineage_id, open_with_pragmas};
use gocode_store::store::StoreTransaction;

type SqliteTaskRunService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;
type SqliteConversationService = ConversationService<StoreTransaction, StoreTransaction>;

struct DaemonReplayAuthorization {
    replay_authority_id: [u8; 16],
    local_session: Arc<Mutex<LocalSessionService>>,
}

impl DaemonReplayAuthorization {
    fn new(replay_authority_id: [u8; 16], local_session: Arc<Mutex<LocalSessionService>>) -> Self {
        Self {
            replay_authority_id,
            local_session,
        }
    }
}

impl ReplayAuthorizationPort for DaemonReplayAuthorization {
    fn current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
    ) -> Result<ReplayAuthorizationLease, ReplayError> {
        if request.authority_id != self.replay_authority_id {
            return Err(ReplayError::AuthorizationRevoked);
        }
        let generation = u64::try_from(request.session_generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let current = self
            .local_session
            .lock()
            .map_err(|_| ReplayError::AuthorizationRevoked)?
            .current_replay_authorization(&request.principal_id, generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            i64::try_from(current.authorization_epoch())
                .map_err(|_| ReplayError::AuthorizationRevoked)?,
            current.sensitivity_ceiling(),
        )
    }

    fn mutate_with_current_lease(
        &self,
        request: &ReplayAuthorizationRequest,
        mutation: &mut dyn FnMut(&ReplayAuthorizationLease) -> Result<usize, ReplayError>,
    ) -> Result<usize, ReplayError> {
        if request.authority_id != self.replay_authority_id {
            return Err(ReplayError::AuthorizationRevoked);
        }
        let generation = u64::try_from(request.session_generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let local_session = self
            .local_session
            .lock()
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let current = local_session
            .current_replay_authorization(&request.principal_id, generation)
            .map_err(|_| ReplayError::AuthorizationRevoked)?;
        let lease = ReplayAuthorizationLease::new(
            request.principal_id.clone(),
            i64::try_from(current.authorization_epoch())
                .map_err(|_| ReplayError::AuthorizationRevoked)?,
            current.sensitivity_ceiling(),
        )?;
        mutation(&lease)
    }
}

/// Fully composed daemon with bootstrap locks, durable store, runtime,
/// canonical router, and shutdown authority kept alive together.
pub struct DaemonApplication {
    bootstrap: BootstrapOutcome,
    store: StoreTransaction,
    http_host: LocalRuntimeTlsHost,
    client_profile: Option<PublishedClientProfileV2>,
    binding: RuntimeSessionBinding,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    protected_activation: bool,
    runtime_controller: RuntimeController,
    _secret_broker: Arc<Mutex<SecretBroker>>,
    task_supervisor: Arc<RuntimeTaskSupervisor>,
    shutdown_timeout: Duration,
}

impl DaemonApplication {
    /// Bootstraps storage, starts the canonical runtime, builds the production
    /// router, and binds HTTP without accepting requests yet.
    pub async fn start(config: &ConfigurationSnapshot) -> Result<Self, DaemonError> {
        Self::validate_config(config)?;
        if config.provider_activation.requires_openai_execution() {
            return Err(DaemonError::Config(
                "OpenAI provider composition is unavailable".to_owned(),
            ));
        }
        let bootstrap = bootstrap(config)?;
        Self::start_with_bootstrap(config, bootstrap, false).await
    }

    /// Starts from an already authenticated protected bundled bootstrap.
    pub async fn start_protected(
        config: &ConfigurationSnapshot,
        bootstrap: BootstrapOutcome,
    ) -> Result<Self, DaemonError> {
        Self::validate_config(config)?;
        Self::start_with_bootstrap(config, bootstrap, true).await
    }

    fn validate_config(config: &ConfigurationSnapshot) -> Result<(), DaemonError> {
        if config.max_in_flight == 0 {
            return Err(DaemonError::Config(
                "max_in_flight must be greater than zero".to_owned(),
            ));
        }
        if config.shutdown_timeout_ms == 0 {
            return Err(DaemonError::Config(
                "shutdown_timeout_ms must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }

    async fn start_with_bootstrap(
        config: &ConfigurationSnapshot,
        bootstrap: BootstrapOutcome,
        protected_activation: bool,
    ) -> Result<Self, DaemonError> {
        let recovery_state = enumerate_recovery_tasks(&bootstrap.db_conn)?;
        let replay_lineage = ensure_event_log_lineage_id(&bootstrap.db_conn).map_err(|error| {
            DaemonError::Bootstrap(format!("initialize replay lineage: {error}"))
        })?;
        let replay_connection = open_with_pragmas(&config.db_path)
            .map_err(|error| DaemonError::Bootstrap(format!("open replay store: {error}")))?;
        let authority = RuntimeAuthorityId(hex::encode(bootstrap.authority_id));
        let secret_broker = Arc::new(Mutex::new(SecretBroker::new()));
        let prohibited_content: Arc<dyn ProhibitedContentPort> = Arc::new(
            secret_broker
                .lock()
                .map_err(|_| {
                    DaemonError::Bootstrap("initialize prohibited-content registry".to_owned())
                })?
                .prohibited_content_guard(),
        );
        let store = StoreTransaction::open(
            &config.db_path,
            authority.clone(),
            Arc::clone(&prohibited_content),
        )
        .map_err(|error| DaemonError::Bootstrap(format!("open runtime store: {error:?}")))?;
        let service: Arc<SqliteTaskRunService> = Arc::new(TaskRunService::new(
            store.clone(),
            store.clone(),
            store.clone(),
            authority.clone(),
        ));
        let conversation_service: Arc<SqliteConversationService> = Arc::new(
            ConversationService::new(store.clone(), store.clone(), authority.clone()),
        );
        let conversation_text_service: Arc<dyn ConversationTextCommandService> =
            Arc::new(ConversationTextService::new(
                store.clone(),
                store.clone(),
                authority,
                Arc::clone(&prohibited_content),
            ));

        let runtime_config = RuntimeConfig {
            max_in_flight_requests: usize::try_from(config.max_in_flight).map_err(|_| {
                DaemonError::Config("max_in_flight does not fit this platform".to_owned())
            })?,
            ..RuntimeConfig::default()
        };
        let generation = RuntimeGenerationId(bootstrap.launch_generation);
        let (handle, mut runtime_controller) = Runtime::start_borrowed_with_conversations(
            TokioRuntimeContext::new(generation, tokio::runtime::Handle::current()),
            service,
            conversation_text_service,
            runtime_config,
        )
        .map_err(|error| DaemonError::Bootstrap(format!("start runtime: {error}")))?;

        let task_run_host = RuntimeTaskRunHost::new(handle.clone(), store.clone());
        let conversation_host = RuntimeCanonicalConversationHost::new(
            handle,
            conversation_service,
            store.clone(),
            DeterministicTextProvider,
            Arc::clone(&prohibited_content),
        );
        let http_recovery_state = map_recovery_state(recovery_state);
        let actor =
            ApiActor::new("gocode-daemon").expect("the built-in daemon actor identity is valid");
        let replay_binding = ReplayHttpBinding::new(
            bootstrap.authority_id,
            i64::try_from(bootstrap.launch_generation)
                .map_err(|_| DaemonError::Bootstrap("replay generation overflow".to_owned()))?,
            0,
        )
        .map_err(|error| DaemonError::Bootstrap(format!("configure replay transport: {error}")))?;
        let replay_integrity_secret = bootstrap
            .replay_integrity_key
            .derive_hmac(b"gocode/replay-cursor-hmac/v1\0");
        let replay_store = ReplayStore::new(replay_connection);
        let retention_manifest = replay_store
            .retention_manifest(&replay_lineage, &replay_integrity_secret)
            .await
            .map_err(|error| {
                DaemonError::Bootstrap(format!("measure retained replay inventory: {error}"))
            })?;
        validate_replay_reader_capacity(
            &retention_manifest,
            REPLAY_FRAME_CAPACITY_BYTES,
            REPLAY_PAGE_CAPACITY_BYTES,
            REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES,
        )
        .map_err(|error| DaemonError::Config(error.to_string()))?;
        let schema_hash: [u8; 32] = hex::decode(gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH)
            .map_err(|_| DaemonError::Bootstrap("decode schema hash".into()))?
            .try_into()
            .map_err(|_| DaemonError::Bootstrap("invalid schema hash".into()))?;
        let capability_digest = gocode_http::runtime_profile::ordered_capability_digest(
            gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES,
        );
        let stable_binding = StableRuntimeBinding::new(
            bootstrap.local_session_authority_id,
            ApiPrincipalId::new("local-owner")
                .map_err(|_| DaemonError::Bootstrap("invalid local principal".into()))?,
            replay_lineage,
            gocode_runtime::bundle::BUNDLE_ID,
            schema_hash,
            capability_digest,
        )
        .map_err(|_| DaemonError::Bootstrap("build stable local session binding".into()))?;
        let mut session_id = *uuid::Uuid::now_v7().as_bytes();
        while session_id == bootstrap.launch_identity.daemon_instance_id().into_bytes() {
            session_id = *uuid::Uuid::now_v7().as_bytes();
        }
        let binding = RuntimeSessionBinding::new(
            stable_binding,
            bootstrap.launch_identity.daemon_instance_id(),
            bootstrap.launch_generation,
            session_id,
            0,
            Sensitivity::Sensitive,
            *bootstrap.launch_identity.certificate_sha256(),
        )
        .map_err(|_| DaemonError::Bootstrap("build local session binding".into()))?;
        let launched_at = Instant::now();
        let session_clock: Arc<dyn Fn() -> Duration + Send + Sync> =
            Arc::new(move || launched_at.elapsed());
        let local_session_service = Arc::new(Mutex::new(if protected_activation {
            LocalSessionService::new_protected(
                binding.clone(),
                bootstrap.launch_identity.bootstrap_secret(),
                Duration::ZERO,
                Duration::from_secs(30),
            )
            .map_err(|_| DaemonError::Bootstrap("initialize protected session".into()))?
        } else {
            LocalSessionService::new(
                binding.clone(),
                bootstrap.launch_identity.bootstrap_secret(),
            )
        }));
        let replay_service = ReplayService::new(
            Arc::new(replay_store),
            replay_integrity_secret,
            replay_lineage,
            Arc::new(DaemonReplayAuthorization::new(
                bootstrap.authority_id,
                Arc::clone(&local_session_service),
            )),
        );
        let http_host = LocalRuntimeTlsHost::bind(
            &config.http_bind,
            Arc::clone(bootstrap.launch_identity.server_config()),
            HealthState {
                recovery_state: http_recovery_state.clone(),
            },
            AdmissionState::new(http_recovery_state),
            Arc::clone(&local_session_service),
            binding.clone(),
            protected_activation,
            Arc::clone(&session_clock),
            RuntimeProfileHttpState::new(
                gocode_runtime::bundle::BUNDLE_ID,
                gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH,
                env!("CARGO_PKG_VERSION"),
                gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES,
            ),
            TaskRunHttpState::new(task_run_host, actor.clone()),
            ConversationHttpState::new(conversation_host, actor),
            ReplayHttpState::new(
                replay_service,
                replay_binding,
                LimitsConfig::default(),
                prohibited_content,
            ),
        )
        .await
        .map_err(DaemonError::from)?;
        let shutdown_timeout = Duration::from_millis(config.shutdown_timeout_ms);
        let client_profile = if protected_activation {
            None
        } else {
            let result = http_host
                .local_addr()
                .map_err(DaemonError::from)
                .and_then(|address| {
                    let directory = std::path::Path::new(&config.replay_integrity_key_path)
                        .parent()
                        .ok_or_else(|| {
                            DaemonError::Bootstrap(
                                "replay_integrity_key_path has no profile directory".into(),
                            )
                        })?;
                    PublishedClientProfileV2::publish(
                        directory,
                        address,
                        &bootstrap.launch_identity,
                        bootstrap.local_session_authority_id,
                        uuid::Uuid::from_bytes(*replay_lineage.as_bytes()),
                    )
                });
            match result {
                Ok(profile) => Some(profile),
                Err(error) => {
                    let _ = tokio::time::timeout(
                        shutdown_timeout,
                        runtime_controller.shutdown(ShutdownMode::Immediate {
                            timeout: shutdown_timeout,
                        }),
                    )
                    .await;
                    return Err(error);
                }
            }
        };

        Ok(Self {
            bootstrap,
            store,
            http_host,
            client_profile,
            binding,
            local_session_service,
            session_clock,
            protected_activation,
            runtime_controller,
            _secret_broker: secret_broker,
            task_supervisor: RuntimeTaskSupervisor::new(),
            shutdown_timeout,
        })
    }

    /// Returns the bound local address before the accept loop starts.
    pub fn local_addr(&self) -> Result<SocketAddr, DaemonError> {
        Ok(self.http_host.local_addr()?)
    }

    /// Returns the stable runtime authority without exposing credentials.
    pub fn authority_id(&self) -> [u8; 16] {
        self.bootstrap.authority_id
    }

    /// Reports whether bootstrap reopened an existing database.
    pub fn db_existed(&self) -> bool {
        self.bootstrap.db_existed
    }

    /// Builds exact authenticated readiness without exposing legacy profile files.
    pub fn protected_ready(
        &self,
        request: &ProtectedLaunchRequestV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<ProtectedReadyV1, DaemonError> {
        if !self.protected_activation || self.client_profile.is_some() {
            return Err(DaemonError::Bootstrap(
                "protected readiness is unavailable".into(),
            ));
        }
        let executable_path = std::env::current_exe()
            .map_err(|_| DaemonError::Bootstrap("measure launched executable".into()))?;
        let executable = ExecutableIdentityV1::measure(&executable_path)
            .map_err(|_| DaemonError::Bootstrap("measure launched executable".into()))?;
        if &executable != request.executable() {
            return Err(DaemonError::Bootstrap(
                "launched executable identity mismatch".into(),
            ));
        }
        let stable = self.binding.stable();
        let stable = StableRuntimeBindingV1::new(
            *stable.authority_id(),
            stable.principal_id().as_str(),
            *stable.lineage_id().as_bytes(),
            stable.profile_id(),
            *stable.schema_hash(),
            *stable.capability_digest(),
        )
        .map_err(|_| DaemonError::Bootstrap("build protected readiness binding".into()))?;
        let ephemeral = self.binding.ephemeral();
        let mut ready = ProtectedReadyV1::new(
            request.launch_authority_id(),
            request.desktop_host_instance_id(),
            executable,
            request.profile().clone(),
            stable,
            ephemeral.daemon_instance_id().into_bytes(),
            ephemeral.launch_generation(),
            *ephemeral.session_id(),
            format!("https://{}", self.local_addr()?),
            *self.bootstrap.launch_identity.certificate_sha256(),
            self.bootstrap
                .launch_identity
                .certificate_der()
                .as_ref()
                .to_vec(),
            gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
        )
        .map_err(|_| DaemonError::Bootstrap("build protected readiness".into()))?;
        ready.sign(keys);
        Ok(ready)
    }

    /// Builds V2 readiness only for the exact protected provider binding.
    pub fn protected_ready_v2(
        &self,
        request: &ProtectedLaunchRequestV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<ProtectedReadyV2, DaemonError> {
        let ready = self.protected_ready(request.compatibility_request(), keys)?;
        let mut ready = ProtectedReadyV2::new(ready, request.provider_binding().clone())
            .map_err(|_| DaemonError::Bootstrap("build provider-bound readiness".into()))?;
        ready.sign(keys);
        Ok(ready)
    }

    /// Shares the in-memory protected session service with the control loop.
    pub fn protected_session_service(
        &self,
    ) -> Result<Arc<Mutex<LocalSessionService>>, DaemonError> {
        if !self.protected_activation {
            return Err(DaemonError::Bootstrap(
                "protected session service is unavailable".into(),
            ));
        }
        Ok(Arc::clone(&self.local_session_service))
    }

    /// Shares the daemon monotonic clock used to enforce bootstrap deadlines.
    pub fn protected_session_clock(
        &self,
    ) -> Result<Arc<dyn Fn() -> Duration + Send + Sync>, DaemonError> {
        if !self.protected_activation {
            return Err(DaemonError::Bootstrap(
                "protected session clock is unavailable".into(),
            ));
        }
        Ok(Arc::clone(&self.session_clock))
    }

    /// Runs until shutdown or HTTP failure, then stops HTTP before the
    /// canonical runtime and releases bootstrap resources last.
    pub async fn run<F>(self, shutdown: F) -> Result<(), DaemonError>
    where
        F: Future<Output = Result<(), DaemonError>>,
    {
        let Self {
            bootstrap,
            store,
            http_host,
            client_profile,
            binding,
            local_session_service,
            session_clock,
            protected_activation,
            mut runtime_controller,
            _secret_broker,
            task_supervisor,
            shutdown_timeout,
        } = self;

        let http_result = http_host.start().run_until(shutdown).await;
        let drain_result =
            graceful_shutdown(&task_supervisor, duration_millis(shutdown_timeout)).await;
        let http_result = combine_shutdown_results(http_result, drain_result);
        let runtime_result = shutdown_runtime(&mut runtime_controller, shutdown_timeout).await;

        drop(client_profile);
        drop(binding);
        drop(local_session_service);
        drop(session_clock);
        let _ = protected_activation;
        drop(_secret_broker);
        drop(store);
        drop(bootstrap);

        combine_shutdown_results(http_result, runtime_result)
    }
}

fn map_recovery_state(state: RecoveryState) -> HttpRecoveryState {
    match state {
        RecoveryState::Ready => HttpRecoveryState::Ready,
        RecoveryState::RecoveryBlocked => HttpRecoveryState::RecoveryBlocked,
        RecoveryState::IntegrityBlocked => HttpRecoveryState::IntegrityBlocked,
    }
}

async fn shutdown_runtime(
    controller: &mut RuntimeController,
    timeout: Duration,
) -> Result<(), DaemonError> {
    let outcome = tokio::time::timeout(
        timeout,
        controller.shutdown(ShutdownMode::Graceful { timeout }),
    )
    .await
    .map_err(|_| DaemonError::Bootstrap("runtime shutdown timeout".to_owned()))?;

    match outcome {
        ShutdownOutcome::Quiesced => {}
        ShutdownOutcome::Incomplete {
            active_workers,
            active_blocking_ops,
            rejected_commands,
        } => {
            return Err(DaemonError::Bootstrap(format!(
                "runtime shutdown incomplete: active_workers={active_workers}, \
                 active_blocking_ops={active_blocking_ops}, \
                 rejected_commands={rejected_commands}"
            )));
        }
    }

    let terminated = tokio::time::timeout(timeout, controller.wait_terminated())
        .await
        .map_err(|_| DaemonError::Bootstrap("runtime termination timeout".to_owned()))?;
    match terminated {
        ShutdownOutcome::Quiesced => Ok(()),
        ShutdownOutcome::Incomplete { .. } => Err(DaemonError::Bootstrap(
            "runtime termination was not quiescent".to_owned(),
        )),
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn combine_shutdown_results(
    http_result: Result<(), DaemonError>,
    runtime_result: Result<(), DaemonError>,
) -> Result<(), DaemonError> {
    match (http_result, runtime_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(http_error), Err(runtime_error)) => Err(DaemonError::Bootstrap(format!(
            "HTTP shutdown failed: {http_error}; runtime shutdown failed: {runtime_error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gocode_api::{DaemonInstanceId, RuntimeSessionBinding};
    use gocode_domain::id::EventLogLineageId;

    fn replay_binding() -> RuntimeSessionBinding {
        let authority = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 1,
        ];
        let daemon = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 2,
        ];
        let session = [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 3,
        ];
        RuntimeSessionBinding::new(
            StableRuntimeBinding::new(
                authority,
                ApiPrincipalId::new("local-owner").unwrap(),
                EventLogLineageId::from_bytes([
                    0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 4,
                ]),
                "gocode-ui-client/1",
                [0x33; 32],
                [0x44; 32],
            )
            .unwrap(),
            DaemonInstanceId::from_bytes(daemon),
            7,
            session,
            3,
            Sensitivity::Internal,
            [0x77; 32],
        )
        .unwrap()
    }

    #[test]
    fn production_replay_authorization_reads_live_local_session_state() {
        let local_session = Arc::new(Mutex::new(LocalSessionService::new(
            replay_binding(),
            [0x88; 32],
        )));
        let authorization = DaemonReplayAuthorization::new([0x99; 16], Arc::clone(&local_session));
        let request = ReplayAuthorizationRequest {
            principal_id: "local-owner".to_owned(),
            authority_id: [0x99; 16],
            session_generation: 7,
            expected_epoch: 3,
            session_id: Some([0xAA; 16]),
            scope: None,
        };

        let initial = authorization.current_lease(&request).unwrap();
        assert_eq!(initial.authorization_epoch(), 3);
        assert_eq!(initial.sensitivity_ceiling(), Sensitivity::Internal);

        local_session
            .lock()
            .unwrap()
            .set_sensitivity_ceiling(Sensitivity::Public);
        let downgraded = authorization.current_lease(&request).unwrap();
        assert_eq!(downgraded.authorization_epoch(), 3);
        assert_eq!(downgraded.sensitivity_ceiling(), Sensitivity::Public);

        local_session.lock().unwrap().set_authorization_epoch(4);
        assert_eq!(
            authorization
                .current_lease(&request)
                .unwrap()
                .authorization_epoch(),
            4
        );
    }
}
