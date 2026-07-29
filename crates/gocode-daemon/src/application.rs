//! Concrete daemon composition root.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gocode_api::ApiActor;
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use gocode_application::ports::RuntimeAuthorityId;
use gocode_application::replay_service::ReplayService;
use gocode_application::service::TaskRunService;
use gocode_http::admission::AdmissionState;
use gocode_http::conversations::ConversationHttpState;
use gocode_http::health::{HealthState, RecoveryState as HttpRecoveryState};
use gocode_http::limits::LimitsConfig;
use gocode_http::replay::{ReplayHttpBinding, ReplayHttpState};
use gocode_http::router::create_router_with_conversations;
use gocode_http::runtime_profile::RuntimeProfileHttpState;
use gocode_http::task_runs::TaskRunHttpState;
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use gocode_runtime::{
    DeterministicTextProvider, Runtime, RuntimeCanonicalConversationHost, RuntimeGenerationId,
    RuntimeTaskRunHost, TokioRuntimeContext,
};
use gocode_store::replay_store::ReplayStore;
use gocode_store::schema::{ensure_event_log_lineage_id, open_with_pragmas};
use gocode_store::store::StoreTransaction;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::bootstrap::{BootstrapOutcome, bootstrap};
use crate::client_profile::PublishedClientProfile;
use crate::config::ConfigurationSnapshot;
use crate::error::DaemonError;
use crate::host::{HttpHost, run_http_host_until_shutdown};
use crate::recovery::{RecoveryState, enumerate_recovery_tasks};
use crate::shutdown::RuntimeTaskSupervisor;

type SqliteTaskRunService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;
type SqliteConversationService = ConversationService<StoreTransaction, StoreTransaction>;

/// Fully composed daemon with bootstrap locks, durable store, runtime,
/// canonical router, and shutdown authority kept alive together.
pub struct DaemonApplication {
    bootstrap: BootstrapOutcome,
    store: StoreTransaction,
    http_host: HttpHost,
    client_profile: PublishedClientProfile,
    runtime_controller: RuntimeController,
    task_supervisor: Arc<RuntimeTaskSupervisor>,
    shutdown_timeout: Duration,
}

impl DaemonApplication {
    /// Bootstraps storage, starts the canonical runtime, builds the production
    /// router, and binds HTTP without accepting requests yet.
    pub async fn start(config: &ConfigurationSnapshot) -> Result<Self, DaemonError> {
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

        let bootstrap = bootstrap(config)?;
        let recovery_state = enumerate_recovery_tasks(&bootstrap.db_conn)?;
        let replay_lineage = ensure_event_log_lineage_id(&bootstrap.db_conn).map_err(|error| {
            DaemonError::Bootstrap(format!("initialize replay lineage: {error}"))
        })?;
        let replay_connection = open_with_pragmas(&config.db_path)
            .map_err(|error| DaemonError::Bootstrap(format!("open replay store: {error}")))?;
        let authority = RuntimeAuthorityId(hex::encode(bootstrap.authority_id));
        let store = StoreTransaction::open(&config.db_path, authority.clone())
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
        let conversation_text_service: Arc<dyn ConversationTextCommandService> = Arc::new(
            ConversationTextService::new(store.clone(), store.clone(), authority),
        );

        let runtime_config = RuntimeConfig {
            max_in_flight_requests: usize::try_from(config.max_in_flight).map_err(|_| {
                DaemonError::Config("max_in_flight does not fit this platform".to_owned())
            })?,
            ..RuntimeConfig::default()
        };
        let generation = RuntimeGenerationId(generate_runtime_generation());
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
        );
        let http_recovery_state = map_recovery_state(recovery_state);
        let actor =
            ApiActor::new("gocode-daemon").expect("the built-in daemon actor identity is valid");
        let replay_binding = ReplayHttpBinding::new(
            bootstrap.authority_id,
            i64::try_from(generation.0)
                .map_err(|_| DaemonError::Bootstrap("replay generation overflow".to_owned()))?,
            0,
        )
        .map_err(|error| DaemonError::Bootstrap(format!("configure replay transport: {error}")))?;
        let replay_service = ReplayService::new(
            Arc::new(ReplayStore::new(replay_connection)),
            derive_replay_secret(&bootstrap.token.0),
            replay_lineage,
        );
        let router = create_router_with_conversations(
            bootstrap.token.0,
            HealthState {
                recovery_state: http_recovery_state.clone(),
            },
            AdmissionState::new(http_recovery_state),
            TaskRunHttpState::new(task_run_host, actor.clone()),
            ConversationHttpState::new(conversation_host, actor),
            RuntimeProfileHttpState::new(
                gocode_runtime::bundle::BUNDLE_ID,
                gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH,
                env!("CARGO_PKG_VERSION"),
                gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES,
            ),
            ReplayHttpState::new(replay_service, replay_binding, LimitsConfig::default()),
        );
        let shutdown_timeout = Duration::from_millis(config.shutdown_timeout_ms);
        let http_host = match HttpHost::bind(&config.http_bind, router).await {
            Ok(host) => host,
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
        };
        let client_profile_result = http_host.local_addr().and_then(|address| {
            PublishedClientProfile::publish(std::path::Path::new(&config.token_path), address)
        });
        let client_profile = match client_profile_result {
            Ok(profile) => profile,
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
        };

        Ok(Self {
            bootstrap,
            store,
            http_host,
            client_profile,
            runtime_controller,
            task_supervisor: RuntimeTaskSupervisor::new(),
            shutdown_timeout,
        })
    }

    /// Returns the bound local address before the accept loop starts.
    pub fn local_addr(&self) -> Result<SocketAddr, DaemonError> {
        self.http_host.local_addr()
    }

    /// Returns the stable runtime authority without exposing credentials.
    pub fn authority_id(&self) -> [u8; 16] {
        self.bootstrap.authority_id
    }

    /// Reports whether bootstrap reopened an existing database.
    pub fn db_existed(&self) -> bool {
        self.bootstrap.db_existed
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
            mut runtime_controller,
            task_supervisor,
            shutdown_timeout,
        } = self;

        let http_result = run_http_host_until_shutdown(
            http_host.start(),
            &task_supervisor,
            duration_millis(shutdown_timeout),
            shutdown,
        )
        .await;
        let runtime_result = shutdown_runtime(&mut runtime_controller, shutdown_timeout).await;

        drop(client_profile);
        drop(store);
        drop(bootstrap);

        combine_shutdown_results(http_result, runtime_result)
    }
}

fn generate_runtime_generation() -> u64 {
    loop {
        let generation = OsRng.next_u64() & i64::MAX as u64;
        if generation != 0 {
            return generation;
        }
    }
}

fn derive_replay_secret(token: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/replay-cursor-hmac/v1\0");
    hasher.update(token);
    hasher.finalize().into()
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
