//! Concrete daemon composition root.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gocode_api::ApiActor;
use gocode_application::ports::RuntimeAuthorityId;
use gocode_application::service::TaskRunService;
use gocode_http::admission::AdmissionState;
use gocode_http::health::{HealthState, RecoveryState as HttpRecoveryState};
use gocode_http::router::create_router;
use gocode_http::task_runs::TaskRunHttpState;
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use gocode_runtime::{Runtime, RuntimeGenerationId, RuntimeTaskRunHost, TokioRuntimeContext};
use gocode_store::store::StoreTransaction;

use crate::bootstrap::{BootstrapOutcome, bootstrap};
use crate::config::ConfigurationSnapshot;
use crate::error::DaemonError;
use crate::host::{HttpHost, run_http_host_until_shutdown};
use crate::recovery::{RecoveryState, enumerate_recovery_tasks};
use crate::shutdown::RuntimeTaskSupervisor;

type SqliteTaskRunService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;

/// Fully composed daemon with bootstrap locks, durable store, runtime,
/// canonical router, and shutdown authority kept alive together.
pub struct DaemonApplication {
    bootstrap: BootstrapOutcome,
    store: StoreTransaction,
    http_host: HttpHost,
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
        let authority = RuntimeAuthorityId(hex::encode(bootstrap.authority_id));
        let store = StoreTransaction::open(&config.db_path, authority.clone())
            .map_err(|error| DaemonError::Bootstrap(format!("open runtime store: {error:?}")))?;
        let service: Arc<SqliteTaskRunService> = Arc::new(TaskRunService::new(
            store.clone(),
            store.clone(),
            store.clone(),
            authority,
        ));

        let runtime_config = RuntimeConfig {
            max_in_flight_requests: usize::try_from(config.max_in_flight).map_err(|_| {
                DaemonError::Config("max_in_flight does not fit this platform".to_owned())
            })?,
            ..RuntimeConfig::default()
        };
        let generation = RuntimeGenerationId(u64::from_be_bytes(
            bootstrap.authority_id[..8]
                .try_into()
                .expect("an authority always contains eight leading bytes"),
        ));
        let (handle, mut runtime_controller) = Runtime::start_borrowed(
            TokioRuntimeContext::new(generation, tokio::runtime::Handle::current()),
            service,
            runtime_config,
        )
        .map_err(|error| DaemonError::Bootstrap(format!("start runtime: {error}")))?;

        let task_run_host = RuntimeTaskRunHost::new(handle, store.clone());
        let http_recovery_state = map_recovery_state(recovery_state);
        let router = create_router(
            bootstrap.token.0,
            HealthState {
                recovery_state: http_recovery_state.clone(),
            },
            AdmissionState::new(http_recovery_state),
            TaskRunHttpState::new(
                task_run_host,
                ApiActor::new("gocode-daemon")
                    .expect("the built-in daemon actor identity is valid"),
            ),
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

        Ok(Self {
            bootstrap,
            store,
            http_host,
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
