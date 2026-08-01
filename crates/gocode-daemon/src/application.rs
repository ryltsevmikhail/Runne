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
    ProtectedLaunchRequestV1, ProtectedReadyV1, RuntimeSessionBinding, StableRuntimeBinding,
    StableRuntimeBindingV1,
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

include!("application/start.rs");
include!("application/access.rs");
include!("application/run.rs");
include!("application/helpers.rs");

#[cfg(test)]
mod tests {
    include!("application/tests.rs");
}
