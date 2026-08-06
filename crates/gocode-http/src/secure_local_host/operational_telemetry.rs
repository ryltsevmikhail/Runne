use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use gocode_api::{
    ConversationCommandHostPort, ConversationQueryHostPort, RuntimeSessionBinding,
    TaskRunCommandHostPort, TaskRunQueryHostPort,
};
use tokio::net::TcpListener;

use super::{LocalRuntimeTlsHost, LocalRuntimeTlsHostError};
use crate::{
    admission::AdmissionState, conversations::ConversationHttpState, health::HealthState,
    local_session::VerifiedLocalTls, operational_telemetry::OperationalTelemetryHttpState,
    replay::ReplayHttpState, router::SecureLocalHttpHost, runtime_profile::RuntimeProfileHttpState,
    task_runs::TaskRunHttpState,
};

impl LocalRuntimeTlsHost {
    /// Binds loopback TLS and mounts capability-gated telemetry behind session auth.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind_with_operational_telemetry<T, C>(
        bind: &str,
        server_config: Arc<rustls::ServerConfig>,
        health_state: HealthState,
        admission_state: AdmissionState,
        local_session_service: Arc<Mutex<gocode_application::local_session::LocalSessionService>>,
        binding: RuntimeSessionBinding,
        dynamic_session_binding: bool,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>,
        runtime_profile_state: RuntimeProfileHttpState,
        task_run_state: TaskRunHttpState<T>,
        conversation_state: ConversationHttpState<C>,
        replay_state: ReplayHttpState,
        operational_telemetry_state: OperationalTelemetryHttpState,
    ) -> Result<Self, LocalRuntimeTlsHostError>
    where
        T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
        C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
    {
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|_| LocalRuntimeTlsHostError::Unavailable)?;
        if !listener
            .local_addr()
            .map_err(|_| LocalRuntimeTlsHostError::Unavailable)?
            .ip()
            .is_loopback()
        {
            return Err(LocalRuntimeTlsHostError::Unavailable);
        }
        let host = SecureLocalHttpHost::new_with_operational_telemetry(
            VerifiedLocalTls::from_verified_listener(),
            health_state,
            admission_state,
            local_session_service,
            binding,
            dynamic_session_binding,
            clock,
            runtime_profile_state,
            task_run_state,
            conversation_state,
            replay_state,
            Some(operational_telemetry_state),
        )
        .map_err(|_| LocalRuntimeTlsHostError::Incompatible)?;
        Ok(Self {
            listener,
            host,
            server_config,
        })
    }
}
