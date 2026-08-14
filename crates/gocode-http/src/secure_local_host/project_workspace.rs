use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use gocode_api::{
    CommandReconciliationHostPort, ConversationCommandHostPort, ConversationQueryHostPort,
    ProjectWorkspaceCommandHostPort, ProjectWorkspaceQueryHostPort, RuntimeSessionBinding,
    TaskRunCommandHostPort, TaskRunQueryHostPort,
};
use tokio::net::TcpListener;

use super::{LocalRuntimeTlsHost, LocalRuntimeTlsHostError};
use crate::{
    admission::AdmissionState, command_reconciliation::CommandReconciliationHttpState,
    conversations::ConversationHttpState, health::HealthState, local_session::VerifiedLocalTls,
    operational_telemetry::OperationalTelemetryHttpState,
    project_workspace::ProjectWorkspaceHttpState, replay::ReplayHttpState,
    router::SecureLocalHttpHost, runtime_profile::RuntimeProfileHttpState,
    task_runs::TaskRunHttpState,
};

impl LocalRuntimeTlsHost {
    /// Adds read-only command reconciliation to the complete production host.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind_with_project_workspace_and_command_reconciliation<T, C, P, R>(
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
        project_workspace_state: ProjectWorkspaceHttpState<P>,
        reconciliation_state: CommandReconciliationHttpState<R>,
        replay_state: ReplayHttpState,
        operational_telemetry_state: OperationalTelemetryHttpState,
    ) -> Result<Self, LocalRuntimeTlsHostError>
    where
        T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
        C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
        P: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort + 'static,
        R: CommandReconciliationHostPort + 'static,
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
        let host = SecureLocalHttpHost::new_with_project_workspace_and_command_reconciliation(
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
            project_workspace_state,
            reconciliation_state,
            replay_state,
            operational_telemetry_state,
        )
        .map_err(|_| LocalRuntimeTlsHostError::Incompatible)?;
        Ok(Self {
            listener,
            host,
            server_config,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn bind_with_project_workspace<T, C, P>(
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
        project_workspace_state: ProjectWorkspaceHttpState<P>,
        replay_state: ReplayHttpState,
        operational_telemetry_state: OperationalTelemetryHttpState,
    ) -> Result<Self, LocalRuntimeTlsHostError>
    where
        T: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
        C: ConversationCommandHostPort + ConversationQueryHostPort + 'static,
        P: ProjectWorkspaceCommandHostPort + ProjectWorkspaceQueryHostPort + 'static,
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
        let host = SecureLocalHttpHost::new_with_project_workspace(
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
            project_workspace_state,
            replay_state,
            operational_telemetry_state,
        )
        .map_err(|_| LocalRuntimeTlsHostError::Incompatible)?;
        Ok(Self {
            listener,
            host,
            server_config,
        })
    }
}
