use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::application) async fn start_http_and_runtime(
    config: &ConfigurationSnapshot,
    bootstrap: BootstrapOutcome,
    recovery_state: RecoveryState,
    replay_connection: runne_store::schema::ManagedConnection,
    replay_lineage: runne_domain::id::EventLogLineageId,
    store: StoreTransaction,
    service: Arc<SqliteTaskRunService>,
    conversation_service: Arc<SqliteConversationService>,
    conversation_text_service: Arc<dyn ConversationTextCommandService>,
    secret_broker: Arc<Mutex<SecretBroker>>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    trust_authority: Option<Arc<runne_security::project_trust_policy::ProjectTrustPolicyAuthority>>,
    provider_activation: ProviderActivation,
    provider_service: Option<Arc<DaemonCanonicalProviderService>>,
    protected_activation: bool,
    installed_candidate: bool,
    launch_authority_id: [u8; 16],
    executable_sha256: [u8; 32],
    session_id: [u8; 16],
    root_admission_keys: Option<runne_api::ProtectedActivationKeys>,
    provider_readiness: runne_api::ProviderActivationReadinessV1,
    enrollment_capability: Option<
        crate::protected_activation::VerifiedProtectedEnrollmentCapability,
    >,
) -> Result<DaemonApplication, DaemonError> {
    let enrollment = linux_enrollment_control::compose_startup_enrollment(
        config,
        bootstrap.authority_id,
        replay_lineage,
        provider_service.as_ref(),
        protected_activation,
        installed_candidate,
        root_admission_keys.as_ref(),
        enrollment_capability.as_ref(),
    )?;
    let bootstrap_reservation_store = Arc::new(SqliteBootstrapReservationStore::new(
        open_runtime_connection(
            &config.db_path,
            runne_store::schema::ConnectionMode::ValidatedReopen,
            bootstrap.authority_id,
            replay_lineage,
            "bootstrap reservation store",
        )?,
    ));
    let runtime_config = linux_enrollment_control::runtime_config(config.max_in_flight)?;
    let generation = RuntimeGenerationId(bootstrap.launch_generation);
    #[cfg(not(target_os = "linux"))]
    let execution_node_epoch = Arc::new(std::sync::atomic::AtomicU64::new(
        bootstrap.launch_generation,
    ));
    let http_recovery_state = super::shutdown::map_recovery_state(recovery_state);
    let actor = ApiActor::new("runne-daemon").expect("the built-in daemon actor identity is valid");
    let replay_binding = ReplayHttpBinding::new(
        bootstrap.authority_id,
        i64::try_from(bootstrap.launch_generation)
            .map_err(|_| DaemonError::Bootstrap("replay generation overflow".to_owned()))?,
        0,
    )
    .map_err(|error| DaemonError::Bootstrap(format!("configure replay transport: {error}")))?;
    let (replay_store, replay_integrity_secret) = replay_setup::prepare_replay_reader(
        replay_connection,
        &replay_lineage,
        &bootstrap.replay_integrity_key,
    )
    .await?;
    let binding = super::http_startup_support::runtime_session_binding(
        &bootstrap,
        replay_lineage,
        enrollment.runtime_capabilities,
        session_id,
    )?;
    let launched_at = Instant::now();
    let clock: Arc<dyn Fn() -> Duration + Send + Sync> = Arc::new(move || launched_at.elapsed());
    let enrollment_routes = enrollment.routes;
    let writer_lease_routes = command_hosts::writer_lease_routes(&store);
    let local_session_service = session::compose(
        binding.clone(),
        launch_authority_id,
        executable_sha256,
        bootstrap.launch_identity.bootstrap_secret(),
        Arc::clone(&bootstrap_reservation_store),
        store.clone(),
        protected_activation,
    )?;
    let replay_state = super::http_startup_support::compose_replay_http_state(
        replay_store.clone(),
        replay_integrity_secret,
        replay_lineage,
        bootstrap.authority_id,
        local_session_service.clone(),
        trust_authority.as_ref(),
        &store,
        Arc::clone(&prohibited_content),
        replay_binding,
        enrollment
            .runtime_capabilities
            .contains(&runne_http::replay::REPLAY_BASELINE_RESUME_V2_CAPABILITY),
    );
    let telemetry_state = super::http_startup_support::operational_telemetry_state(
        provider_service.as_ref(),
        &binding,
    );
    let command_hosts = command_hosts::compose(
        &store,
        std::path::Path::new(&config.db_path),
        bootstrap.authority_id,
        Arc::clone(&prohibited_content),
        trust_authority.clone(),
        root_admission_keys,
        protected_activation,
        Arc::clone(&local_session_service),
    );
    #[cfg(target_os = "linux")]
    let registered_execution_node = execution_node::register_before_taskrun_recovery(
        &store,
        &local_session_service,
        &bootstrap,
        &binding,
    )?;
    #[cfg(target_os = "linux")]
    let execution_node_epoch = Arc::clone(&registered_execution_node.worker_epoch);
    #[cfg(target_os = "linux")]
    let node_lease_heartbeat = Arc::clone(&registered_execution_node.heartbeat);
    let automatic_taskruns = automatic_taskruns::compose(
        store.clone(),
        Arc::clone(&service),
        Arc::clone(&conversation_text_service),
        provider_service.clone(),
        bootstrap.authority_id,
        bootstrap.launch_generation,
        Arc::clone(&execution_node_epoch),
        Arc::clone(&prohibited_content),
        #[cfg(feature = "desktop-protected")]
        command_hosts.root_admission.clone(),
        #[cfg(target_os = "linux")]
        node_lease_heartbeat,
    )?;
    let provider_execution: Option<
        Arc<dyn runne_runtime::canonical_provider_execution::CanonicalProviderExecutionService>,
    > = provider_service.clone().map(|provider| provider as Arc<_>);
    let (handle, mut runtime_controller) = Runtime::start_borrowed_with_automatic_taskruns(
        TokioRuntimeContext::new(generation, tokio::runtime::Handle::current()),
        service,
        conversation_text_service,
        provider_execution,
        automatic_taskruns,
        runtime_config,
    )
    .map_err(|error| DaemonError::Bootstrap(format!("start runtime: {error}")))?;
    let runtime_liveness = handle.clone();
    let task_run_host = super::task_run_effects::build_task_run_host(
        handle.clone(),
        store.clone(),
        provider_service.clone(),
    );
    let conversation_host = if provider_activation.requires_openai_execution()
        || provider_activation.requires_deepseek_execution()
        || provider_activation.requires_native_execution()
        || provider_activation.requires_radius_execution()
    {
        RuntimeCanonicalConversationHost::<_, _, _, DeterministicTextProvider>::new_provider(
            handle,
            conversation_service,
            store.clone(),
            Arc::clone(&prohibited_content),
        )
    } else {
        RuntimeCanonicalConversationHost::new(
            handle,
            conversation_service,
            store.clone(),
            DeterministicTextProvider,
            Arc::clone(&prohibited_content),
        )
    };
    #[cfg(feature = "desktop-protected")]
    let root_control = command_hosts.root_control.clone();
    let runtime_profile_state = profile::runtime_profile(
        env!("CARGO_PKG_VERSION"),
        provider_service.clone(),
        &provider_activation,
        provider_readiness,
        enrollment.runtime_capabilities,
    );
    let pinned_model = command_hosts::pinned_task_run_model(&provider_service);
    let (selected_profiles, profile_models) =
        super::profile_models::selected_profile_models(provider_service.as_ref());
    let http_host = LocalRuntimeTlsHost::bind_with_project_workspace_and_command_reconciliation(
        &config.http_bind,
        Arc::clone(bootstrap.launch_identity.server_config()),
        HealthState {
            recovery_state: http_recovery_state.clone(),
        },
        AdmissionState::new(http_recovery_state),
        Arc::clone(&local_session_service),
        binding.clone(),
        protected_activation,
        Arc::clone(&clock),
        runtime_profile_state,
        TaskRunHttpState::new(
            task_run_host,
            actor.clone(),
            pinned_model.map(str::to_owned),
        )
        .with_prohibited_content(Arc::clone(&prohibited_content))
        .with_allowed_profiles(selected_profiles)
        .with_profile_models(profile_models),
        ConversationHttpState::new(conversation_host, actor.clone()),
        runne_http::project_workspace::ProjectWorkspaceHttpState::new(
            command_hosts.project_workspace,
            actor.clone(),
        ),
        command_hosts.trust_control_routes,
        Some(writer_lease_routes),
        runne_http::workspace_files::WorkspaceFileHttpState::new(command_hosts.workspace_files),
        runne_http::workspace_diffs::WorkspaceDiffHttpState::new(command_hosts.workspace_diffs),
        runne_http::processes::ProcessHttpState::new(command_hosts.process, actor.clone()),
        runne_http::editors::WorkspaceEditorHttpState::new(
            command_hosts.workspace_editor,
            actor.clone(),
        ),
        runne_http::command_reconciliation::CommandReconciliationHttpState::new(
            command_hosts.reconciliation,
        ),
        runne_http::approvals::ApprovalHttpState::new(command_hosts.approval, actor.clone()),
        replay_state,
        telemetry_state,
        enrollment_routes,
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
                crate::client_profile::publish_for_startup(
                    address,
                    &config.replay_integrity_key_path,
                    &bootstrap.launch_identity,
                    launch_authority_id,
                    executable_sha256,
                    bootstrap.local_session_authority_id,
                    &replay_lineage,
                    session_id,
                    enrollment.runtime_capabilities,
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
    Ok(DaemonApplication {
        bootstrap,
        #[cfg(target_os = "linux")]
        execution_node: registered_execution_node.node,
        store,
        http_host,
        client_profile,
        binding,
        local_session_service,
        session_clock: clock,
        protected_activation,
        provider_activation,
        provider_readiness,
        runtime_liveness,
        runtime_controller,
        _bootstrap_reservation_store: bootstrap_reservation_store,
        _secret_broker: secret_broker,
        task_supervisor: RuntimeTaskSupervisor::new(),
        shutdown_timeout,
        #[cfg(feature = "desktop-protected")]
        root_control,
        runtime_capabilities: enrollment.runtime_capabilities,
        credential_enrollment_control: enrollment.control,
        credential_enrollment_controls: enrollment.credential_enrollment_controls,
    })
}
