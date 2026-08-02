use super::replay_authorization::DaemonReplayAuthorization;
use super::shutdown::map_recovery_state;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn start_http_and_runtime(
    config: &ConfigurationSnapshot,
    bootstrap: BootstrapOutcome,
    recovery_state: RecoveryState,
    replay_connection: rusqlite::Connection,
    replay_lineage: gocode_domain::id::EventLogLineageId,
    store: StoreTransaction,
    service: Arc<SqliteTaskRunService>,
    conversation_service: Arc<SqliteConversationService>,
    conversation_text_service: Arc<dyn ConversationTextCommandService>,
    secret_broker: Arc<Mutex<SecretBroker>>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    provider_activation: ProviderActivation,
    provider_service: Option<Arc<DaemonCanonicalOpenAiService>>,
    protected_activation: bool,
    session_id: [u8; 16],
) -> Result<DaemonApplication, DaemonError> {
    let runtime_config = RuntimeConfig {
        max_in_flight_requests: usize::try_from(config.max_in_flight).map_err(|_| {
            DaemonError::Config("max_in_flight does not fit this platform".to_owned())
        })?,
        ..RuntimeConfig::default()
    };
    let generation = RuntimeGenerationId(bootstrap.launch_generation);
    let (handle, mut runtime_controller) = if let Some(provider_service) = provider_service {
        Runtime::start_borrowed_with_provider_conversations(
            TokioRuntimeContext::new(generation, tokio::runtime::Handle::current()),
            service,
            conversation_text_service,
            provider_service,
            runtime_config,
        )
    } else {
        Runtime::start_borrowed_with_conversations(
            TokioRuntimeContext::new(generation, tokio::runtime::Handle::current()),
            service,
            conversation_text_service,
            runtime_config,
        )
    }
    .map_err(|error| DaemonError::Bootstrap(format!("start runtime: {error}")))?;

    let task_run_host = RuntimeTaskRunHost::new(handle.clone(), store.clone());
    let conversation_host = if provider_activation.requires_openai_execution() {
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
    let stable_binding = StableRuntimeBinding::new(
        bootstrap.local_session_authority_id,
        ApiPrincipalId::new("local-owner")
            .map_err(|_| DaemonError::Bootstrap("invalid local principal".into()))?,
        replay_lineage,
        gocode_runtime::bundle::BUNDLE_ID,
        schema_hash,
        gocode_http::runtime_profile::ordered_capability_digest(
            gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES,
        ),
    )
    .map_err(|_| DaemonError::Bootstrap("build stable local session binding".into()))?;
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

    Ok(DaemonApplication {
        bootstrap,
        store,
        http_host,
        client_profile,
        binding,
        local_session_service,
        session_clock,
        protected_activation,
        provider_activation,
        runtime_controller,
        _secret_broker: secret_broker,
        task_supervisor: RuntimeTaskSupervisor::new(),
        shutdown_timeout,
    })
}
