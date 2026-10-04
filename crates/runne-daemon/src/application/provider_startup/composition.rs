use super::*;
use runne_provider_quota::QuotaStateStore;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;

impl DaemonApplication {
    pub(in crate::application) async fn start_with_bootstrap(
        config: &ConfigurationSnapshot,
        bootstrap: BootstrapOutcome,
        startup: StartupProvider,
    ) -> Result<Self, DaemonError> {
        let recovery_state = enumerate_recovery_tasks(&bootstrap.db_conn)?;
        let replay_lineage = ensure_event_log_lineage_id(&bootstrap.db_conn).map_err(|error| {
            DaemonError::Bootstrap(format!("initialize replay lineage: {error}"))
        })?;
        let replay_connection = open_runtime_connection(
            &config.db_path,
            runne_store::schema::ConnectionMode::ValidatedReopen,
            bootstrap.authority_id,
            replay_lineage,
            "replay store",
        )?;
        let authority = RuntimeAuthorityId(hex::encode(bootstrap.authority_id));
        let secret_broker = Arc::new(Mutex::new(SecretBroker::new()));
        #[cfg(all(target_os = "linux", feature = "test-support", not(test)))]
        {
            let mut broker = secret_broker
                .lock()
                .map_err(|_| DaemonError::Bootstrap("initialize T1 fixture registry".into()))?;
            super::t1_fixture_secret::register_if_selected(&mut broker)
                .map_err(|_| DaemonError::Bootstrap("register T1 fixture canary".into()))?;
        }
        let prohibited_content: Arc<dyn ProhibitedContentPort> = Arc::new(
            secret_broker
                .lock()
                .map_err(|_| {
                    DaemonError::Bootstrap("initialize prohibited-content registry".to_owned())
                })?
                .prohibited_content_guard(),
        );
        // Single process-wide project trust authority (T1): opened once next
        // to the canonical store and shared by the root-admission gate, the
        // replay delivery authorization and the provider dispatch gate.
        #[cfg(feature = "desktop-protected")]
        let trust_authority: Option<Arc<ProjectTrustPolicyAuthority>> =
            match runne_store::ProjectTrustStore::open(
                std::path::Path::new(&config.db_path),
                bootstrap.authority_id,
            ) {
                Ok(trust_store) => Some(Arc::new(
                    ProjectTrustPolicyAuthority::new(Arc::new(trust_store))
                        .with_byte_inspection(Arc::clone(&prohibited_content)),
                )),
                Err(_) => None,
            };
        #[cfg(not(feature = "desktop-protected"))]
        let trust_authority: Option<Arc<ProjectTrustPolicyAuthority>> = None;
        let store_writer = open_runtime_connection(
            &config.db_path,
            runne_store::schema::ConnectionMode::ValidatedReopen,
            bootstrap.authority_id,
            replay_lineage,
            "runtime writer",
        )?;
        let store_reader = open_runtime_connection(
            &config.db_path,
            runne_store::schema::ConnectionMode::Reader,
            bootstrap.authority_id,
            replay_lineage,
            "runtime reader",
        )?;
        let store = StoreTransaction::open_with_connections(
            &config.db_path,
            store_writer,
            store_reader,
            authority.clone(),
            Arc::clone(&prohibited_content),
        )
        .map_err(|error| DaemonError::Bootstrap(format!("open runtime store: {error:?}")))?;
        let service: Arc<SqliteTaskRunService> = Arc::new(
            TaskRunService::new(
                store.clone(),
                store.clone(),
                store.clone(),
                authority.clone(),
            )
            .with_unknown_successor_repository(Arc::new(
                store.unknown_successor_repository(Arc::new(
                    crate::canonical_provider::CompiledHistoricalProviderModelResolver,
                )),
            )),
        );
        let conversation_service: Arc<SqliteConversationService> = Arc::new(
            ConversationService::new(store.clone(), store.clone(), authority.clone()),
        );
        let conversation_text_service: Arc<dyn ConversationTextCommandService> =
            Arc::new(ConversationTextService::new(
                store.clone(),
                store.clone(),
                authority.clone(),
                Arc::clone(&prohibited_content),
            ));
        // X2 restart settlement: close provably effect-free generations the
        // dead instance left in Started before any client can attach.
        let settled = super::startup_settlement::settle_interrupted_text_generations(
            &bootstrap.db_conn,
            &conversation_text_service,
            &authority,
        )?;
        if settled > 0 {
            tracing::info!(
                generations = settled,
                "settled interrupted text generations at restart"
            );
        }
        let mut session_id = *uuid::Uuid::now_v7().as_bytes();
        while session_id == bootstrap.launch_identity.daemon_instance_id().into_bytes() {
            session_id = *uuid::Uuid::now_v7().as_bytes();
        }
        let (
            provider_activation,
            activation_provenance,
            launch_authority_id,
            protected_activation,
            dependencies,
            root_admission_keys,
            enrollment_capability,
            secondary_catalog,
        ) = startup.into_parts();
        let launch_authority_id =
            launch_authority_id.unwrap_or(bootstrap.local_session_authority_id);
        #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
        let installed_candidate = protected_activation
            && super::installed_candidate::has_installed_candidate(&config.db_path);
        #[cfg(not(all(target_os = "linux", feature = "desktop-protected")))]
        let installed_candidate = false;
        let provider_profile_digest = *provider_activation.binding().profile_digest();
        let readiness_credential_id = provider_credential_id(&provider_activation);
        let quota_store = Arc::new(QuotaStateStore::new());
        let compose_result = match activation_provenance {
            Some(activation_provenance) => {
                let selected_provider =
                    select_provider_runtime_with_quota(&provider_activation, quota_store.clone())?;
                compose_selected_provider(&provider_activation, || {
                    let db_path = config.db_path.clone();
                    let dispatch_connection = open_runtime_connection(
                        &db_path,
                        runne_store::schema::ConnectionMode::ValidatedReopen,
                        bootstrap.authority_id,
                        replay_lineage,
                        "provider dispatch store",
                    );
                    let execution_connection = open_runtime_connection(
                        &db_path,
                        runne_store::schema::ConnectionMode::ValidatedReopen,
                        bootstrap.authority_id,
                        replay_lineage,
                        "provider execution store",
                    );
                    let conversation_store = store.clone();
                    let credential_connection = open_runtime_connection(
                        &db_path,
                        runne_store::schema::ConnectionMode::ValidatedReopen,
                        bootstrap.authority_id,
                        replay_lineage,
                        "provider credential store",
                    );
                    let conversation_service = Arc::clone(&conversation_text_service);
                    let prohibited_content = Arc::clone(&prohibited_content);
                    // Dispatch fail-closed parity with replay: a protected
                    // composition whose authority failed to open gates ALL
                    // provider deliveries as denied (closed), never skip.
                    #[cfg(feature = "desktop-protected")]
                    let trust_gate = match trust_authority.as_ref() {
                        Some(authority) => {
                            crate::application::trust_delivery::DeliveryTrustGate::open(
                                Arc::clone(authority),
                                &store,
                            )
                        }
                        None => crate::application::trust_delivery::DeliveryTrustGate::closed(),
                    };
                    #[cfg(not(feature = "desktop-protected"))]
                    let trust_gate =
                        crate::application::trust_delivery::DeliveryTrustGate::disabled();
                    async move {
                        let dispatch_connection = dispatch_connection?;
                        let execution_connection = execution_connection?;
                        let credential_connection = credential_connection?;
                        let dependencies = dependencies.ok_or_else(|| {
                            DaemonError::Bootstrap("provider dependencies unavailable".into())
                        })?;
                        let selected_provider = selected_provider.ok_or_else(|| {
                            DaemonError::Bootstrap("provider selection unavailable".into())
                        })?;
                        DaemonCanonicalProviderService::compose(
                            DaemonCanonicalProviderComposition {
                                db_path,
                                dispatch_connection,
                                execution_connection,
                                credential_connection,
                                runtime_authority_id: bootstrap.authority_id,
                                runtime_generation: bootstrap.launch_generation,
                                activation_provenance,
                                expected_profile_digest: provider_profile_digest,
                                secondary_catalog,
                                conversation_store,
                                conversation_service,
                                prohibited_content,
                                trust: Some(trust_gate.clone()),
                                profile: selected_provider.profile,
                                adapter_factory: selected_provider.adapter_factory,
                                provider_id: selected_provider.provider_id,
                                model_id: selected_provider.model_id,
                                model_revision: selected_provider.model_revision,
                                scope: selected_provider.scope,
                                credential_id: selected_provider.credential_id,
                                quota_store: quota_store.clone(),
                                dependencies,
                            },
                        )
                        .await
                    }
                })
                .await
            }
            None => Ok(None),
        };
        composition_diagnostics::record_result(
            matches!(&compose_result, Ok(Some(_))),
            compose_result.as_ref().err(),
        );
        let (provider_service, provider_readiness) = match compose_result {
            Ok(Some(service)) => {
                let readiness = service.current_provider_readiness();
                (Some(service), readiness)
            }
            Ok(None) => (None, ProviderActivationReadinessV1::Ready),
            Err(_error) if protected_activation => {
                let readiness = match readiness_credential_id {
                    Some(credential_id) => {
                        crate::canonical_provider::probe_provider_readiness(
                            bootstrap.authority_id,
                            credential_id,
                        )
                        .await
                    }
                    None => ProviderActivationReadinessV1::SecureStoreUnavailable,
                };
                (
                    None,
                    if readiness.is_ready() {
                        ProviderActivationReadinessV1::SecureStoreUnavailable
                    } else {
                        readiness
                    },
                )
            }
            Err(error) => return Err(error),
        };
        let executable_sha256 =
            *super::super::executable_identity::measure_launched_executable()?.executable_sha256();
        http_startup::start_http_and_runtime(
            config,
            bootstrap,
            recovery_state,
            replay_connection,
            replay_lineage,
            store,
            service,
            conversation_service,
            conversation_text_service,
            secret_broker,
            prohibited_content,
            trust_authority.clone(),
            provider_activation,
            provider_service,
            protected_activation,
            installed_candidate,
            launch_authority_id,
            executable_sha256,
            session_id,
            root_admission_keys,
            provider_readiness,
            enrollment_capability,
        )
        .await
    }
}
