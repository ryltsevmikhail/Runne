use super::*;

impl DaemonCanonicalProviderService {
    pub(crate) async fn compose(
        c: DaemonCanonicalProviderComposition,
    ) -> Result<Arc<Self>, DaemonError> {
        let DaemonCanonicalProviderComposition {
            db_path,
            dispatch_connection,
            execution_connection,
            credential_connection,
            runtime_authority_id,
            runtime_generation,
            activation_provenance,
            expected_profile_digest,
            secondary_catalog,
            d2_tool_loop_budget,
            conversation_store,
            conversation_service,
            prohibited_content,
            trust,
            profile,
            adapter_factory,
            provider_id,
            model_id,
            model_revision,
            scope,
            credential_id,
            quota_store,
            dependencies,
        } = c;
        let selected_dependencies = dependencies::select(dependencies);
        let effect_source = selected_dependencies.effect;
        #[cfg(test)]
        let secondary_effect_override = selected_dependencies.secondary_effect;
        #[cfg(not(test))]
        let secondary_effect_override: Option<Arc<dyn CanonicalProviderEffect>> = None;
        #[cfg(all(feature = "test-support", not(test)))]
        let adapter_override = selected_dependencies.adapter_override;
        let retained_keyring = selected_dependencies.keyring;
        let terminal_store_decorator = selected_dependencies.decorator;
        let fixture_transport = selected_dependencies.fixture_transport;
        #[cfg(test)]
        let credential_versions = selected_dependencies.credential_versions;
        #[cfg(test)]
        let primary_missing_fixture = selected_dependencies.primary_missing_fixture;
        if profile.profile_digest() != expected_profile_digest {
            return Err(DaemonError::Bootstrap(
                "provider profile binding mismatch".into(),
            ));
        }
        // This exact, separately selected identity is an opt-in profile;
        // text-only submissions keep the existing profile and digest.
        #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
        let tool_profile = d2_tool_loop_budget.and_then(|_| {
            super::openai_profile::opt_in_tool_profile(profile.as_ref())
                .or_else(|| super::deepseek_profile::opt_in_tool_profile(profile.as_ref()))
        });
        #[cfg(not(all(feature = "desktop-protected", target_os = "linux")))]
        let tool_profile = None;
        let dispatch_store = Arc::new(
            SqliteProviderDispatchStore::open_with_connection(&db_path, dispatch_connection)
                .map_err(|_| {
                    DaemonError::Bootstrap("provider dispatch store unavailable".into())
                })?,
        );
        super::settle_startup::settle_uncertain_without_delivery(dispatch_store.as_ref());
        let execution_store = Arc::new(
            SqliteProviderExecutionStore::open_with_connection(&db_path, execution_connection)
                .map_err(|_| {
                    DaemonError::Bootstrap("provider execution store unavailable".into())
                })?,
        );
        let scanner_store = Arc::new(
            SqliteProviderRecoveryStore::open(std::path::Path::new(&db_path), runtime_authority_id)
                .map_err(|_| {
                    DaemonError::Bootstrap("provider scanner recovery unavailable".into())
                })?,
        );
        let fencing_token = runtime_generation;
        let launch_capability = runtime_launch::activate(
            execution_store.as_ref(),
            runtime_authority_id,
            runtime_generation,
            &activation_provenance,
            profile.as_ref(),
            &scope,
        )?;
        #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
        let tool_profile_grant = super::tool_grant::install(
            tool_profile.as_deref(),
            d2_tool_loop_budget,
            provider_id.as_ref(),
            execution_store.as_ref(),
            &launch_capability,
        )?;
        #[cfg(not(all(feature = "desktop-protected", target_os = "linux")))]
        let _tool_profile_grant: Option<
            runne_store::provider::ProviderSecondaryProfileGrant,
        > = {
            let _ = d2_tool_loop_budget;
            None
        };
        let (secondary_grant, secondary_effects_metadata) =
            secondary_background::install_catalog_and_metadata(
                execution_store.as_ref(),
                &launch_capability,
                secondary_catalog.clone(),
                &db_path,
                runtime_authority_id,
                secondary_effect_override
                    .as_deref()
                    .map(|adapter| adapter.recovery_capabilities()),
            )?;
        let registry =
            Arc::new(runne_observability::operational::RecoveryObservationRegistry::new().0);
        let keyring =
            retained_keyring.unwrap_or_else(|| native_journal_keyring(runtime_authority_id));
        let tail_store: Arc<dyn WithheldTailStore> = if fixture_transport {
            Arc::new(LoopbackWithheldTailStore::default())
        } else {
            native_withheld_tail_store(runtime_authority_id)
        };
        let runtime_store = runtime_store::compose_runtime_store(
            Arc::clone(&execution_store),
            runtime_generation,
            terminal_store_decorator,
        );
        #[cfg(test)]
        let mut credentials = if primary_missing_fixture {
            credential_reader::fixture_missing(
                credential_connection,
                credential_id,
                effect_source.clone().expect("fixture adapter exists"),
            )?
        } else {
            match effect_source.clone() {
                Some(effect) if credential_id != ProviderCredentialId::OpenAi => {
                    credential_reader::fixture_enrolled(
                        credential_connection,
                        credential_id,
                        effect,
                    )?
                }
                Some(effect) => credential_reader::fixture(
                    credential_connection,
                    runtime_authority_id,
                    runtime_generation,
                    credential_id,
                    credential_versions,
                    effect,
                )?,
                None => credential_reader::production(
                    credential_connection,
                    credential_id,
                    adapter_factory.as_ref(),
                    activation_provenance.is_protected(),
                    tool_profile.as_ref().is_some_and(|p| {
                        p.profile_id()
                            == runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID
                    }),
                    None,
                )?,
            }
        };
        #[cfg(all(feature = "test-support", not(test)))]
        let mut credentials = match effect_source.clone() {
            Some(effect) => credential_reader::fixture(
                credential_connection,
                runtime_authority_id,
                runtime_generation,
                credential_id,
                effect,
            )?,
            None => {
                let selected = adapter_override
                    .as_deref()
                    .unwrap_or(adapter_factory.as_ref());
                credential_reader::production(
                    credential_connection,
                    credential_id,
                    selected,
                    activation_provenance.is_protected(),
                    tool_profile.as_ref().is_some_and(|p| {
                        p.profile_id()
                            == runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID
                    }),
                    None,
                )?
            }
        };
        #[cfg(not(any(test, feature = "test-support")))]
        let mut credentials = credential_reader::production(
            credential_connection,
            credential_id,
            adapter_factory.as_ref(),
            activation_provenance.is_protected(),
            tool_profile.as_ref().is_some_and(|p| {
                p.profile_id() == runne_provider_deepseek::DEEPSEEK_RESPONSES_TOOL_PROFILE_ID
            }),
            super::delivery_status::observer(&db_path),
        )?;
        let tool_adapter = credentials.tool_adapter.take().or_else(|| {
            tool_profile
                .as_ref()
                .map(|_| Arc::clone(&credentials.adapter))
        });
        let defer_initial_credential_reconciliation = credentials.defer_initial_reconciliation;
        let enrollment_store_authority = credentials
            .enrollment_authorities
            .as_ref()
            .map(|a| a.store.clone());
        let credential_enrollment_control =
            enrollment_control::compose(&mut credentials, runtime_authority_id, 1)?;
        let matcher = ProhibitedContentCredentialMatcher::new(prohibited_content.as_ref());
        let redaction = ProviderEventRedactionBoundary::new(
            tail_store.as_ref(),
            scanner_store.as_ref(),
            &matcher,
        );
        let execution = RuntimeProviderExecution::new(
            keyring.as_ref(),
            runtime_store.as_ref(),
            profile.as_ref(),
            prohibited_content.as_ref(),
            &redaction,
        );
        journal_bootstrap::initialize(
            execution_store.as_ref(),
            &execution,
            keyring.as_ref(),
            profile.as_ref(),
            credentials.status,
            expected_profile_digest,
            runtime_authority_id,
        )?;
        let (context, facts) = remote_context::compose(&keyring, &execution_store);
        let (secondary_profile, saved_remote_gate, secondary_effects_metadata) =
            secondary_background::compose_optional_secondary_background(
                secondary_catalog.as_ref(),
                secondary_background::SecondaryBackgroundConfig {
                    db_path: db_path.clone(),
                    execution: Arc::clone(&execution_store),
                    context: Arc::clone(&context),
                    runtime_authority: runtime_authority_id,
                    protected_activation: activation_provenance.is_protected(),
                    adapter_override: secondary_effect_override.clone(),
                    grant: secondary_grant,
                },
                secondary_effects_metadata,
            )?;
        let service = Arc::new(Self {
            dispatch_store,
            execution_store,
            credential_store: credentials.store,
            enrollment_store_authority,
            quota_store,
            credential_readback: credentials.readback,
            credential_status: credentials.status,
            credential_enrollment_control,
            runtime_store,
            conversation_store,
            conversation_service,
            adapter: credentials.adapter,
            profile,
            tool_profile,
            tool_adapter,
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            tool_profile_grant,
            provider_id,
            model_id,
            model_revision,
            keyring,
            remote_fact_authenticator: facts,
            prohibited_content,
            trust,
            scanner_store,
            tail_store,
            runtime_authority_id,
            database_generation: 1,
            runtime_generation,
            fencing_token,
            launch_capability,
            renewal_dispatch_gate: super::dispatch_gate::ProviderDispatchGate::default(),
            recovery_registry: registry,
            secondary_profile,
            secondary_effects_metadata,
            saved_remote_gate,
        });
        credential_reconciliation::finish_composition(
            &service,
            defer_initial_credential_reconciliation,
            effect_source.is_some(),
        )
        .await?;
        Ok(service)
    }
}
