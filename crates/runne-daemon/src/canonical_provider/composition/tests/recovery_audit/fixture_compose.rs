impl Harness {
    pub(in crate::canonical_provider::composition::tests) async fn new_openai_provider()
    -> (Self, Arc<DaemonCanonicalProviderService>) {
        let fixture = generic_openai_profile_fixture();
        let harness = Self::new_with_profile(&fixture).await;
        let effect =
            runne_daemon_openai_effect::effect_from_loopback_fixture(reqwest::Client::new())
                .unwrap()
                .0;
        let service = harness
            .compose_with_profile(
                &fixture,
                crate::canonical_provider::openai_effect_adapter(effect),
            )
            .await
            .unwrap();
        (harness, service)
    }

    pub(in crate::canonical_provider::composition::tests) async fn try_compose_openai_provider_at_generation(
        &self,
        generation: u64,
    ) -> Result<Arc<DaemonCanonicalProviderService>, DaemonError> {
        let fixture = generic_openai_profile_fixture();
        let effect =
            runne_daemon_openai_effect::effect_from_loopback_fixture(reqwest::Client::new())
                .unwrap()
                .0;
        self.compose_profile_at_generation(
            &fixture,
            crate::canonical_provider::openai_effect_adapter(effect),
            generation,
        )
        .await
    }

    pub(in crate::canonical_provider::composition::tests) async fn compose_with_profile(
        &self,
        profile: &crate::canonical_provider::composition::tests::online_dispatch::profile_fixture::PrimaryProfileFixture,
        effect: Arc<dyn CanonicalProviderEffect>,
    ) -> Result<Arc<DaemonCanonicalProviderService>, DaemonError> {
        self.compose_profile_at_generation(profile, effect, self.generation)
            .await
    }

    async fn compose_profile_at_generation(
        &self,
        profile: &crate::canonical_provider::composition::tests::online_dispatch::profile_fixture::PrimaryProfileFixture,
        effect: Arc<dyn CanonicalProviderEffect>,
        generation: u64,
    ) -> Result<Arc<DaemonCanonicalProviderService>, DaemonError> {
        if profile.profile.profile_digest() != self.profile_digest {
            return Err(DaemonError::Bootstrap(
                "test profile does not match initial runtime activation".into(),
            ));
        }
        let adapter_effect = Arc::clone(&effect);
        let adapter: Arc<ProviderEffectFactory> =
            Arc::new(move |_, _| Ok(Arc::clone(&adapter_effect)));
        let decorator = Arc::new(|store: Arc<SqliteProviderExecutionStore>, _: u64| {
            let execution: Arc<dyn ProviderExecutionStore> = store.clone();
            let terminal: Arc<dyn ProviderTerminalPersistence> = store;
            (execution, terminal)
        });
        let dependencies = ProtectedProviderDependencyCapsule::from_loopback_fixture(
            Arc::clone(&effect),
            Arc::clone(&self.keyring),
            decorator,
            Arc::new(crate::canonical_provider::credential_versions::fixture_native),
        );
        DaemonCanonicalProviderService::compose(DaemonCanonicalProviderComposition {
            db_path: self.db_path.clone(),
            dispatch_connection: self.try_writer_connection()?,
            execution_connection: self.try_writer_connection()?,
            credential_connection: self.try_writer_connection()?,
            runtime_authority_id: self.authority,
            runtime_generation: generation,
            activation_provenance: self.provenance,
            expected_profile_digest: self.profile_digest,
            secondary_catalog: None,
            d2_tool_loop_budget: None,
            conversation_store: self.store.clone(),
            conversation_service: Arc::clone(&self.conversation_service),
            prohibited_content: Arc::clone(&self.prohibited),
            trust: Some(crate::application::trust_delivery::DeliveryTrustGate::disabled()),
            profile: Arc::clone(&profile.profile),
            adapter_factory: adapter,
            provider_id: Cow::Owned(profile.provider_id.clone()),
            model_id: Cow::Owned(profile.model_id.clone()),
            model_revision: Cow::Owned(profile.model_revision.clone()),
            scope: Cow::Owned(profile.scope.clone()),
            credential_id: profile.credential_id,
            quota_store: Arc::new(runne_provider_quota::QuotaStateStore::new()),
            dependencies,
        })
        .await
    }

    async fn try_compose_configured(
        &self,
        generation: u64,
        secondary_catalog: Option<crate::canonical_provider::VerifiedSecondaryCatalog>,
        secondary_effect: Option<Arc<dyn CanonicalProviderEffect>>,
        primary_fixture: bool,
        primary_effect: Option<Arc<dyn CanonicalProviderEffect>>,
    ) -> Result<Arc<DaemonCanonicalProviderService>, DaemonError> {
        let loopback_effect = if primary_effect.is_none() {
            let effect =
                runne_daemon_openai_effect::effect_from_loopback_fixture(reqwest::Client::new())
                    .unwrap()
                    .0;
            Some(crate::canonical_provider::openai_effect_adapter(effect))
        } else {
            None
        };
        let adapter_factory: Arc<ProviderEffectFactory> = if let Some(primary) = &primary_effect {
            let primary = Arc::clone(primary);
            Arc::new(move |_, _| Ok(Arc::clone(&primary)))
        } else if primary_fixture {
            let adapter = loopback_effect
                .as_ref()
                .expect("loopback primary effect was initialized")
                .clone();
            Arc::new(move |_, _| Ok(Arc::clone(&adapter)))
        } else {
            let adapter = secondary_effect
                .as_ref()
                .expect("secondary fixture adapter is required")
                .clone();
            Arc::new(move |_, _| Ok(Arc::clone(&adapter)))
        };
        let decorator = Arc::new(|store: Arc<SqliteProviderExecutionStore>, _: u64| {
            let execution: Arc<dyn ProviderExecutionStore> = store.clone();
            let terminal: Arc<dyn ProviderTerminalPersistence> = store;
            (execution, terminal)
        });
        let dependencies = if let Some(primary) = primary_effect {
            ProtectedProviderDependencyCapsule::from_loopback_fixture(
                primary,
                Arc::clone(&self.keyring),
                decorator,
                Arc::new(crate::canonical_provider::credential_versions::fixture_native),
            )
        } else {
            let effect = loopback_effect.expect("loopback primary effect was initialized");
            match (primary_fixture, secondary_effect) {
                (true, Some(secondary)) => {
                    ProtectedProviderDependencyCapsule::from_loopback_fixture_with_secondary(
                        effect,
                        secondary,
                        Arc::clone(&self.keyring),
                        decorator,
                        Arc::new(crate::canonical_provider::credential_versions::fixture_native),
                    )
                }
                (true, None) => ProtectedProviderDependencyCapsule::from_loopback_fixture(
                    effect,
                    Arc::clone(&self.keyring),
                    decorator,
                    Arc::new(crate::canonical_provider::credential_versions::fixture_native),
                ),
                (false, Some(secondary)) => {
                    ProtectedProviderDependencyCapsule::production_with_secondary_fixture(
                        secondary,
                        Arc::clone(&self.keyring),
                        decorator,
                    )
                }
                (false, None) => unreachable!("secondary fixture adapter is required"),
            }
        };
        DaemonCanonicalProviderService::compose(DaemonCanonicalProviderComposition {
            db_path: self.db_path.clone(),
            dispatch_connection: self.try_writer_connection()?,
            execution_connection: self.try_writer_connection()?,
            credential_connection: self.try_writer_connection()?,
            runtime_authority_id: self.authority,
            runtime_generation: generation,
            activation_provenance: self.provenance,
            expected_profile_digest: self.profile_digest,
            secondary_catalog,
            d2_tool_loop_budget: None,
            conversation_store: self.store.clone(),
            conversation_service: Arc::clone(&self.conversation_service),
            prohibited_content: Arc::clone(&self.prohibited),
            trust: Some(crate::application::trust_delivery::DeliveryTrustGate::disabled()),
            profile: openai_profile(),
            adapter_factory,
            provider_id: Cow::Borrowed("openai"),
            model_id: Cow::Borrowed(runne_provider_openai::OPENAI_MODEL_ID),
            model_revision: Cow::Borrowed(runne_provider_openai::OPENAI_MODEL_REVISION),
            scope: Cow::Borrowed("provider.openai.responses.text"),
            credential_id: ProviderCredentialId::OpenAi,
            quota_store: Arc::new(runne_provider_quota::QuotaStateStore::new()),
            dependencies,
        })
        .await
    }
}

fn generic_openai_profile_fixture(
) -> crate::canonical_provider::composition::tests::online_dispatch::profile_fixture::PrimaryProfileFixture{
    use runne_provider::{ProviderCapability, ProviderInputRole, ProviderTextInput};

    let profile = openai_profile();
    let activation = ProviderActivation::from_binding(
        runne_api::ProviderActivationBindingV1::openai_responses_text_v1(),
    );
    let call = runne_provider::ProviderCall::new(
        runne_provider::ProviderCallId::from_bytes([0xA7; 16]),
        runne_provider::ModelRef::new(
            runne_provider::ProviderId::new("openai").unwrap(),
            runne_provider_openai::OPENAI_MODEL_ID,
            runne_provider_openai::OPENAI_MODEL_REVISION,
        )
        .unwrap(),
        [0xB8; 32],
        32,
        profile.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "recovery fixture").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    crate::canonical_provider::composition::tests::online_dispatch::profile_fixture::PrimaryProfileFixture {
        activation,
        profile,
        provider_id: "openai".into(),
        model_id: runne_provider_openai::OPENAI_MODEL_ID.into(),
        model_revision: runne_provider_openai::OPENAI_MODEL_REVISION.into(),
        scope: "provider.openai.responses.text".into(),
        credential_id: ProviderCredentialId::Generic("openai"),
        call,
    }
}
