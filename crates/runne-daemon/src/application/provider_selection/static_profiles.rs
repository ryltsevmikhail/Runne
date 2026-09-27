use super::*;

pub(super) fn openai_runtime() -> Result<SelectedProviderRuntime, DaemonError> {
    let profile = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .map_err(|_| DaemonError::Bootstrap("provider profile unavailable".into()))?;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(
            OpenAiTextProviderProfile::new(profile),
        ))),
        adapter_factory: Arc::new(|authority, _budget_store| {
            <dyn runne_daemon_openai_effect::OpenAiEffect>::production(authority)
                .map(openai_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))
        }),
        provider_id: Cow::Borrowed("openai"),
        model_id: Cow::Borrowed(OPENAI_MODEL_ID),
        model_revision: Cow::Borrowed(OPENAI_MODEL_REVISION),
        scope: Cow::Borrowed("provider.openai.responses.text"),
        credential_id: ProviderCredentialId::OpenAi,
    })
}

pub(super) fn deepseek_runtime() -> Result<SelectedProviderRuntime, DaemonError> {
    let profile = DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .map_err(|_| DaemonError::Bootstrap("provider profile unavailable".into()))?;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile))),
        adapter_factory: Arc::new(|authority, _budget_store| {
            let effect = {
                #[cfg(all(target_os = "linux", feature = "linux-native-enrollment-qualification"))]
                {
                    deepseek_diagnostics::production_effect(authority)
                }
                #[cfg(not(all(
                    target_os = "linux",
                    feature = "linux-native-enrollment-qualification"
                )))]
                {
                    <dyn runne_daemon_deepseek_effect::DeepSeekEffect>::production(authority)
                }
            };
            effect
                .map(deepseek_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))
        }),
        provider_id: Cow::Borrowed("deepseek"),
        model_id: Cow::Borrowed(DEEPSEEK_MODEL_ID),
        model_revision: Cow::Borrowed(DEEPSEEK_MODEL_REVISION),
        scope: Cow::Borrowed("provider.deepseek.responses.text"),
        credential_id: ProviderCredentialId::DeepSeek,
    })
}

pub(super) fn zai_runtime(
    quota_store: Arc<QuotaStateStore>,
) -> Result<SelectedProviderRuntime, DaemonError> {
    let profile = runne_provider_zai::profile();
    let profile_for_factory = profile.clone();
    let quota_sink: Arc<dyn runne_provider_quota::QuotaEvidenceSink> = quota_store;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile))),
        adapter_factory: Arc::new(move |authority, _budget_store| {
            runne_daemon_chat_completions_effect::ChatCompletionsEffect::new_with_quota(
                profile_for_factory.clone(),
                authority,
                Some(quota_sink.clone()),
            )
            .map(|effect| {
                Arc::new(effect) as Arc<dyn crate::canonical_provider::CanonicalProviderEffect>
            })
            .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))
        }),
        provider_id: Cow::Borrowed(runne_provider_zai::ZAI_PROVIDER_ID),
        model_id: Cow::Borrowed(runne_provider_zai::ZAI_MODEL_ID),
        model_revision: Cow::Borrowed(runne_provider_zai::ZAI_MODEL_REVISION),
        scope: Cow::Borrowed("provider.zai.coding.chat_completions.text"),
        credential_id: ProviderCredentialId::Zai,
    })
}

pub(super) fn qwencloud_runtime(
    quota_store: Arc<QuotaStateStore>,
) -> Result<SelectedProviderRuntime, DaemonError> {
    let profile = runne_provider_qwencloud::profile();
    let profile_for_factory = profile.clone();
    let quota_sink: Arc<dyn runne_provider_quota::QuotaEvidenceSink> = quota_store;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile))),
        adapter_factory: Arc::new(move |authority, _budget_store| {
            runne_daemon_chat_completions_effect::ChatCompletionsEffect::new_with_quota(
                profile_for_factory.clone(),
                authority,
                Some(quota_sink.clone()),
            )
            .map(|effect| {
                Arc::new(effect) as Arc<dyn crate::canonical_provider::CanonicalProviderEffect>
            })
            .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))
        }),
        provider_id: Cow::Borrowed(runne_provider_qwencloud::QWENCLOUD_PROVIDER_ID),
        model_id: Cow::Borrowed(runne_provider_qwencloud::QWENCLOUD_MODEL_ID),
        model_revision: Cow::Borrowed(runne_provider_qwencloud::QWENCLOUD_MODEL_REVISION),
        scope: Cow::Borrowed("provider.qwen.token_plan.individual.chat_completions.text"),
        credential_id: ProviderCredentialId::QwenTokenPlanIndividual,
    })
}

pub(super) fn local_engine_runtime() -> Result<SelectedProviderRuntime, DaemonError> {
    let profile = LocalEngineTextProfile::from_json(include_bytes!(
        "../../../../../docs/profiles/local-engine-text-v1.json"
    ))
    .map_err(|_| DaemonError::Bootstrap("provider profile unavailable".into()))?;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile))),
        adapter_factory: Arc::new(|_authority, _budget_store| {
            runne_daemon_local_engine_effect::production()
                .map(local_engine_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))
        }),
        provider_id: Cow::Borrowed("local"),
        model_id: Cow::Borrowed("local-engine-text"),
        model_revision: Cow::Borrowed("v1"),
        scope: Cow::Borrowed("provider.local.engine.text"),
        credential_id: ProviderCredentialId::LocalEngine,
    })
}
