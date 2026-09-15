use super::{
    ReqwestTransport, ResponsesEffect, ResponsesEffectConfig, ResponsesEffectError,
    ResponsesTransport, Sender,
};
use runne_provider_quota::{QuotaEvidenceSink, SubscriptionBudgetAuthority};
use runne_provider_responses_wire::ResponsesProfile;
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use std::sync::Arc;

/// Creates a production effect with shared provider-neutral quota evidence.
pub fn production_effect_with_quota(
    config: ResponsesEffectConfig,
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    quota_sink: Arc<dyn QuotaEvidenceSink>,
) -> Result<Arc<dyn ResponsesEffect>, ResponsesEffectError> {
    production_effect_with_quota_and_budget(config, materializer, quota_sink, None)
}

/// Creates a production effect with quota evidence and durable subscription accounting.
pub fn production_effect_with_quota_and_budget(
    config: ResponsesEffectConfig,
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    quota_sink: Arc<dyn QuotaEvidenceSink>,
    budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
) -> Result<Arc<dyn ResponsesEffect>, ResponsesEffectError> {
    if !config
        .auth
        .matches_provider_id(config.profile.provider_id())
    {
        return Err(ResponsesEffectError::Auth);
    }
    if config.profile.endpoint().contains('{') {
        return Err(ResponsesEffectError::Endpoint);
    }
    validate_profile(&config.profile)?;
    let transport = Arc::new(ReqwestTransport::new().map_err(|_| ResponsesEffectError::Transport)?);
    Ok(Arc::new(Sender::new_with_quota_and_budget(
        config,
        materializer,
        transport,
        Some(quota_sink),
        budget,
    )?))
}

/// Constructs a fixture effect with shared quota evidence.
pub fn fixture_effect_with_quota(
    config: ResponsesEffectConfig,
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    transport: Arc<dyn ResponsesTransport>,
    quota_sink: Arc<dyn QuotaEvidenceSink>,
) -> Result<Arc<dyn ResponsesEffect>, ResponsesEffectError> {
    if !config
        .auth
        .matches_provider_id(config.profile.provider_id())
    {
        return Err(ResponsesEffectError::Auth);
    }
    validate_profile(&config.profile)?;
    Ok(Arc::new(Sender::new_with_quota(
        config,
        materializer,
        transport,
        Some(quota_sink),
    )?))
}

/// Creates a production effect with the fixed HTTPS transport and secure broker.
pub fn production_effect(
    config: ResponsesEffectConfig,
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
) -> Result<Arc<dyn ResponsesEffect>, ResponsesEffectError> {
    if !config
        .auth
        .matches_provider_id(config.profile.provider_id())
    {
        return Err(ResponsesEffectError::Auth);
    }
    if config.profile.endpoint().contains('{') {
        return Err(ResponsesEffectError::Endpoint);
    }
    validate_profile(&config.profile)?;
    let transport = Arc::new(ReqwestTransport::new().map_err(|_| ResponsesEffectError::Transport)?);
    Ok(Arc::new(Sender::new(config, materializer, transport)?))
}

/// Constructs an effect with a deterministic fixture transport.
pub fn fixture_effect(
    config: ResponsesEffectConfig,
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    transport: Arc<dyn ResponsesTransport>,
) -> Result<Arc<dyn ResponsesEffect>, ResponsesEffectError> {
    if !config
        .auth
        .matches_provider_id(config.profile.provider_id())
    {
        return Err(ResponsesEffectError::Auth);
    }
    validate_profile(&config.profile)?;
    Ok(Arc::new(Sender::new(config, materializer, transport)?))
}

fn validate_profile(profile: &ResponsesProfile) -> Result<(), ResponsesEffectError> {
    if profile.provider() == runne_provider_responses_wire::ResponsesProvider::OpenAiCodex
        && (profile.model() != runne_provider_responses_wire::CODEX_MODEL
            || profile.max_output_tokens()
                != runne_provider_responses_wire::CODEX_MAX_OUTPUT_TOKENS)
    {
        return Err(ResponsesEffectError::Profile);
    }
    Ok(())
}
