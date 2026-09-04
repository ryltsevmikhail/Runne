use super::*;
use crate::canonical_provider::{
    OpenAiTextProviderProfile, ProviderEffectFactory, SharedTextProviderProfile,
    deepseek_effect_adapter, local_engine_effect_adapter, openai_effect_adapter,
};
use runne_daemon_local_engine_effect::LocalEngineTextProfile;
use runne_provider_deepseek::{
    DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DeepSeekResponsesTextProfile,
};
use runne_provider_openai::{OPENAI_MODEL_ID, OPENAI_MODEL_REVISION, OpenAiResponsesTextProfile};
use runne_secure_store::ProviderCredentialId;

pub(super) struct SelectedProviderRuntime {
    pub(super) profile: Arc<SharedTextProviderProfile>,
    pub(super) adapter_factory: Arc<ProviderEffectFactory>,
    pub(super) provider_id: &'static str,
    pub(super) model_id: &'static str,
    pub(super) model_revision: &'static str,
    pub(super) scope: &'static str,
    pub(super) credential_id: ProviderCredentialId,
}

pub(super) fn select_provider_runtime(
    activation: &ProviderActivation,
) -> Result<Option<SelectedProviderRuntime>, DaemonError> {
    match activation {
        ProviderActivation::Deterministic(_) => Ok(None),
        ProviderActivation::OpenAiResponsesText(_) => openai_runtime().map(Some),
        ProviderActivation::DeepSeekResponsesText(_) => deepseek_runtime().map(Some),
        ProviderActivation::LocalEngineText(_) => local_engine_runtime().map(Some),
    }
}

pub(super) const fn provider_credential_id(
    activation: &ProviderActivation,
) -> Option<ProviderCredentialId> {
    match activation {
        ProviderActivation::Deterministic(_) => None,
        ProviderActivation::OpenAiResponsesText(_) => Some(ProviderCredentialId::OpenAi),
        ProviderActivation::DeepSeekResponsesText(_) => Some(ProviderCredentialId::DeepSeek),
        ProviderActivation::LocalEngineText(_) => Some(ProviderCredentialId::LocalEngine),
    }
}

fn openai_runtime() -> Result<SelectedProviderRuntime, DaemonError> {
    let profile = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .map_err(|_| DaemonError::Bootstrap("provider profile unavailable".into()))?;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(
            OpenAiTextProviderProfile::new(profile),
        ))),
        adapter_factory: Arc::new(|authority| {
            <dyn runne_daemon_openai_effect::OpenAiEffect>::production(authority)
                .map(openai_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))
        }),
        provider_id: "openai",
        model_id: OPENAI_MODEL_ID,
        model_revision: OPENAI_MODEL_REVISION,
        scope: "provider.openai.responses.text",
        credential_id: ProviderCredentialId::OpenAi,
    })
}

fn deepseek_runtime() -> Result<SelectedProviderRuntime, DaemonError> {
    let profile = DeepSeekResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/deepseek-responses-text-v1.json"
    ))
    .map_err(|_| DaemonError::Bootstrap("provider profile unavailable".into()))?;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile))),
        adapter_factory: Arc::new(|authority| {
            <dyn runne_daemon_deepseek_effect::DeepSeekEffect>::production(authority)
                .map(deepseek_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))
        }),
        provider_id: "deepseek",
        model_id: DEEPSEEK_MODEL_ID,
        model_revision: DEEPSEEK_MODEL_REVISION,
        scope: "provider.deepseek.responses.text",
        credential_id: ProviderCredentialId::DeepSeek,
    })
}

fn local_engine_runtime() -> Result<SelectedProviderRuntime, DaemonError> {
    let profile = LocalEngineTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/local-engine-text-v1.json"
    ))
    .map_err(|_| DaemonError::Bootstrap("provider profile unavailable".into()))?;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile))),
        adapter_factory: Arc::new(|_authority| {
            runne_daemon_local_engine_effect::production()
                .map(local_engine_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))
        }),
        provider_id: "local",
        model_id: "local-engine-text",
        model_revision: "v1",
        scope: "provider.local.engine.text",
        credential_id: ProviderCredentialId::LocalEngine,
    })
}
