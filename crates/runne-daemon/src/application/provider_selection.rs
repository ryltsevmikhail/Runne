use super::*;
use crate::canonical_provider::{
    OpenAiTextProviderProfile, ProviderEffectFactory, SharedTextProviderProfile,
    deepseek_effect_adapter, local_engine_effect_adapter, openai_effect_adapter,
    responses_effect_adapter,
};
use crate::provider_activation::configured_profile;
use runne_daemon_local_engine_effect::LocalEngineTextProfile;
use runne_daemon_responses_effect::{
    ResponsesEffectConfig, production_effect_with_quota_and_budget,
};
use runne_provider_deepseek::{
    DEEPSEEK_MODEL_ID, DEEPSEEK_MODEL_REVISION, DeepSeekResponsesTextProfile,
};
use runne_provider_openai::{OPENAI_MODEL_ID, OPENAI_MODEL_REVISION, OpenAiResponsesTextProfile};
use runne_provider_quota::QuotaStateStore;
use runne_secure_store::ProviderCredentialId;
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use std::borrow::Cow;

mod cloud;
mod native;
mod radius;

pub(super) struct SelectedProviderRuntime {
    pub(super) profile: Arc<SharedTextProviderProfile>,
    pub(super) adapter_factory: Arc<ProviderEffectFactory>,
    pub(super) provider_id: Cow<'static, str>,
    pub(super) model_id: Cow<'static, str>,
    pub(super) model_revision: Cow<'static, str>,
    pub(super) scope: Cow<'static, str>,
    pub(super) credential_id: ProviderCredentialId,
}

#[cfg(test)]
pub(super) fn select_provider_runtime(
    activation: &ProviderActivation,
) -> Result<Option<SelectedProviderRuntime>, DaemonError> {
    select_provider_runtime_with_quota(activation, Arc::new(QuotaStateStore::new()))
}

pub(super) fn select_provider_runtime_with_quota(
    activation: &ProviderActivation,
    quota_store: Arc<QuotaStateStore>,
) -> Result<Option<SelectedProviderRuntime>, DaemonError> {
    match activation {
        ProviderActivation::Deterministic(_) => Ok(None),
        ProviderActivation::OpenAiResponsesText(_) => openai_runtime().map(Some),
        ProviderActivation::DeepSeekResponsesText(_) => deepseek_runtime().map(Some),
        ProviderActivation::ZaiCodingChatCompletionsText(_) => zai_runtime(quota_store).map(Some),
        ProviderActivation::QwenCloudTokenChatCompletionsText(_) => {
            qwencloud_runtime(quota_store).map(Some)
        }
        ProviderActivation::GenericChatCompletionsText(binding) => {
            generic_chat_runtime(binding, quota_store).map(Some)
        }
        ProviderActivation::LocalEngineText(_) => local_engine_runtime().map(Some),
        ProviderActivation::NativeText(..) => native::runtime(activation, quota_store).map(Some),
        ProviderActivation::RadiusText(..) => radius::runtime(activation, quota_store).map(Some),
        ProviderActivation::ResponsesText(..) => {
            responses_runtime(activation, quota_store).map(Some)
        }
        ProviderActivation::CloudText(..) => cloud::runtime(activation, quota_store).map(Some),
    }
}

pub(super) fn provider_credential_id(
    activation: &ProviderActivation,
) -> Option<ProviderCredentialId> {
    match activation {
        ProviderActivation::Deterministic(_) => None,
        ProviderActivation::OpenAiResponsesText(_) => Some(ProviderCredentialId::OpenAi),
        ProviderActivation::DeepSeekResponsesText(_) => Some(ProviderCredentialId::DeepSeek),
        ProviderActivation::ZaiCodingChatCompletionsText(_) => Some(ProviderCredentialId::Zai),
        ProviderActivation::QwenCloudTokenChatCompletionsText(_) => {
            Some(ProviderCredentialId::QwenTokenPlanIndividual)
        }
        ProviderActivation::GenericChatCompletionsText(binding) => generic_profile(binding)
            .and_then(|profile| ProviderCredentialId::from_account(profile.provider_id)),
        ProviderActivation::LocalEngineText(_) => Some(ProviderCredentialId::LocalEngine),
        ProviderActivation::NativeText(binding, _) => native::credential_id(binding),
        ProviderActivation::RadiusText(_, _) => Some(ProviderCredentialId::Generic("radius")),
        ProviderActivation::ResponsesText(binding, _) => binding
            .profile_id()
            .split('/')
            .nth(1)
            .and_then(ProviderCredentialId::from_account),
        ProviderActivation::CloudText(binding, _) => binding
            .profile_id()
            .split('/')
            .nth(1)
            .and_then(ProviderCredentialId::from_account),
    }
}

fn responses_runtime(
    activation: &ProviderActivation,
    quota_store: Arc<QuotaStateStore>,
) -> Result<SelectedProviderRuntime, DaemonError> {
    let ProviderActivation::ResponsesText(binding, settings) = activation else {
        return Err(DaemonError::Config("Responses activation expected".into()));
    };
    let (profile, auth) = configured_profile(binding.profile_id(), settings)
        .map_err(|message| DaemonError::Config(message.into()))?;
    if profile.profile_digest() != *binding.profile_digest()
        || profile.profile_id() != binding.profile_id()
    {
        return Err(DaemonError::Config(
            "Responses profile digest mismatch".into(),
        ));
    }
    let provider_id = profile.provider_id().to_owned();
    let model_id = profile.model().to_owned();
    let model_revision = profile.model_revision().to_owned();
    let scope = format!("provider.{provider_id}.responses.text");
    let profile_for_factory = profile.clone();
    let auth_for_factory = auth.clone();
    let quota_sink: Arc<dyn runne_provider_quota::QuotaEvidenceSink> = quota_store;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile))),
        adapter_factory: Arc::new(
            move |materializer, budget_store: Arc<SqliteProviderCredentialLifecycleStore>| {
                production_effect_with_quota_and_budget(
                    ResponsesEffectConfig {
                        profile: profile_for_factory.clone(),
                        auth: auth_for_factory.clone(),
                    },
                    materializer,
                    quota_sink.clone(),
                    Some(budget_store),
                )
                .map(responses_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("Responses provider unavailable".into()))
            },
        ),
        provider_id: Cow::Owned(provider_id),
        model_id: Cow::Owned(model_id),
        model_revision: Cow::Owned(model_revision),
        scope: Cow::Owned(scope),
        credential_id: ProviderCredentialId::from_account(
            binding.profile_id().split('/').nth(1).unwrap_or_default(),
        )
        .ok_or_else(|| DaemonError::Config("Responses credential is not closed".into()))?,
    })
}

fn generic_profile(
    binding: &runne_api::ProviderActivationBindingV1,
) -> Option<&'static runne_provider_chat_completions::GenericChatProfile> {
    runne_provider_chat_completions::generic_profiles()
        .iter()
        .find(|profile| {
            profile.profile_id == binding.profile_id()
                && profile.profile.profile_digest() == *binding.profile_digest()
        })
}

fn generic_chat_runtime(
    binding: &runne_api::ProviderActivationBindingV1,
    quota_store: Arc<QuotaStateStore>,
) -> Result<SelectedProviderRuntime, DaemonError> {
    let profile = generic_profile(binding)
        .ok_or_else(|| DaemonError::Config("unknown generic provider profile".into()))?;
    let profile_for_factory = profile.profile.clone();
    let provider_id = profile.provider_id;
    let profile_for_effect = profile_for_factory.clone();
    let model_id = Cow::Owned(profile_for_factory.model_id().to_owned());
    let model_revision = Cow::Owned(profile_for_factory.model_revision().to_owned());
    let quota_sink: Arc<dyn runne_provider_quota::QuotaEvidenceSink> = quota_store;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(
            profile_for_factory,
        ))),
        adapter_factory: Arc::new(
            move |authority, budget_store: Arc<SqliteProviderCredentialLifecycleStore>| {
                runne_daemon_chat_completions_effect::ChatCompletionsEffect::new_with_quota_and_budget(
                profile_for_effect.clone(),
                authority,
                Some(quota_sink.clone()),
                Some(budget_store),
            )
            .map(|effect| {
                Arc::new(effect) as Arc<dyn crate::canonical_provider::CanonicalProviderEffect>
            })
            .map_err(|_| DaemonError::Bootstrap("provider adapter unavailable".into()))
            },
        ),
        provider_id: Cow::Borrowed(provider_id),
        model_id,
        model_revision,
        scope: Cow::Borrowed("provider.generic.chat_completions.text"),
        credential_id: ProviderCredentialId::from_account(provider_id).ok_or_else(|| {
            DaemonError::Config("generic provider credential is not closed".into())
        })?,
    })
}

mod static_profiles;

use static_profiles::{
    deepseek_runtime, local_engine_runtime, openai_runtime, qwencloud_runtime, zai_runtime,
};

#[cfg(test)]
#[path = "provider_selection_catalog_tests.rs"]
mod catalog_tests;
#[cfg(test)]
#[path = "provider_selection_cloud_tests.rs"]
mod cloud_tests;
#[cfg(test)]
#[path = "provider_selection_matrix_tests.rs"]
mod matrix_tests;
#[cfg(test)]
#[path = "provider_selection_responses_tests.rs"]
mod responses_tests;
#[cfg(test)]
#[path = "provider_selection_tests.rs"]
mod tests;
