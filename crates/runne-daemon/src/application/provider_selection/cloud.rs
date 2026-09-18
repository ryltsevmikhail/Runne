use super::SelectedProviderRuntime;
use crate::canonical_provider::{CanonicalProviderEffect, SharedTextProviderProfile};
use crate::error::DaemonError;
use crate::provider_activation::ProviderActivation;
use crate::provider_activation::cloud::configured_profile;
use runne_daemon_chat_completions_effect::ChatCompletionsEffect;
use runne_provider_quota::QuotaStateStore;
use runne_secure_store::ProviderCredentialId;
use std::{borrow::Cow, sync::Arc};

pub(super) fn runtime(
    activation: &ProviderActivation,
    quota_store: Arc<QuotaStateStore>,
) -> Result<SelectedProviderRuntime, DaemonError> {
    let ProviderActivation::CloudText(binding, settings) = activation else {
        return Err(DaemonError::Config("Cloud activation expected".into()));
    };
    ProviderActivation::validate_settings(binding.mode(), binding.profile_id(), settings)
        .map_err(|message| DaemonError::Config(message.into()))?;
    let (profile, auth_header) = configured_profile(binding.profile_id(), settings)
        .map_err(|message| DaemonError::Config(message.into()))?;
    if profile.profile_digest() != *binding.profile_digest()
        || profile.profile_id() != binding.profile_id()
    {
        return Err(DaemonError::Config("Cloud profile digest mismatch".into()));
    }
    let provider_id = profile.provider_id().to_owned();
    let profile_for_factory = profile.clone();
    let quota_sink: Arc<dyn runne_provider_quota::QuotaEvidenceSink> = quota_store;
    Ok(SelectedProviderRuntime {
        profile: Arc::new(SharedTextProviderProfile::new(Arc::new(profile.clone()))),
        adapter_factory: Arc::new(move |materializer, _budget_store| {
            ChatCompletionsEffect::new_with_quota_and_auth(
                profile_for_factory.clone(),
                materializer,
                Some(quota_sink.clone()),
                auth_header,
            )
            .map(|effect| Arc::new(effect) as Arc<dyn CanonicalProviderEffect>)
            .map_err(|_| DaemonError::Bootstrap("Cloud provider unavailable".into()))
        }),
        provider_id: Cow::Owned(provider_id.clone()),
        model_id: Cow::Owned(profile.model_id().to_owned()),
        model_revision: Cow::Owned(profile.model_revision().to_owned()),
        scope: Cow::Owned(format!(
            "provider.{provider_id}.cloud.chat_completions.text"
        )),
        credential_id: ProviderCredentialId::from_account(&provider_id)
            .ok_or_else(|| DaemonError::Config("Cloud credential is not closed".into()))?,
    })
}
