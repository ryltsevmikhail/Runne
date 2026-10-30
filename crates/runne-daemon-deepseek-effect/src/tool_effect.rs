use super::{DeepSeekEffect, DeepSeekEffectError, Sender, client, profile};
use runne_provider_deepseek::{DeepSeekResponsesToolProfile, DeepSeekTransportPolicy};
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use std::sync::Arc;

impl dyn DeepSeekEffect {
    /// Creates the opt-in tool sender using the runtime-owned credential boundary.
    pub fn production_tools(
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    ) -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError> {
        Self::production_tools_inner(materializer, None)
    }

    /// Creates the opt-in tool sender with a closed delivery-stage observer.
    pub fn production_tools_with_observer(
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        observer: Arc<dyn crate::diagnostics::DeepSeekEffectObserver>,
    ) -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError> {
        Self::production_tools_inner(materializer, Some(observer))
    }

    fn production_tools_inner(
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        observer: Option<Arc<dyn crate::diagnostics::DeepSeekEffectObserver>>,
    ) -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError> {
        let profile = profile().map_err(|_| DeepSeekEffectError)?;
        let policy =
            DeepSeekTransportPolicy::for_profile(&profile).map_err(|_| DeepSeekEffectError)?;
        let client = client::production_client(&policy).map_err(|_| DeepSeekEffectError)?;
        let credential = client::NativeCredential::from_materializer(materializer);
        let mut sender = Sender::new_with_observer(profile.clone(), credential, client, observer)
            .map_err(|_| DeepSeekEffectError)?;
        sender.tool_profile =
            Some(DeepSeekResponsesToolProfile::new(profile).map_err(|_| DeepSeekEffectError)?);
        Ok(Arc::new(sender))
    }
}

/// Creates a loopback-only tool sender and its fixture authentication gate.
#[doc(hidden)]
pub fn tool_effect_from_loopback_fixture(
    client: reqwest::Client,
) -> Result<(Arc<dyn DeepSeekEffect>, client::FixtureRequestAuthenticator), DeepSeekEffectError> {
    let profile = profile().map_err(|_| DeepSeekEffectError)?;
    let credential = client::FixtureCredential::new();
    let authenticator = credential.request_authenticator();
    let mut sender =
        Sender::new(profile.clone(), credential, client).map_err(|_| DeepSeekEffectError)?;
    sender.tool_profile =
        Some(DeepSeekResponsesToolProfile::new(profile).map_err(|_| DeepSeekEffectError)?);
    Ok((Arc::new(sender), authenticator))
}

impl<C> Sender<C> {
    pub(super) fn profile_digest(&self) -> [u8; 32] {
        self.tool_profile.as_ref().map_or_else(
            || self.profile.profile_digest(),
            DeepSeekResponsesToolProfile::profile_digest,
        )
    }
}
