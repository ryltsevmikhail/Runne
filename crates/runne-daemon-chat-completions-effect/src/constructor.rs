use super::transport::{ChatCompletionsTransport, ReqwestChatTransport};
use super::{ChatCompletionsEffect, ChatCompletionsEffectError, auth::ChatCompletionsAuthHeader};
use runne_provider_chat_completions::{ChatCompletionsProfile, ChatCompletionsRenderer};
use runne_provider_quota::{QuotaEvidenceSink, SubscriptionBudgetAuthority};
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use std::sync::Arc;

impl ChatCompletionsEffect {
    /// Constructs a production effect with a fixed profile and secure-store reader.
    ///
    /// # Errors
    ///
    /// Returns a closed effect error when the profile fails validation or the
    /// production transport cannot be built.
    pub fn new(
        profile: ChatCompletionsProfile,
        credentials: Arc<dyn ProviderCredentialDispatchMaterializer>,
    ) -> Result<Self, ChatCompletionsEffectError> {
        Self::new_with_quota(profile, credentials, None)
    }

    /// Constructs an effect with an optional provider-neutral quota evidence sink.
    ///
    /// The sink receives only credential identity and normalized token counts;
    /// it never participates in credential materialization or network requests.
    ///
    /// # Errors
    ///
    /// Returns a closed effect error when the profile fails validation or the
    /// production transport cannot be built.
    pub fn new_with_quota(
        profile: ChatCompletionsProfile,
        credentials: Arc<dyn ProviderCredentialDispatchMaterializer>,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    ) -> Result<Self, ChatCompletionsEffectError> {
        Self::new_with_quota_and_auth(
            profile,
            credentials,
            quota_sink,
            ChatCompletionsAuthHeader::Authorization,
        )
    }

    /// Constructs an effect with optional durable subscription accounting.
    ///
    /// # Errors
    ///
    /// Returns a closed effect error when the profile fails validation or the
    /// production transport cannot be built.
    pub fn new_with_quota_and_budget(
        profile: ChatCompletionsProfile,
        credentials: Arc<dyn ProviderCredentialDispatchMaterializer>,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
        budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    ) -> Result<Self, ChatCompletionsEffectError> {
        let renderer = ChatCompletionsRenderer::new(profile.clone())
            .map_err(|_| ChatCompletionsEffectError)?;
        let transport =
            Arc::new(ReqwestChatTransport::new().map_err(|_| ChatCompletionsEffectError)?);
        Ok(Self {
            profile,
            renderer,
            credentials,
            transport,
            quota_sink,
            budget,
            streams: super::streams::StreamStore::new(),
            auth_header: ChatCompletionsAuthHeader::Authorization,
        })
    }

    /// Constructs an effect with a caller-supplied bounded transport seam.
    ///
    /// # Errors
    ///
    /// Returns a closed effect error when the profile fails validation.
    pub fn new_with_transport(
        profile: ChatCompletionsProfile,
        credentials: Arc<dyn ProviderCredentialDispatchMaterializer>,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
        auth_header: ChatCompletionsAuthHeader,
        transport: Arc<dyn ChatCompletionsTransport>,
    ) -> Result<Self, ChatCompletionsEffectError> {
        let renderer = ChatCompletionsRenderer::new(profile.clone())
            .map_err(|_| ChatCompletionsEffectError)?;
        Ok(Self::build(
            profile,
            credentials,
            quota_sink,
            auth_header,
            renderer,
            transport,
        ))
    }

    /// Constructs an effect with an explicit provider authentication header.
    ///
    /// # Errors
    ///
    /// Returns a closed effect error when the profile fails validation or the
    /// production transport cannot be built.
    pub fn new_with_quota_and_auth(
        profile: ChatCompletionsProfile,
        credentials: Arc<dyn ProviderCredentialDispatchMaterializer>,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
        auth_header: ChatCompletionsAuthHeader,
    ) -> Result<Self, ChatCompletionsEffectError> {
        let renderer = ChatCompletionsRenderer::new(profile.clone())
            .map_err(|_| ChatCompletionsEffectError)?;
        let transport =
            Arc::new(ReqwestChatTransport::new().map_err(|_| ChatCompletionsEffectError)?);
        Ok(Self::build(
            profile,
            credentials,
            quota_sink,
            auth_header,
            renderer,
            transport,
        ))
    }

    fn build(
        profile: ChatCompletionsProfile,
        credentials: Arc<dyn ProviderCredentialDispatchMaterializer>,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
        auth_header: ChatCompletionsAuthHeader,
        renderer: ChatCompletionsRenderer,
        transport: Arc<dyn ChatCompletionsTransport>,
    ) -> Self {
        Self {
            profile,
            renderer,
            credentials,
            transport,
            quota_sink,
            budget: None,
            streams: super::streams::StreamStore::new(),
            auth_header,
        }
    }
}
