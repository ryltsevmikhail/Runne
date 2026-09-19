#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

//! Bounded Responses effect for the exact Codex, Copilot, Azure and xAI profiles.

use runne_provider::{
    DispatchError, DispatchRequest, ProviderPort, ProviderPreEffectRejection, ProviderStreamEvent,
    ProviderStreamEventKind, ProviderStreamId,
};
use runne_provider_oauth::{OAuthProvider, parse_stored_envelope};
use runne_provider_quota::{
    QuotaDecision, QuotaEvidenceSink, QuotaIdentity, SubscriptionBudgetAuthority,
};
use runne_provider_responses_wire::{ResponsesProfile, ResponsesStreamDecoder};
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
};
use std::any::Any;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, atomic::AtomicUsize};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

mod auth;
mod constructor;
mod port;
mod quota;
mod slot;
mod transport;
pub use auth::{AuthError, ResponsesAuth};
use slot::StreamSlot;
use transport::valid_sse_content_type;
pub use transport::{ReqwestTransport, ResponsesTransport, TransportResponse};

/// Effect construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResponsesEffectError {
    /// Authentication policy does not match the profile.
    #[error("responses auth policy does not match profile")]
    Auth,
    /// Transport could not be constructed.
    #[error("responses transport could not be constructed")]
    Transport,
    /// Azure profile has no concrete endpoint.
    #[error("responses endpoint is not concrete")]
    Endpoint,
    /// Profile does not carry the attested model reservation bound.
    #[error("responses profile reservation bound is not attested")]
    Profile,
}

/// A typed effect configuration bound to one immutable Responses profile.
#[derive(Debug, Clone)]
pub struct ResponsesEffectConfig {
    /// Exact profile.
    pub profile: ResponsesProfile,
    /// Exact authentication scheme.
    pub auth: ResponsesAuth,
}

pub use constructor::{
    fixture_effect, fixture_effect_with_quota, production_effect, production_effect_with_quota,
    production_effect_with_quota_and_budget,
};

struct Ready {
    request: DispatchRequest,
    credential: CredentialDispatchBinding,
}
impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

struct Sender {
    config: ResponsesEffectConfig,
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    transport: Arc<dyn ResponsesTransport>,
    quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    streams: Mutex<BTreeMap<ProviderStreamId, VecDeque<ProviderStreamEvent>>>,
    active_streams: Arc<AtomicUsize>,
}
impl Sender {
    fn new(
        config: ResponsesEffectConfig,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        transport: Arc<dyn ResponsesTransport>,
    ) -> Result<Self, ResponsesEffectError> {
        Self::new_with_quota(config, materializer, transport, None)
    }

    fn new_with_quota(
        config: ResponsesEffectConfig,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        transport: Arc<dyn ResponsesTransport>,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    ) -> Result<Self, ResponsesEffectError> {
        Self::new_with_quota_and_budget(config, materializer, transport, quota_sink, None)
    }

    fn new_with_quota_and_budget(
        config: ResponsesEffectConfig,
        materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
        transport: Arc<dyn ResponsesTransport>,
        quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
        budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
    ) -> Result<Self, ResponsesEffectError> {
        if config.profile.endpoint().contains('{') {
            return Err(ResponsesEffectError::Endpoint);
        }
        Ok(Self {
            config,
            materializer,
            transport,
            quota_sink,
            budget,
            streams: Mutex::new(BTreeMap::new()),
            active_streams: Arc::new(AtomicUsize::new(0)),
        })
    }
    async fn execute(
        &self,
        ready: Ready,
        receipt: ProviderEffectStartReceipt,
    ) -> Result<ProviderStreamId, DispatchError> {
        if !receipt.matches_claim(ready.request.claim())
            || !receipt.matches_credential(&ready.credential)
            || ready.request.claim().profile_digest != self.config.profile.profile_digest()
        {
            return Err(DispatchError::MaybeDispatched);
        }
        if Instant::now() >= receipt.deadline() {
            return Err(DispatchError::MaybeDispatched);
        }
        let mut slot = StreamSlot::reserve(Arc::clone(&self.active_streams))
            .ok_or(DispatchError::MaybeDispatched)?;
        let (lifecycle, fence) = ready
            .credential
            .point_of_use_revisions()
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let credential_version = ready.credential.version_ref().version();
        if let Some(sink) = self.quota_sink.as_ref() {
            let identity =
                QuotaIdentity::new(self.config.profile.provider_id(), credential_version)
                    .map_err(|_| DispatchError::MaybeDispatched)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(1, |duration| duration.as_secs().max(1));
            match sink.admission(&identity, now) {
                QuotaDecision::Allow | QuotaDecision::AllowUnknown | QuotaDecision::AllowStale => {}
                QuotaDecision::PauseExhausted { .. } | QuotaDecision::Unavailable => {
                    return Err(DispatchError::RejectedBeforeEffect(
                        ProviderPreEffectRejection::BudgetDenied,
                    ));
                }
            }
        }
        let read = runne_secure_store::ProviderCredentialDispatchRead::new(
            ready.credential.native_capability(),
            lifecycle,
            fence,
            receipt.credential_read_receipt_digest(),
        )
        .map_err(|_| DispatchError::MaybeDispatched)?;
        let material = self.materializer.materialize_active(read).map_err(|_| {
            DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::CredentialAccessDenied)
        })?;
        if Instant::now() >= receipt.deadline() {
            return Err(DispatchError::MaybeDispatched);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DispatchError::MaybeDispatched)?
            .as_secs();
        let headers = material
            .with_bytes(|bytes| match &self.config.auth {
                ResponsesAuth::Codex { .. } => {
                    let envelope = parse_stored_envelope(
                        bytes,
                        OAuthProvider::OpenAiCodex,
                        credential_version,
                        now,
                        60,
                    )
                    .map_err(|_| AuthError::Credential)?;
                    self.config.auth.headers_from_oauth_envelope(
                        &envelope,
                        ready.request.provider_idempotency_key(),
                    )
                }
                ResponsesAuth::CopilotSession => {
                    let envelope = parse_stored_envelope(
                        bytes,
                        OAuthProvider::GithubCopilot,
                        credential_version,
                        now,
                        60,
                    )
                    .map_err(|_| AuthError::Credential)?;
                    self.config.auth.headers_from_oauth_envelope(
                        &envelope,
                        ready.request.provider_idempotency_key(),
                    )
                }
                ResponsesAuth::AzureApiKey | ResponsesAuth::XaiBearer => self.config.auth.headers(
                    &Zeroizing::new(bytes.to_vec()),
                    ready.request.provider_idempotency_key(),
                ),
            })
            .map_err(|_| {
                DispatchError::RejectedBeforeEffect(
                    ProviderPreEffectRejection::CredentialUnavailable,
                )
            })?;
        let stream_id = ProviderStreamId::from_bytes(*ready.request.attempt_id().as_bytes());
        let response = self
            .transport
            .send(
                self.config.profile.endpoint(),
                headers,
                ready.request.prepared().rendered_bytes().to_vec(),
            )
            .await?;
        if Instant::now() >= receipt.deadline() {
            return Err(DispatchError::MaybeDispatched);
        }
        if response.url != self.config.profile.endpoint()
            || !(200..300).contains(&response.status)
            || !response
                .content_type
                .as_deref()
                .is_some_and(valid_sse_content_type)
        {
            return Err(DispatchError::MaybeDispatched);
        }
        let mut decoder = ResponsesStreamDecoder::for_profile(&self.config.profile);
        decoder
            .push(&response.body)
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let events = decoder
            .finish()
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| DispatchError::MaybeDispatched)?;
        streams.insert(stream_id, events.clone().into());
        drop(streams);
        quota::record_usage(
            self.config.profile.provider_id(),
            credential_version,
            self.quota_sink.as_ref(),
            &events,
        );
        quota::spend_budget(
            self.budget.as_ref(),
            self.config.profile.provider_id(),
            credential_version,
            &events,
        );
        slot.keep();
        Ok(stream_id)
    }
}

/// Object-safe combined provider boundary used by the daemon registry.
pub trait ResponsesEffect: ProviderPort + ProviderEffectPort + Send + Sync {}
impl ResponsesEffect for Sender {}

#[cfg(test)]
#[path = "effect_tests.rs"]
mod tests;
