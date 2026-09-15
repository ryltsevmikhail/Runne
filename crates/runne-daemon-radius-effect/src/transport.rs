use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use runne_provider::{
    DispatchError, ProviderPreEffectRejection, ProviderStreamEventKind, ProviderStreamId,
};
use runne_provider_quota::{
    QuotaDecision, QuotaEvidenceSink, QuotaIdentity, SubscriptionBudgetAuthority,
};
use runne_provider_radius::{DEFAULT_RADIUS_GATEWAY, RadiusStreamDecoder};
use runne_secure_store::ProviderCredentialDispatchMaterializer;
use runne_store::provider::ProviderEffectStartReceipt;
use std::sync::Arc;
use tokio::time::{timeout, timeout_at};

use crate::{
    MAX_RESPONSE_BYTES, RadiusAuth, RadiusEffect, RadiusEffectConfig, RadiusEffectError, Ready,
    StreamEntry, credentials,
};

pub fn build(
    profile: runne_provider_radius::RadiusProfile,
    auth: RadiusAuth,
    materializer: Arc<dyn ProviderCredentialDispatchMaterializer>,
    config: RadiusEffectConfig,
    transport: Arc<dyn RadiusTransport>,
    quota_sink: Option<Arc<dyn QuotaEvidenceSink>>,
    budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
) -> Result<Arc<RadiusEffect>, RadiusEffectError> {
    if profile.base_url() != DEFAULT_RADIUS_GATEWAY || config.max_concurrent == 0 {
        return Err(RadiusEffectError::InvalidProfile);
    }
    Ok(Arc::new(RadiusEffect {
        renderer: runne_provider_radius::RadiusRenderer::new(profile.clone()),
        profile,
        auth,
        materializer,
        quota_sink,
        budget,
        transport,
        config,
        permits: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent)),
        streams: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    }))
}

impl RadiusEffect {
    pub(crate) async fn dispatch_ready(
        &self,
        ready: Ready,
        receipt: ProviderEffectStartReceipt,
    ) -> Result<ProviderStreamId, DispatchError> {
        if !receipt.matches_claim(ready.request.claim())
            || !receipt.matches_credential(&ready.credential)
            || ready.request.claim().profile_digest != self.profile.profile_digest()
            || !request_matches_profile(self, &ready.request)
        {
            return Err(DispatchError::MaybeDispatched);
        }
        if std::time::Instant::now() >= receipt.deadline() {
            return Err(DispatchError::MaybeDispatched);
        }
        let permit = timeout_at(
            receipt.deadline().into(),
            self.permits.clone().acquire_owned(),
        )
        .await
        .map_err(|_| DispatchError::MaybeDispatched)?
        .map_err(|_| DispatchError::MaybeDispatched)?;
        if std::time::Instant::now() >= receipt.deadline() {
            return Err(DispatchError::MaybeDispatched);
        }
        let identity = QuotaIdentity::new(
            self.profile.provider_id(),
            ready.credential.version_ref().version(),
        )
        .map_err(|_| DispatchError::MaybeDispatched)?;
        ensure_quota_allows(self.quota_sink.as_ref(), &identity, unix_now())?;
        let material = credentials::materialize(&self.materializer, &ready, &receipt)?;
        let auth = match self.auth {
            RadiusAuth::ApiKey => credentials::bearer_header(&material)?,
        };
        let expected_url = format!("{}/messages", self.profile.base_url());
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        let response = timeout_at(
            receipt.deadline().into(),
            timeout(
                self.config.header_timeout,
                self.transport.send(
                    expected_url.clone(),
                    headers,
                    ready.request.prepared().rendered_bytes().to_vec(),
                ),
            ),
        )
        .await
        .map_err(|_| DispatchError::MaybeDispatched)?
        .map_err(|_| DispatchError::MaybeDispatched)?
        .map_err(|_| DispatchError::MaybeDispatched)?;
        if std::time::Instant::now() >= receipt.deadline() {
            return Err(DispatchError::MaybeDispatched);
        }
        if response.status != 200
            || response.url != expected_url
            || !response
                .content_type
                .as_deref()
                .is_some_and(valid_sse_content_type)
            || response.body.is_empty()
            || response.body.len() > MAX_RESPONSE_BYTES
        {
            return Err(DispatchError::MaybeDispatched);
        }
        let mut decoder = RadiusStreamDecoder::new();
        decoder
            .push(&response.body)
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let events = decoder
            .finish()
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let stream = ProviderStreamId::from_bytes(*ready.request.attempt_id().as_bytes());
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| DispatchError::MaybeDispatched)?;
        if streams.contains_key(&stream) {
            return Err(DispatchError::AttemptConflict);
        }
        streams.insert(
            stream,
            StreamEntry {
                events: events.clone().into(),
                _permit: permit,
            },
        );
        drop(streams);
        record_usage(self.quota_sink.as_ref(), &identity, &events);
        spend_budget(self.budget.as_ref(), &identity, &events);
        Ok(stream)
    }
}

fn spend_budget(
    budget: Option<&Arc<dyn SubscriptionBudgetAuthority>>,
    identity: &QuotaIdentity,
    events: &[runne_provider::ProviderStreamEvent],
) {
    let Some(budget) = budget else { return };
    let tokens: u64 = events
        .iter()
        .filter_map(|event| match event.kind() {
            ProviderStreamEventKind::Usage { usage } => {
                usage.input_tokens().checked_add(usage.output_tokens())
            }
            _ => None,
        })
        .sum();
    let _ = budget.spend(
        identity.provider_id(),
        identity.credential_version(),
        tokens,
    );
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |duration| duration.as_secs().max(1))
}

fn ensure_quota_allows(
    sink: Option<&Arc<dyn QuotaEvidenceSink>>,
    identity: &QuotaIdentity,
    now: u64,
) -> Result<(), DispatchError> {
    let Some(sink) = sink else { return Ok(()) };
    match sink.admission(identity, now) {
        QuotaDecision::Allow | QuotaDecision::AllowUnknown | QuotaDecision::AllowStale => Ok(()),
        QuotaDecision::PauseExhausted { .. } | QuotaDecision::Unavailable => Err(
            DispatchError::RejectedBeforeEffect(ProviderPreEffectRejection::BudgetDenied),
        ),
    }
}

fn record_usage(
    sink: Option<&Arc<dyn QuotaEvidenceSink>>,
    identity: &QuotaIdentity,
    events: &[runne_provider::ProviderStreamEvent],
) {
    let Some(sink) = sink else { return };
    let observed_at = unix_now();
    for event in events {
        if let ProviderStreamEventKind::Usage { usage } = event.kind() {
            let _ = sink.record_usage(
                identity,
                usage.input_tokens(),
                usage.output_tokens(),
                observed_at,
            );
        }
    }
}

mod http;
use http::valid_sse_content_type;
pub use http::{
    RadiusTransport, RadiusTransportError, RadiusTransportResponse, ReqwestRadiusTransport,
};

fn request_matches_profile(
    effect: &RadiusEffect,
    request: &runne_provider::DispatchRequest,
) -> bool {
    let Ok(expected) = effect.renderer.prepare(request.prepared().call()) else {
        return false;
    };
    expected.request_ref() == request.prepared().request_ref()
        && expected.render_digest() == request.prepared().render_digest()
        && expected.rendered_bytes() == request.prepared().rendered_bytes()
}
