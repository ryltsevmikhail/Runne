use reqwest::header::{HeaderMap, HeaderValue};
use runne_provider::{
    DispatchError, ProviderFuture, ProviderPreEffectRejection, ProviderStreamEventKind,
    ProviderStreamId,
};
use runne_provider_native_wire::NativeWireProfile;
use runne_provider_quota::{
    QuotaDecision, QuotaEvidenceSink, QuotaIdentity, SubscriptionBudgetAuthority,
};
use runne_store::provider::ProviderEffectStartReceipt;
use std::sync::Arc;
use tokio::time::{timeout, timeout_at};

use crate::{
    MAX_RESPONSE_BYTES, NativeEffect, NativeEffectArgs, NativeEffectError, StreamEntry,
    TrustedNativeEndpoint, credentials,
};

mod reqwest_transport;
pub use reqwest_transport::ReqwestNativeTransport;

pub fn build(args: NativeEffectArgs) -> Result<Arc<NativeEffect>, NativeEffectError> {
    crate::routes::validate_route(&args.profile, &args.endpoint, args.auth)?;
    let permits = std::num::NonZeroUsize::new(args.config.max_concurrent)
        .ok_or(NativeEffectError::InvalidDescriptor)?;
    Ok(Arc::new(NativeEffect {
        profile: args.profile,
        endpoint: args.endpoint,
        auth: args.auth,
        materializer: args.materializer,
        quota_sink: args.quota_sink,
        budget: args.budget,
        transport: args.transport,
        config: args.config,
        permits: Arc::new(tokio::sync::Semaphore::new(permits.get())),
        streams: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    }))
}

impl NativeEffect {
    pub(crate) async fn dispatch_authorized(
        &self,
        ready: super::port::AuthorizedReady,
        receipt: ProviderEffectStartReceipt,
    ) -> Result<ProviderStreamId, DispatchError> {
        if !receipt.matches_claim(ready.request.claim())
            || !receipt.matches_credential(&ready.credential)
            || ready.request.claim().profile_digest != self.profile.profile_digest()
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
        let material = credentials::materialize(
            &self.materializer,
            &ready.credential,
            receipt.credential_read_receipt_digest(),
        )
        .await?;
        let url = self.request_url();
        let mut headers = credentials::auth_headers(
            self.auth,
            &material,
            matches!(self.profile, NativeWireProfile::Anthropic(_)),
        )?;
        headers.insert(
            crate::REQUEST_ID,
            HeaderValue::from_str(ready.request.provider_idempotency_key())
                .map_err(|_| DispatchError::MaybeDispatched)?,
        );
        let response = timeout_at(
            receipt.deadline().into(),
            timeout(
                self.config.header_timeout,
                self.transport.send(
                    url.clone(),
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
            || response.url != self.request_url()
            || !response
                .content_type
                .as_deref()
                .is_some_and(valid_sse_content_type)
            || response.body.is_empty()
            || response.body.len() > MAX_RESPONSE_BYTES
        {
            return Err(DispatchError::MaybeDispatched);
        }
        let events = credentials::decode(&self.profile, &response.body)
            .map_err(|()| DispatchError::MaybeDispatched)?;
        let stream = ProviderStreamId::from_bytes(*ready.request.claim().attempt_id.as_bytes());
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

    fn request_url(&self) -> String {
        let model = crate::routes::encode_segment(self.profile.model_id());
        match &self.endpoint {
            TrustedNativeEndpoint::Anthropic { base_url } => {
                format!("{}/v1/messages", base_url.trim_end_matches('/'))
            }
            TrustedNativeEndpoint::Gemini { base_url } => format!(
                "{}/models/{model}:streamGenerateContent?alt=sse",
                base_url.trim_end_matches('/')
            ),
            TrustedNativeEndpoint::Vertex {
                base_url,
                project,
                location,
            } => format!(
                "{}/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:streamGenerateContent?alt=sse",
                base_url.trim_end_matches('/')
            ),
        }
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
    sink: Option<&std::sync::Arc<dyn QuotaEvidenceSink>>,
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

/// Response returned by a bounded native transport seam.
#[derive(Debug, Clone)]
pub struct NativeTransportResponse {
    /// Final URL observed by the transport.
    pub url: String,
    /// HTTP status code.
    pub status: u16,
    /// Content-Type value, if supplied.
    pub content_type: Option<String>,
    /// Bounded response bytes.
    pub body: Vec<u8>,
}

/// Transport failure without retaining provider response or credential data.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("native transport unavailable")]
pub struct NativeTransportError;

/// Injectable transport for production and deterministic HTTP fixtures.
pub trait NativeTransport: Send + Sync {
    /// Sends one already-rendered request with sensitive headers.
    fn send(
        &self,
        url: String,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> ProviderFuture<'_, Result<NativeTransportResponse, NativeTransportError>>;
}

fn valid_sse_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
}
