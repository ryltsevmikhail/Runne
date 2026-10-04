use reqwest::header::{CONTENT_TYPE, HeaderMap};
use runne_provider::ProviderFuture;
use runne_store::provider::ProviderFinalSendAuthority;
use std::time::Duration;
use tokio::time::timeout;

use crate::{MAX_RESPONSE_BYTES, MAX_RESPONSE_CHUNKS};

/// Response returned by a bounded Radius transport seam.
#[derive(Debug, Clone)]
pub struct RadiusTransportResponse {
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
#[error("Radius transport unavailable")]
pub struct RadiusTransportError;

/// Injectable transport for production and deterministic HTTP fixtures.
pub trait RadiusTransport: Send + Sync {
    /// Sends one already-rendered request with sensitive headers.
    fn send(
        &self,
        url: String,
        headers: HeaderMap,
        body: Vec<u8>,
        final_send: ProviderFinalSendAuthority,
    ) -> ProviderFuture<'_, Result<RadiusTransportResponse, RadiusTransportError>>;
}

pub(super) fn valid_sse_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// Fixed HTTPS reqwest transport used by production.
pub struct ReqwestRadiusTransport {
    client: reqwest::Client,
    idle_timeout: Duration,
}

impl ReqwestRadiusTransport {
    /// Builds the production transport with proxies, redirects and retries disabled.
    pub fn new(idle_timeout: Duration) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(15))
                .build()?,
            idle_timeout,
        })
    }
}

impl RadiusTransport for ReqwestRadiusTransport {
    fn send(
        &self,
        url: String,
        headers: HeaderMap,
        body: Vec<u8>,
        final_send: ProviderFinalSendAuthority,
    ) -> ProviderFuture<'_, Result<RadiusTransportResponse, RadiusTransportError>> {
        Box::pin(async move {
            final_send.consume().map_err(|_| RadiusTransportError)?;
            let mut response = self
                .client
                .post(url)
                .headers(headers)
                .body(body)
                .send()
                .await
                .map_err(|_| RadiusTransportError)?;
            let url = response.url().to_string();
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let mut bytes = Vec::new();
            let mut chunks = 0usize;
            loop {
                let chunk = timeout(self.idle_timeout, response.chunk())
                    .await
                    .map_err(|_| RadiusTransportError)?
                    .map_err(|_| RadiusTransportError)?;
                let Some(chunk) = chunk else { break };
                chunks = chunks
                    .checked_add(1)
                    .filter(|value| *value <= MAX_RESPONSE_CHUNKS)
                    .ok_or(RadiusTransportError)?;
                let next = bytes
                    .len()
                    .checked_add(chunk.len())
                    .filter(|value| *value <= MAX_RESPONSE_BYTES)
                    .ok_or(RadiusTransportError)?;
                bytes.reserve(next - bytes.len());
                bytes.extend_from_slice(&chunk);
            }
            Ok(RadiusTransportResponse {
                url,
                status,
                content_type,
                body: bytes,
            })
        })
    }
}
