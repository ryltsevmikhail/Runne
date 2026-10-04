use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, HeaderMap};
use runne_provider::ProviderFuture;
use runne_store::provider::ProviderFinalSendAuthority;
use tokio::time::timeout;

use super::{NativeTransport, NativeTransportError, NativeTransportResponse};
use crate::{MAX_RESPONSE_BYTES, MAX_RESPONSE_CHUNKS};

/// Fixed HTTPS reqwest transport used by production.
pub struct ReqwestNativeTransport {
    client: reqwest::Client,
    idle_timeout: Duration,
}

impl ReqwestNativeTransport {
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

    #[cfg(test)]
    pub(crate) const fn from_client(client: reqwest::Client, idle_timeout: Duration) -> Self {
        Self {
            client,
            idle_timeout,
        }
    }
}

impl NativeTransport for ReqwestNativeTransport {
    fn send(
        &self,
        url: String,
        headers: HeaderMap,
        body: Vec<u8>,
        final_send: ProviderFinalSendAuthority,
    ) -> ProviderFuture<'_, Result<NativeTransportResponse, NativeTransportError>> {
        Box::pin(async move {
            final_send.consume().map_err(|_| NativeTransportError)?;
            let mut response = self
                .client
                .post(url)
                .headers(headers)
                .header(CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(|_| NativeTransportError)?;
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
                    .map_err(|_| NativeTransportError)?
                    .map_err(|_| NativeTransportError)?;
                let Some(chunk) = chunk else { break };
                chunks = chunks
                    .checked_add(1)
                    .filter(|value| *value <= MAX_RESPONSE_CHUNKS)
                    .ok_or(NativeTransportError)?;
                let next = bytes
                    .len()
                    .checked_add(chunk.len())
                    .filter(|value| *value <= MAX_RESPONSE_BYTES)
                    .ok_or(NativeTransportError)?;
                bytes.reserve(next - bytes.len());
                bytes.extend_from_slice(&chunk);
            }
            Ok(NativeTransportResponse {
                url,
                status,
                content_type,
                body: bytes,
            })
        })
    }
}
