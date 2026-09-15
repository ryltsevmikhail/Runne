use reqwest::header::{HeaderName, HeaderValue};
use std::time::Duration;

use crate::bounds::{append_bounded, record_chunk, wait_for_chunk};
use runne_provider::ProviderFuture;

const MAX_BODY_BYTES: usize = 524_288;

/// Response returned by a bounded Chat transport seam.
#[derive(Debug, Clone)]
pub struct ChatTransportResponse {
    /// Final URL observed after the request, used for exact endpoint checks.
    pub url: String,
    /// HTTP status code.
    pub status: u16,
    /// Content-Type value, if supplied by the server.
    pub content_type: Option<String>,
    /// Bounded response bytes.
    pub body: Vec<u8>,
}

/// Transport failure without retaining provider response or credential data.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("Chat Completions transport unavailable")]
pub struct ChatTransportError;

/// Injectable transport used by production and deterministic HTTP fixtures.
pub trait ChatCompletionsTransport: Send + Sync {
    /// Sends one already-rendered request with the supplied sensitive header.
    fn send(
        &self,
        url: String,
        header: HeaderName,
        value: HeaderValue,
        body: Vec<u8>,
    ) -> ProviderFuture<'_, Result<ChatTransportResponse, ChatTransportError>>;
}

/// Fixed HTTPS transport for production dispatch.
pub struct ReqwestChatTransport {
    client: reqwest::Client,
}

impl ReqwestChatTransport {
    /// Builds the production transport with no proxy, redirects or retries.
    pub fn new() -> Result<Self, ChatTransportError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| ChatTransportError)?;
        Ok(Self { client })
    }
}

impl ChatCompletionsTransport for ReqwestChatTransport {
    fn send(
        &self,
        url: String,
        header: HeaderName,
        value: HeaderValue,
        body: Vec<u8>,
    ) -> ProviderFuture<'_, Result<ChatTransportResponse, ChatTransportError>> {
        Box::pin(async move {
            let response = self
                .client
                .post(url)
                .header(header, value)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await
                .map_err(|_| ChatTransportError)?;
            let status = response.status().as_u16();
            let url = response.url().to_string();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let mut response = response;
            let mut body = Vec::new();
            let mut chunks = 0;
            loop {
                let chunk = wait_for_chunk(response.chunk())
                    .await
                    .map_err(|_| ChatTransportError)?
                    .map_err(|_| ChatTransportError)?;
                let Some(chunk) = chunk else { break };
                record_chunk(&mut chunks).map_err(|_| ChatTransportError)?;
                append_bounded(&mut body, &chunk, MAX_BODY_BYTES)
                    .map_err(|_| ChatTransportError)?;
            }
            Ok(ChatTransportResponse {
                url,
                status,
                content_type,
                body,
            })
        })
    }
}
