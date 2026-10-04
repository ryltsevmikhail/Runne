use reqwest::{header::HeaderMap, redirect::Policy};
use runne_provider::{DispatchError, ProviderFuture};
use runne_store::provider::ProviderFinalSendAuthority;
use std::time::Duration;

const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_CHUNKS: usize = 16_384;

/// Bounded transport response passed to the Responses decoder.
#[derive(Debug)]
pub struct TransportResponse {
    /// Final URL after transport.
    pub url: String,
    /// HTTP status.
    pub status: u16,
    /// Content type, if supplied.
    pub content_type: Option<String>,
    /// Bounded response bytes.
    pub body: Vec<u8>,
}

/// Transport abstraction enabling deterministic fixture servers without network credentials.
pub trait ResponsesTransport: Send + Sync {
    /// Sends one request with already constructed sensitive headers.
    fn send<'a>(
        &'a self,
        url: &'a str,
        headers: HeaderMap,
        body: Vec<u8>,
        final_send: ProviderFinalSendAuthority,
    ) -> ProviderFuture<'a, Result<TransportResponse, DispatchError>>;
}

/// Production HTTPS transport with redirects, retries and proxies disabled.
pub struct ReqwestTransport {
    client: reqwest::Client,
    idle_timeout: Duration,
}
impl ReqwestTransport {
    /// Builds a bounded transport with fixed timeouts.
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .use_rustls_tls()
                .https_only(true)
                .no_proxy()
                .redirect(Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(10))
                .build()?,
            idle_timeout: Duration::from_secs(30),
        })
    }
}
impl ResponsesTransport for ReqwestTransport {
    fn send<'a>(
        &'a self,
        url: &'a str,
        headers: HeaderMap,
        body: Vec<u8>,
        final_send: ProviderFinalSendAuthority,
    ) -> ProviderFuture<'a, Result<TransportResponse, DispatchError>> {
        Box::pin(async move {
            final_send.consume().map_err(|_| {
                DispatchError::RejectedBeforeEffect(
                    runne_provider::ProviderPreEffectRejection::AdapterRejected,
                )
            })?;
            let mut response = self
                .client
                .post(url)
                .headers(headers)
                .body(body)
                .send()
                .await
                .map_err(|_| DispatchError::MaybeDispatched)?;
            let url = response.url().to_string();
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let mut bytes = Vec::new();
            let mut chunks = 0usize;
            loop {
                let next = tokio::time::timeout(self.idle_timeout, response.chunk())
                    .await
                    .map_err(|_| DispatchError::MaybeDispatched)?
                    .map_err(|_| DispatchError::MaybeDispatched)?;
                let Some(chunk) = next else { break };
                chunks = chunks
                    .checked_add(1)
                    .filter(|n| *n <= MAX_CHUNKS)
                    .ok_or(DispatchError::MaybeDispatched)?;
                append_bounded(&mut bytes, &chunk)?;
            }
            if bytes.is_empty() {
                return Err(DispatchError::MaybeDispatched);
            }
            Ok(TransportResponse {
                url,
                status,
                content_type,
                body: bytes,
            })
        })
    }
}

fn append_bounded(bytes: &mut Vec<u8>, chunk: &[u8]) -> Result<(), DispatchError> {
    let new_len = bytes
        .len()
        .checked_add(chunk.len())
        .filter(|length| *length <= MAX_BODY)
        .ok_or(DispatchError::MaybeDispatched)?;
    bytes.reserve(chunk.len());
    bytes.extend_from_slice(chunk);
    debug_assert_eq!(bytes.len(), new_len);
    Ok(())
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "the parent effect module validates the response media type"
)]
pub(crate) fn valid_sse_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media| media.trim().eq_ignore_ascii_case("text/event-stream"))
}

#[cfg(test)]
mod tests {
    use super::{MAX_BODY, append_bounded, valid_sse_content_type};
    use runne_provider::DispatchError;

    #[test]
    fn content_type_requires_exact_sse_media_type() {
        assert!(valid_sse_content_type("text/event-stream; charset=utf-8"));
        assert!(!valid_sse_content_type("text/event-stream-evil"));
        assert!(!valid_sse_content_type("application/json"));
    }

    #[test]
    fn body_limit_is_checked_before_append() {
        let mut bytes = vec![0; MAX_BODY - 1];
        assert!(append_bounded(&mut bytes, &[1]).is_ok());
        assert_eq!(
            append_bounded(&mut bytes, &[2]),
            Err(DispatchError::MaybeDispatched)
        );
        assert_eq!(bytes.len(), MAX_BODY);
    }
}
