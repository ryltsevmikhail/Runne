use core::fmt;
use std::time::Duration;

use gocode_provider::ProviderFuture;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use thiserror::Error;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::OpenAiResponsesTextProfile;

const METHOD: &str = "POST";
const SSE_CONTENT_TYPE: &str = "text/event-stream";
const JSON_CONTENT_TYPE: &str = "application/json";
const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-client-request-id");
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_mins(3);
/// Maximum raw bytes accepted for one SSE event.
pub const OPENAI_MAX_SSE_FRAME_BYTES: usize = 65_536;
/// Maximum decoded bytes accepted across one response stream.
pub const OPENAI_MAX_DECODED_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Maximum SSE events accepted across one response stream.
pub const OPENAI_MAX_SSE_EVENTS: usize = 16_384;
/// Maximum physical SSE lines accepted across one response stream.
pub const OPENAI_MAX_SSE_LINES: usize = OPENAI_MAX_SSE_EVENTS * 4;
/// Maximum response body fragments accepted from a transport implementation.
pub const OPENAI_MAX_TRANSPORT_CHUNKS: usize = 65_536;
/// Maximum normalized assistant text bytes.
pub const OPENAI_MAX_NORMALIZED_TEXT_BYTES: usize = 65_536;
const MAX_REMOTE_REJECTION_BYTES: usize = 65_536;

/// Immutable transport policy for the exact `OpenAI` Responses text profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiTransportPolicy {
    origin: String,
    path: String,
    connect_timeout: Duration,
    idle_timeout: Duration,
    total_timeout: Duration,
    max_transport_chunks: usize,
}

impl OpenAiTransportPolicy {
    /// Builds the only transport policy accepted by this adapter.
    ///
    /// # Errors
    ///
    /// Returns [`OpenAiTransportError::EndpointMismatch`] if the supplied
    /// profile is not the immutable HTTPS Responses profile.
    pub fn for_profile(profile: &OpenAiResponsesTextProfile) -> Result<Self, OpenAiTransportError> {
        if profile.origin() != "https://api.openai.com" || profile.path() != "/v1/responses" {
            return Err(OpenAiTransportError::EndpointMismatch);
        }
        Ok(Self {
            origin: profile.origin().to_owned(),
            path: profile.path().to_owned(),
            connect_timeout: CONNECT_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            total_timeout: TOTAL_TIMEOUT,
            max_transport_chunks: OPENAI_MAX_TRANSPORT_CHUNKS,
        })
    }

    /// Returns the exact HTTPS origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Returns the exact request path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the only allowed HTTP method.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        METHOD
    }

    /// Ambient/system proxy discovery is disabled.
    #[must_use]
    pub const fn uses_ambient_proxy(&self) -> bool {
        false
    }

    /// Redirect following is disabled.
    #[must_use]
    pub const fn follows_redirects(&self) -> bool {
        false
    }

    /// The transport never automatically retries an external effect.
    #[must_use]
    pub const fn automatically_retries(&self) -> bool {
        false
    }

    /// Returns the raw per-SSE-event byte bound.
    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        OPENAI_MAX_SSE_FRAME_BYTES
    }

    /// Returns the cumulative decoded response byte bound.
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> usize {
        OPENAI_MAX_DECODED_STREAM_BYTES
    }

    /// Returns the maximum accepted SSE event count.
    #[must_use]
    pub const fn max_events(&self) -> usize {
        OPENAI_MAX_SSE_EVENTS
    }

    /// Returns the maximum physical SSE line count.
    #[must_use]
    pub const fn max_lines(&self) -> usize {
        OPENAI_MAX_SSE_LINES
    }

    /// Returns the maximum transport response fragment count.
    #[must_use]
    pub const fn max_transport_chunks(&self) -> usize {
        self.max_transport_chunks
    }

    /// Returns the normalized assistant text byte bound.
    #[must_use]
    pub const fn max_text_bytes(&self) -> usize {
        OPENAI_MAX_NORMALIZED_TEXT_BYTES
    }

    /// Returns the bounded TCP/TLS connection deadline.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Returns the deadline between response body chunks.
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Returns the full request/response deadline.
    #[must_use]
    pub const fn total_timeout(&self) -> Duration {
        self.total_timeout
    }

    fn url(&self) -> String {
        format!("{}{}", self.origin, self.path)
    }
}

/// One exact admitted transport request.
///
/// `Debug` intentionally exposes only bounded lengths and non-secret routing
/// metadata.
pub struct OpenAiTransportRequest {
    origin: String,
    path: String,
    request_id: String,
    body: Zeroizing<Vec<u8>>,
    credential: Zeroizing<Vec<u8>>,
}

impl OpenAiTransportRequest {
    pub(crate) fn new(
        policy: &OpenAiTransportPolicy,
        request_id: String,
        body: Vec<u8>,
        credential: Zeroizing<Vec<u8>>,
    ) -> Result<Self, OpenAiTransportError> {
        if request_id.is_empty()
            || request_id.len() > 256
            || request_id.bytes().any(|byte| byte.is_ascii_control())
            || body.is_empty()
            || credential.is_empty()
        {
            return Err(OpenAiTransportError::RequestRejected);
        }
        Ok(Self {
            origin: policy.origin.clone(),
            path: policy.path.clone(),
            request_id,
            body: Zeroizing::new(body),
            credential,
        })
    }

    /// Returns the exact HTTPS origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Returns the exact request path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the stable non-secret local attempt correlation.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the exact credential-free request body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns short-lived credential bytes to the admitted transport only.
    #[must_use]
    pub fn credential(&self) -> &[u8] {
        &self.credential
    }
}

impl fmt::Debug for OpenAiTransportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiTransportRequest")
            .field("origin", &self.origin)
            .field("path", &self.path)
            .field("request_id_len", &self.request_id.len())
            .field("body_len", &self.body.len())
            .field("credential", &"<redacted>")
            .finish()
    }
}

/// Bounded response body chunks with no raw-data diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenAiTransportResponse {
    status: u16,
    content_type: &'static str,
    chunks: Vec<Vec<u8>>,
}

impl OpenAiTransportResponse {
    /// Constructs a successful `text/event-stream` fixture/transport result.
    ///
    /// # Errors
    ///
    /// Rejects empty, over-fragmented or oversized response bodies and
    /// coalesces accepted fragments into one bounded buffer.
    pub fn sse(chunks: Vec<Vec<u8>>) -> Result<Self, OpenAiTransportError> {
        if chunks.is_empty() {
            return Err(OpenAiTransportError::StreamLimitExceeded);
        }
        let mut body =
            BoundedBodyBuffer::new(OPENAI_MAX_TRANSPORT_CHUNKS, OPENAI_MAX_DECODED_STREAM_BYTES);
        for chunk in chunks {
            body.push(&chunk)?;
        }
        let body = body.finish()?;
        Ok(Self {
            status: 200,
            content_type: SSE_CONTENT_TYPE,
            chunks: vec![body],
        })
    }

    /// Constructs one bounded non-success JSON response.
    ///
    /// # Errors
    ///
    /// Rejects success status, empty/malformed JSON and oversized bodies.
    pub fn json_rejection(status: u16, body: Vec<u8>) -> Result<Self, OpenAiTransportError> {
        if (200..300).contains(&status)
            || body.is_empty()
            || body.len() > MAX_REMOTE_REJECTION_BYTES
            || serde_json::from_slice::<serde_json::Value>(&body).is_err()
        {
            return Err(OpenAiTransportError::ResponseRejected);
        }
        Ok(Self {
            status,
            content_type: JSON_CONTENT_TYPE,
            chunks: vec![body],
        })
    }

    /// Returns the HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the validated media type.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        self.content_type
    }

    /// Returns bounded raw chunks for the SSE decoder.
    #[must_use]
    pub fn chunks(&self) -> &[Vec<u8>] {
        &self.chunks
    }
}

#[derive(Debug)]
struct BoundedBodyBuffer {
    body: Vec<u8>,
    chunk_count: usize,
    max_chunks: usize,
    max_bytes: usize,
}

impl BoundedBodyBuffer {
    const fn new(max_chunks: usize, max_bytes: usize) -> Self {
        Self {
            body: Vec::new(),
            chunk_count: 0,
            max_chunks,
            max_bytes,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<(), OpenAiTransportError> {
        let next_count = self
            .chunk_count
            .checked_add(1)
            .filter(|count| *count <= self.max_chunks)
            .ok_or(OpenAiTransportError::StreamLimitExceeded)?;
        let next_bytes = self
            .body
            .len()
            .checked_add(chunk.len())
            .filter(|bytes| *bytes <= self.max_bytes)
            .ok_or(OpenAiTransportError::StreamLimitExceeded)?;
        self.body
            .try_reserve(next_bytes - self.body.len())
            .map_err(|_| OpenAiTransportError::StreamLimitExceeded)?;
        self.body.extend_from_slice(chunk);
        self.chunk_count = next_count;
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, OpenAiTransportError> {
        if self.body.is_empty() {
            return Err(OpenAiTransportError::ResponseRejected);
        }
        Ok(self.body)
    }
}

impl fmt::Debug for OpenAiTransportResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiTransportResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("chunk_count", &self.chunks.len())
            .field(
                "decoded_len",
                &self.chunks.iter().map(Vec::len).sum::<usize>(),
            )
            .finish()
    }
}

/// Sanitized transport failure without request, response or credential data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenAiTransportError {
    /// Network transport is unavailable.
    #[error("OpenAI transport is unavailable")]
    Unavailable,
    /// A bounded connection, idle or total deadline elapsed.
    #[error("OpenAI transport deadline elapsed")]
    Timeout,
    /// TLS setup or certificate verification failed.
    #[error("OpenAI TLS verification failed")]
    TlsFailure,
    /// Request or response endpoint differed from the exact profile.
    #[error("OpenAI endpoint does not match the exact profile")]
    EndpointMismatch,
    /// Local request metadata failed before network start.
    #[error("OpenAI transport request was rejected")]
    RequestRejected,
    /// HTTP response status/media type/body was not an allowed branch.
    #[error("OpenAI response was rejected")]
    ResponseRejected,
    /// Response/frame/event/text bounds were exceeded.
    #[error("OpenAI response exceeded a transport bound")]
    StreamLimitExceeded,
}

/// Async exact transport boundary used by the provider adapter.
pub trait OpenAiTransport: Send + Sync {
    /// Starts one already admitted request. Any returned error is
    /// conservatively treated as maybe-dispatched by the adapter.
    fn send(
        &self,
        request: OpenAiTransportRequest,
    ) -> ProviderFuture<'_, Result<OpenAiTransportResponse, OpenAiTransportError>>;
}

/// Production reqwest/rustls transport with no proxy, redirect or retry.
#[derive(Debug, Clone)]
pub struct OpenAiHttpTransport {
    policy: OpenAiTransportPolicy,
    client: reqwest::Client,
}

impl OpenAiHttpTransport {
    /// Builds a reqwest client pinned to rustls and the exact transport policy.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when the client cannot be constructed.
    pub fn new(policy: OpenAiTransportPolicy) -> Result<Self, OpenAiTransportError> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(policy.connect_timeout())
            .timeout(policy.total_timeout())
            .build()
            .map_err(|_| OpenAiTransportError::Unavailable)?;
        Ok(Self { policy, client })
    }

    async fn send_inner(
        &self,
        request: OpenAiTransportRequest,
    ) -> Result<OpenAiTransportResponse, OpenAiTransportError> {
        if request.origin != self.policy.origin || request.path != self.policy.path {
            return Err(OpenAiTransportError::EndpointMismatch);
        }
        let request_url = self.policy.url();
        let headers = build_headers(&request)?;
        let operation = async {
            let mut response = self
                .client
                .post(request_url)
                .headers(headers)
                .body(request.body.to_vec())
                .send()
                .await
                .map_err(|error| map_reqwest_error(&error))?;
            if response.url().scheme() != "https"
                || response.url().origin().ascii_serialization() != self.policy.origin
                || response.url().path() != self.policy.path
                || response.url().query().is_some()
                || response.url().fragment().is_some()
            {
                return Err(OpenAiTransportError::EndpointMismatch);
            }
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .and_then(normalize_content_type)
                .ok_or(OpenAiTransportError::ResponseRejected)?;
            if status == 200 && content_type != SSE_CONTENT_TYPE {
                return Err(OpenAiTransportError::ResponseRejected);
            }
            if (201..300).contains(&status) {
                return Err(OpenAiTransportError::ResponseRejected);
            }
            if !(200..300).contains(&status) && content_type != JSON_CONTENT_TYPE {
                return Err(OpenAiTransportError::ResponseRejected);
            }
            let maximum = if (200..300).contains(&status) {
                OPENAI_MAX_DECODED_STREAM_BYTES
            } else {
                MAX_REMOTE_REJECTION_BYTES
            };
            let mut body = BoundedBodyBuffer::new(self.policy.max_transport_chunks(), maximum);
            loop {
                let chunk = timeout(self.policy.idle_timeout(), response.chunk())
                    .await
                    .map_err(|_| OpenAiTransportError::Timeout)?
                    .map_err(|error| map_reqwest_error(&error))?;
                let Some(chunk) = chunk else {
                    break;
                };
                body.push(&chunk)?;
            }
            let body = body.finish()?;
            if !(200..300).contains(&status) {
                return OpenAiTransportResponse::json_rejection(status, body);
            }
            OpenAiTransportResponse::sse(vec![body])
        };
        timeout(self.policy.total_timeout(), operation)
            .await
            .map_err(|_| OpenAiTransportError::Timeout)?
    }
}

fn build_headers(request: &OpenAiTransportRequest) -> Result<HeaderMap, OpenAiTransportError> {
    let mut authorization = Zeroizing::new(Vec::with_capacity(
        "Bearer ".len() + request.credential.len(),
    ));
    authorization.extend_from_slice(b"Bearer ");
    authorization.extend_from_slice(&request.credential);
    let mut authorization_header = HeaderValue::from_bytes(&authorization)
        .map_err(|_| OpenAiTransportError::RequestRejected)?;
    authorization_header.set_sensitive(true);
    let mut request_id_header = HeaderValue::from_str(&request.request_id)
        .map_err(|_| OpenAiTransportError::RequestRejected)?;
    request_id_header.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, authorization_header);
    headers.insert(REQUEST_ID_HEADER, request_id_header);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
    headers.insert(ACCEPT, HeaderValue::from_static(SSE_CONTENT_TYPE));
    Ok(headers)
}

impl OpenAiTransport for OpenAiHttpTransport {
    fn send(
        &self,
        request: OpenAiTransportRequest,
    ) -> ProviderFuture<'_, Result<OpenAiTransportResponse, OpenAiTransportError>> {
        Box::pin(async move { self.send_inner(request).await })
    }
}

fn normalize_content_type(value: &str) -> Option<&'static str> {
    let media_type = value
        .split(';')
        .next()
        .map(str::trim)
        .map(str::to_ascii_lowercase)?;
    match media_type.as_str() {
        SSE_CONTENT_TYPE => Some(SSE_CONTENT_TYPE),
        JSON_CONTENT_TYPE => Some(JSON_CONTENT_TYPE),
        _ => None,
    }
}

fn map_reqwest_error(error: &reqwest::Error) -> OpenAiTransportError {
    if error.is_timeout() {
        OpenAiTransportError::Timeout
    } else if error.is_connect() {
        OpenAiTransportError::TlsFailure
    } else {
        OpenAiTransportError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::process::Command;
    use std::sync::Arc;

    use gocode_provider::ProviderFuture;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;
    use zeroize::Zeroizing;

    use super::*;

    const TERMINAL_SSE: &[u8] = b"event: error\ndata: {\"type\":\"error\",\"code\":\"server_error\",\"message\":\"redacted\",\"param\":null,\"sequence_number\":0}\n\n";
    const REJECTION_JSON: &[u8] = br#"{"error":{"message":"redacted","type":"rate_limit_error"}}"#;
    const PROXY_CHILD_MARKER: &str = "GOCODE_OPENAI_PROXY_TEST_CHILD";

    #[tokio::test]
    async fn local_tls_peer_observes_exact_method_path_headers_and_body() {
        let (certificate, server_config) = tls_identity("api.openai.com");
        let (address, request_rx) = spawn_server(
            server_config,
            200,
            SSE_CONTENT_TYPE,
            TERMINAL_SSE,
            None,
            Duration::ZERO,
        )
        .await;
        let transport = test_transport(address, &certificate);
        let request = transport_request();

        let response = transport.send(request).await.expect("TLS response");
        assert_eq!(response.status(), 200);
        let request = String::from_utf8(request_rx.await.expect("captured request"))
            .expect("HTTP request UTF-8");
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with("POST /v1/responses HTTP/1.1\r\n"));
        assert!(lower.contains("\r\nhost: api.openai.com\r\n"));
        assert!(lower.contains("\r\nx-client-request-id: gocode-attempt-local-tls\r\n"));
        assert!(lower.contains("\r\nauthorization: bearer fixture-credential-never-print\r\n"));
        assert!(request.ends_with("{\"stream\":true}\n"));
    }

    #[tokio::test]
    async fn redirect_is_returned_as_bounded_rejection_and_never_followed() {
        let (certificate, server_config) = tls_identity("api.openai.com");
        let (address, request_rx) = spawn_server(
            server_config,
            307,
            JSON_CONTENT_TYPE,
            REJECTION_JSON,
            Some("https://redirect.invalid/v1/responses"),
            Duration::ZERO,
        )
        .await;
        let transport = test_transport(address, &certificate);

        let response = transport
            .send(transport_request())
            .await
            .expect("bounded redirect response");
        assert_eq!(response.status(), 307);
        request_rx.await.expect("one exact request");
    }

    #[tokio::test]
    async fn counterfeit_tls_certificate_fails_before_http_bytes() {
        let (trusted_certificate, _) = tls_identity("api.openai.com");
        let (_, counterfeit_config) = tls_identity("api.openai.com");
        let (address, request_rx) = spawn_server(
            counterfeit_config,
            200,
            SSE_CONTENT_TYPE,
            TERMINAL_SSE,
            None,
            Duration::ZERO,
        )
        .await;
        let transport = test_transport(address, &trusted_certificate);

        assert_eq!(
            transport.send(transport_request()).await,
            Err(OpenAiTransportError::TlsFailure)
        );
        assert!(request_rx.await.expect("captured request").is_empty());
    }

    #[test]
    fn authorization_and_request_id_headers_are_sensitive() {
        let request = transport_request();
        let headers = build_headers(&request).expect("headers");
        assert!(
            headers
                .get(AUTHORIZATION)
                .expect("authorization")
                .is_sensitive()
        );
        assert!(
            headers
                .get(&REQUEST_ID_HEADER)
                .expect("request id")
                .is_sensitive()
        );
    }

    #[tokio::test]
    async fn response_body_idle_deadline_fails_closed() {
        let (certificate, server_config) = tls_identity("api.openai.com");
        let (address, request_rx) = spawn_server(
            server_config,
            200,
            SSE_CONTENT_TYPE,
            TERMINAL_SSE,
            None,
            Duration::from_millis(100),
        )
        .await;
        let mut transport = test_transport(address, &certificate);
        transport.policy.idle_timeout = Duration::from_millis(10);
        transport.policy.total_timeout = Duration::from_secs(1);

        assert_eq!(
            transport.send(transport_request()).await,
            Err(OpenAiTransportError::Timeout)
        );
        request_rx.await.expect("captured request");
    }

    #[test]
    fn ambient_proxy_environment_is_ignored() {
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "transport::tests::ambient_proxy_environment_is_ignored_child",
            ])
            .env(PROXY_CHILD_MARKER, "1")
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env("http_proxy", "http://127.0.0.1:9")
            .env("https_proxy", "http://127.0.0.1:9")
            .env("all_proxy", "http://127.0.0.1:9")
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .output()
            .expect("spawn proxy-isolation child");
        assert!(output.status.success(), "proxy-isolation child failed");
    }

    #[test]
    fn ambient_proxy_environment_is_ignored_child() {
        if std::env::var_os(PROXY_CHILD_MARKER).is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let (certificate, server_config) = tls_identity("api.openai.com");
            let (address, request_rx) = spawn_server(
                server_config,
                200,
                SSE_CONTENT_TYPE,
                TERMINAL_SSE,
                None,
                Duration::ZERO,
            )
            .await;
            let transport = test_transport(address, &certificate);
            assert_eq!(
                transport
                    .send(transport_request())
                    .await
                    .expect("direct request")
                    .status(),
                200
            );
            request_rx.await.expect("captured direct request");
        });
    }

    #[tokio::test]
    async fn total_response_deadline_fails_closed() {
        let (certificate, server_config) = tls_identity("api.openai.com");
        let (address, request_rx) = spawn_server(
            server_config,
            200,
            SSE_CONTENT_TYPE,
            TERMINAL_SSE,
            None,
            Duration::from_millis(100),
        )
        .await;
        let mut transport = test_transport(address, &certificate);
        transport.policy.idle_timeout = Duration::from_secs(1);
        transport.policy.total_timeout = Duration::from_millis(10);

        assert_eq!(
            transport.send(transport_request()).await,
            Err(OpenAiTransportError::Timeout)
        );
        request_rx.await.expect("captured request");
    }

    #[tokio::test]
    async fn many_http_body_frames_are_coalesced_into_one_bounded_buffer() {
        let (certificate, server_config) = tls_identity("api.openai.com");
        let (address, request_rx) = spawn_chunked_server(server_config, TERMINAL_SSE).await;
        let mut transport = test_transport(address, &certificate);
        transport.policy.max_transport_chunks = TERMINAL_SSE.len();

        let response = transport
            .send(transport_request())
            .await
            .expect("fragmented response");
        assert_eq!(response.chunks().len(), 1);
        assert_eq!(response.chunks()[0], TERMINAL_SSE);
        request_rx.await.expect("captured request");
    }

    #[tokio::test]
    async fn http_body_frame_after_exact_callback_limit_fails_closed() {
        let (certificate, server_config) = tls_identity("api.openai.com");
        let (address, request_rx) = spawn_chunked_server(server_config, TERMINAL_SSE).await;
        let mut transport = test_transport(address, &certificate);
        transport.policy.max_transport_chunks = TERMINAL_SSE.len() - 1;

        assert_eq!(
            transport.send(transport_request()).await,
            Err(OpenAiTransportError::StreamLimitExceeded)
        );
        request_rx.await.expect("captured request");
    }

    #[test]
    fn empty_body_callbacks_count_toward_the_same_production_limit() {
        let mut body = BoundedBodyBuffer::new(2, 8);
        body.push(&[]).expect("first empty callback");
        body.push(&[]).expect("exact callback limit");
        assert_eq!(
            body.push(&[]),
            Err(OpenAiTransportError::StreamLimitExceeded)
        );
        assert!(body.finish().is_err(), "empty body must remain invalid");
    }

    fn transport_request() -> OpenAiTransportRequest {
        OpenAiTransportRequest::new(
            &test_policy(),
            "gocode-attempt-local-tls".to_owned(),
            b"{\"stream\":true}\n".to_vec(),
            Zeroizing::new(b"fixture-credential-never-print".to_vec()),
        )
        .expect("transport request")
    }

    fn test_policy() -> OpenAiTransportPolicy {
        OpenAiTransportPolicy {
            origin: "https://api.openai.com".to_owned(),
            path: "/v1/responses".to_owned(),
            connect_timeout: CONNECT_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            total_timeout: TOTAL_TIMEOUT,
            max_transport_chunks: OPENAI_MAX_TRANSPORT_CHUNKS,
        }
    }

    fn test_transport(address: SocketAddr, certificate: &[u8]) -> OpenAiHttpTransport {
        let policy = test_policy();
        let certificate =
            reqwest::Certificate::from_der(certificate).expect("test root certificate");
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(certificate)
            .https_only(true)
            .no_proxy()
            .redirect(Policy::none())
            .resolve("api.openai.com", address)
            .http1_only()
            .connect_timeout(policy.connect_timeout())
            .timeout(policy.total_timeout())
            .build()
            .expect("test client");
        OpenAiHttpTransport { policy, client }
    }

    async fn spawn_server(
        config: Arc<rustls::ServerConfig>,
        status: u16,
        content_type: &'static str,
        body: &'static [u8],
        location: Option<&'static str>,
        body_delay: Duration,
    ) -> (SocketAddr, oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let (request_tx, request_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let Ok(mut stream) = TlsAcceptor::from(config).accept(stream).await else {
                let _ = request_tx.send(Vec::new());
                return;
            };
            let request = read_http_request(&mut stream).await;
            let _ = request_tx.send(request);
            let reason = if status == 200 {
                "OK"
            } else {
                "Temporary Redirect"
            };
            let location = location
                .map(|value| format!("Location: {value}\r\n"))
                .unwrap_or_default();
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("response headers");
            if !body_delay.is_zero() {
                tokio::time::sleep(body_delay).await;
            }
            let _ = stream.write_all(body).await;
            let _ = stream.shutdown().await;
        });
        (address, request_rx)
    }

    async fn spawn_chunked_server(
        config: Arc<rustls::ServerConfig>,
        body: &'static [u8],
    ) -> (SocketAddr, oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let (request_tx, request_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let mut stream = TlsAcceptor::from(config)
                .accept(stream)
                .await
                .expect("TLS accept");
            let request = read_http_request(&mut stream).await;
            let _ = request_tx.send(request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("response headers");
            for byte in body {
                stream.write_all(b"1\r\n").await.expect("chunk size");
                stream.write_all(&[*byte]).await.expect("chunk byte");
                stream.write_all(b"\r\n").await.expect("chunk terminator");
                tokio::task::yield_now().await;
            }
            stream.write_all(b"0\r\n\r\n").await.expect("final chunk");
            let _ = stream.shutdown().await;
        });
        (address, request_rx)
    }

    async fn read_http_request<T>(stream: &mut T) -> Vec<u8>
    where
        T: AsyncReadExt + Unpin,
    {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.expect("request read");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            let Some(headers_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
            else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            if request.len() >= headers_end + content_length {
                break;
            }
        }
        request
    }

    fn tls_identity(dns_name: &str) -> (Vec<u8>, Arc<rustls::ServerConfig>) {
        let mut parameters = CertificateParams::new(Vec::new()).expect("certificate parameters");
        parameters.subject_alt_names =
            vec![SanType::DnsName(dns_name.try_into().expect("DNS name"))];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let certificate = parameters.self_signed(&key).expect("certificate");
        let certificate_der = certificate.der().to_vec();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("server config");
        (certificate_der, Arc::new(config))
    }

    impl OpenAiTransport for &OpenAiHttpTransport {
        fn send(
            &self,
            request: OpenAiTransportRequest,
        ) -> ProviderFuture<'_, Result<OpenAiTransportResponse, OpenAiTransportError>> {
            Box::pin(async move { self.send_inner(request).await })
        }
    }
}
