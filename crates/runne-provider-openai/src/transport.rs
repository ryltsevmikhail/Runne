use core::fmt;
use std::time::Duration;

use thiserror::Error;

use runne_provider::RemoteResponseId;

use crate::OpenAiResponsesTextProfile;

const METHOD: &str = "POST";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_mins(2);

/// Maximum raw bytes accepted for one SSE event.
pub const OPENAI_MAX_SSE_FRAME_BYTES: usize = 65_536;
/// Maximum decoded bytes accepted across one response stream.
pub const OPENAI_MAX_DECODED_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Maximum SSE events accepted across one response stream.
pub const OPENAI_MAX_SSE_EVENTS: usize = 16_384;
/// Maximum physical SSE lines accepted across one response stream.
pub const OPENAI_MAX_SSE_LINES: usize = OPENAI_MAX_SSE_EVENTS * 4;
/// Maximum response body fragments accepted by the daemon-private sender.
pub const OPENAI_MAX_TRANSPORT_CHUNKS: usize = 65_536;
/// Maximum normalized assistant text bytes.
pub const OPENAI_MAX_NORMALIZED_TEXT_BYTES: usize = 65_536;

/// Credential-free immutable routing and bounds for the `OpenAI` profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiTransportPolicy {
    origin: String,
    path: String,
    background: bool,
}

impl OpenAiTransportPolicy {
    /// Validates the exact HTTPS Responses endpoint from the pinned profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile does not name the pinned endpoint.
    pub fn for_profile(profile: &OpenAiResponsesTextProfile) -> Result<Self, OpenAiTransportError> {
        if profile.origin() != "https://api.openai.com" || profile.path() != "/v1/responses" {
            return Err(OpenAiTransportError::EndpointMismatch);
        }
        Ok(Self {
            origin: profile.origin().to_owned(),
            path: profile.path().to_owned(),
            background: profile.is_background(),
        })
    }

    /// Returns the exact HTTPS origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// Returns the exact endpoint path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Builds the exact same-response status URL for the background profile.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-background profile or unsafe response ID.
    pub fn status_url(&self, id: &RemoteResponseId) -> Result<String, OpenAiTransportError> {
        self.response_control_url(id, false)
    }
    /// Builds the exact same-response cancellation URL for the background profile.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-background profile or unsafe response ID.
    pub fn cancellation_url(&self, id: &RemoteResponseId) -> Result<String, OpenAiTransportError> {
        self.response_control_url(id, true)
    }
    fn response_control_url(
        &self,
        id: &RemoteResponseId,
        cancel: bool,
    ) -> Result<String, OpenAiTransportError> {
        let value = id.as_str();
        let suffix = value
            .strip_prefix("resp_")
            .ok_or(OpenAiTransportError::RequestRejected)?;
        if !self.background
            || suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(OpenAiTransportError::RequestRejected);
        }
        let action = if cancel { "/cancel" } else { "" };
        Ok(format!("{}{}/{}{}", self.origin, self.path, value, action))
    }
    /// Returns the sole method allowed by the profile.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        METHOD
    }
    /// Ambient proxy discovery is forbidden.
    #[must_use]
    pub const fn uses_ambient_proxy(&self) -> bool {
        false
    }
    /// Redirect following is forbidden.
    #[must_use]
    pub const fn follows_redirects(&self) -> bool {
        false
    }
    /// Automatic effect retries are forbidden.
    #[must_use]
    pub const fn automatically_retries(&self) -> bool {
        false
    }
    /// Returns the TCP/TLS connection ceiling.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        CONNECT_TIMEOUT
    }
    /// Returns the response-idle ceiling.
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        IDLE_TIMEOUT
    }
    /// Returns the local policy ceiling; the daemon may only shorten it.
    #[must_use]
    pub const fn total_timeout(&self) -> Duration {
        TOTAL_TIMEOUT
    }
    /// Returns the raw per-event byte ceiling.
    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        OPENAI_MAX_SSE_FRAME_BYTES
    }
    /// Returns the cumulative decoded byte ceiling.
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> usize {
        OPENAI_MAX_DECODED_STREAM_BYTES
    }
    /// Returns the event count ceiling.
    #[must_use]
    pub const fn max_events(&self) -> usize {
        OPENAI_MAX_SSE_EVENTS
    }
    /// Returns the line count ceiling.
    #[must_use]
    pub const fn max_lines(&self) -> usize {
        OPENAI_MAX_SSE_LINES
    }
    /// Returns the response fragment ceiling.
    #[must_use]
    pub const fn max_transport_chunks(&self) -> usize {
        OPENAI_MAX_TRANSPORT_CHUNKS
    }
    /// Returns the normalized output ceiling.
    #[must_use]
    pub const fn max_text_bytes(&self) -> usize {
        OPENAI_MAX_NORMALIZED_TEXT_BYTES
    }
}

/// Bounded, credential-free response handed to the local SSE codec.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenAiTransportResponse {
    status: u16,
    content_type: &'static str,
    chunks: Vec<Vec<u8>>,
}

impl OpenAiTransportResponse {
    /// Constructs a successful bounded SSE response.
    ///
    /// # Errors
    ///
    /// Returns an error when local size limits are exceeded.
    pub fn sse(chunks: Vec<Vec<u8>>) -> Result<Self, OpenAiTransportError> {
        Self::new(200, "text/event-stream", chunks)
    }
    /// Constructs a bounded remote rejection response.
    ///
    /// # Errors
    ///
    /// Returns an error for successful statuses or exhausted local limits.
    pub fn json_rejection(status: u16, chunks: Vec<u8>) -> Result<Self, OpenAiTransportError> {
        if (200..300).contains(&status) {
            return Err(OpenAiTransportError::ResponseRejected);
        }
        Self::new(status, "application/json", vec![chunks])
    }
    fn new(
        status: u16,
        content_type: &'static str,
        chunks: Vec<Vec<u8>>,
    ) -> Result<Self, OpenAiTransportError> {
        if chunks.is_empty()
            || chunks.len() > OPENAI_MAX_TRANSPORT_CHUNKS
            || chunks
                .iter()
                .try_fold(0_usize, |total, chunk| total.checked_add(chunk.len()))
                .as_ref()
                .is_none_or(|total| *total > OPENAI_MAX_DECODED_STREAM_BYTES)
        {
            return Err(OpenAiTransportError::StreamLimitExceeded);
        }
        Ok(Self {
            status,
            content_type,
            chunks,
        })
    }
    /// Returns HTTP status captured by the daemon-private sender.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }
    /// Returns validated response media type.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        self.content_type
    }
    /// Returns bounded response chunks.
    #[must_use]
    pub fn chunks(&self) -> &[Vec<u8>] {
        &self.chunks
    }
}

impl fmt::Debug for OpenAiTransportResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiTransportResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("chunk_count", &self.chunks.len())
            .finish()
    }
}

/// Closed errors emitted by policy validation and the local response codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenAiTransportError {
    /// Profile routing differs from the exact HTTPS endpoint.
    #[error("OpenAI endpoint differs from the pinned profile")]
    EndpointMismatch,
    /// A local request invariant was violated before network start.
    #[error("OpenAI request was rejected")]
    RequestRejected,
    /// The received response violates the pinned media/status contract.
    #[error("OpenAI response was rejected")]
    ResponseRejected,
    /// A local resource bound was exceeded.
    #[error("OpenAI response exceeded a bound")]
    StreamLimitExceeded,
    /// A daemon-private sender reported a bounded timeout.
    #[error("OpenAI transport timed out")]
    Timeout,
    /// A daemon-private sender failed before a response was available.
    #[error("OpenAI transport unavailable")]
    Unavailable,
    /// A daemon-private TLS validation failure occurred.
    #[error("OpenAI TLS validation failed")]
    TlsFailure,
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod transport_tests;
