use core::fmt;
use std::time::Duration;

use thiserror::Error;

use crate::DeepSeekResponsesTextProfile;

const METHOD: &str = "POST";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_mins(2);

/// Maximum raw bytes accepted for one SSE event.
pub const DEEPSEEK_MAX_SSE_FRAME_BYTES: usize = 65_536;
/// Maximum decoded bytes accepted across one response stream.
pub const DEEPSEEK_MAX_DECODED_STREAM_BYTES: usize = 8 * 1024 * 1024;
/// Maximum SSE events accepted across one response stream.
pub const DEEPSEEK_MAX_SSE_EVENTS: usize = 16_384;
/// Maximum physical SSE lines accepted across one response stream.
pub const DEEPSEEK_MAX_SSE_LINES: usize = DEEPSEEK_MAX_SSE_EVENTS * 4;
/// Maximum response body fragments accepted by the daemon-private sender.
pub const DEEPSEEK_MAX_TRANSPORT_CHUNKS: usize = 65_536;
/// Maximum normalized assistant text bytes.
pub const DEEPSEEK_MAX_NORMALIZED_TEXT_BYTES: usize = 65_536;

/// Credential-free immutable routing and bounds for the `DeepSeek` profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepSeekTransportPolicy {
    origin: String,
    path: String,
}

impl DeepSeekTransportPolicy {
    /// Validates the exact HTTPS Responses endpoint from the pinned profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the profile does not name the pinned endpoint.
    pub fn for_profile(
        profile: &DeepSeekResponsesTextProfile,
    ) -> Result<Self, DeepSeekTransportError> {
        if profile.origin() != "https://api.deepseek.com" || profile.path() != "/responses" {
            return Err(DeepSeekTransportError::EndpointMismatch);
        }
        Ok(Self {
            origin: profile.origin().to_owned(),
            path: profile.path().to_owned(),
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
        DEEPSEEK_MAX_SSE_FRAME_BYTES
    }
    /// Returns the cumulative decoded byte ceiling.
    #[must_use]
    pub const fn max_decoded_bytes(&self) -> usize {
        DEEPSEEK_MAX_DECODED_STREAM_BYTES
    }
    /// Returns the event count ceiling.
    #[must_use]
    pub const fn max_events(&self) -> usize {
        DEEPSEEK_MAX_SSE_EVENTS
    }
    /// Returns the line count ceiling.
    #[must_use]
    pub const fn max_lines(&self) -> usize {
        DEEPSEEK_MAX_SSE_LINES
    }
    /// Returns the response fragment ceiling.
    #[must_use]
    pub const fn max_transport_chunks(&self) -> usize {
        DEEPSEEK_MAX_TRANSPORT_CHUNKS
    }
    /// Returns the normalized output ceiling.
    #[must_use]
    pub const fn max_text_bytes(&self) -> usize {
        DEEPSEEK_MAX_NORMALIZED_TEXT_BYTES
    }
}

/// Bounded, credential-free response handed to the local SSE codec.
#[derive(Clone, PartialEq, Eq)]
pub struct DeepSeekTransportResponse {
    status: u16,
    content_type: &'static str,
    chunks: Vec<Vec<u8>>,
}

impl DeepSeekTransportResponse {
    /// Constructs a successful bounded SSE response.
    ///
    /// # Errors
    ///
    /// Returns an error when local size limits are exceeded.
    pub fn sse(chunks: Vec<Vec<u8>>) -> Result<Self, DeepSeekTransportError> {
        Self::new(200, "text/event-stream", chunks)
    }
    /// Constructs a bounded remote rejection response.
    ///
    /// # Errors
    ///
    /// Returns an error for successful statuses or exhausted local limits.
    pub fn json_rejection(status: u16, chunks: Vec<u8>) -> Result<Self, DeepSeekTransportError> {
        if (200..300).contains(&status) {
            return Err(DeepSeekTransportError::ResponseRejected);
        }
        Self::new(status, "application/json", vec![chunks])
    }
    fn new(
        status: u16,
        content_type: &'static str,
        chunks: Vec<Vec<u8>>,
    ) -> Result<Self, DeepSeekTransportError> {
        if chunks.is_empty()
            || chunks.len() > DEEPSEEK_MAX_TRANSPORT_CHUNKS
            || chunks
                .iter()
                .try_fold(0_usize, |total, chunk| total.checked_add(chunk.len()))
                .as_ref()
                .is_none_or(|total| *total > DEEPSEEK_MAX_DECODED_STREAM_BYTES)
        {
            return Err(DeepSeekTransportError::StreamLimitExceeded);
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

impl fmt::Debug for DeepSeekTransportResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeepSeekTransportResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("chunk_count", &self.chunks.len())
            .finish()
    }
}

/// Closed errors emitted by policy validation and the local response codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeepSeekTransportError {
    /// Profile routing differs from the exact HTTPS endpoint.
    #[error("DeepSeek endpoint differs from the pinned profile")]
    EndpointMismatch,
    /// A local request invariant was violated before network start.
    #[error("DeepSeek request was rejected")]
    RequestRejected,
    /// The received response violates the pinned media/status contract.
    #[error("DeepSeek response was rejected")]
    ResponseRejected,
    /// A local resource bound was exceeded.
    #[error("DeepSeek response exceeded a bound")]
    StreamLimitExceeded,
    /// A daemon-private sender reported a bounded timeout.
    #[error("DeepSeek transport timed out")]
    Timeout,
    /// A daemon-private sender failed before a response was available.
    #[error("DeepSeek transport unavailable")]
    Unavailable,
    /// A daemon-private TLS validation failure occurred.
    #[error("DeepSeek TLS validation failed")]
    TlsFailure,
}
