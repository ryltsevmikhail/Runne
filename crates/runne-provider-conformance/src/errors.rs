use std::fmt;

/// Public provider failure class emitted by the conformance classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailureKind {
    /// Authentication or authorization was rejected.
    Authentication,
    /// Provider throttled the request.
    RateLimited,
    /// A bounded timeout occurred.
    Timeout,
    /// Transport failed before a typed remote response.
    Transport,
    /// The selected model is unknown or unavailable.
    ModelUnavailable,
    /// The provider response could not be decoded safely.
    MalformedResponse,
    /// Local or remote cancellation was observed.
    Cancelled,
    /// No more specific public class is justified.
    Unknown,
}

/// Retry decision and optional provider-supplied delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryMetadata {
    retryable: bool,
    retry_after_seconds: Option<u64>,
}

impl RetryMetadata {
    /// Returns whether a retry is safe at this classification boundary.
    #[must_use]
    pub const fn retryable(self) -> bool {
        self.retryable
    }
    /// Returns bounded retry-after metadata, if supplied.
    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }
}

/// Typed provider failure that deliberately does not retain raw diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderFailure {
    kind: ProviderFailureKind,
    retry: RetryMetadata,
}

impl ProviderFailure {
    /// Returns the public failure class.
    #[must_use]
    pub const fn kind(self) -> ProviderFailureKind {
        self.kind
    }
    /// Returns retry semantics.
    #[must_use]
    pub const fn retry(self) -> RetryMetadata {
        self.retry
    }
}

impl fmt::Display for ProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            ProviderFailureKind::Authentication => "provider authentication failed",
            ProviderFailureKind::RateLimited => "provider rate limit reached",
            ProviderFailureKind::Timeout => "provider request timed out",
            ProviderFailureKind::Transport => "provider transport failed",
            ProviderFailureKind::ModelUnavailable => "provider model is unavailable",
            ProviderFailureKind::MalformedResponse => "provider response is malformed",
            ProviderFailureKind::Cancelled => "provider request was cancelled",
            ProviderFailureKind::Unknown => "provider failure is unknown",
        })
    }
}

/// Maps bounded provider status/code metadata into the public typed error set.
#[must_use]
pub fn classify_provider_failure(
    status: Option<u16>,
    provider_code: Option<&str>,
    retry_after_seconds: Option<u64>,
) -> ProviderFailure {
    let code = provider_code.map(str::to_ascii_lowercase);
    let code = code.as_deref().unwrap_or_default();
    let kind = if code.contains("auth") || code.contains("credential") {
        ProviderFailureKind::Authentication
    } else if code.contains("rate") || code.contains("thrott") {
        ProviderFailureKind::RateLimited
    } else if code.contains("timeout") {
        ProviderFailureKind::Timeout
    } else if code.contains("model")
        && (code.contains("unknown") || code.contains("unavailable") || code.contains("not_found"))
    {
        ProviderFailureKind::ModelUnavailable
    } else if code.contains("malformed") || code.contains("invalid_json") {
        ProviderFailureKind::MalformedResponse
    } else if code.contains("cancel") {
        ProviderFailureKind::Cancelled
    } else if code.contains("transport") || code.contains("unavailable") {
        ProviderFailureKind::Transport
    } else {
        match status {
            Some(401 | 403) => ProviderFailureKind::Authentication,
            Some(404) => ProviderFailureKind::ModelUnavailable,
            Some(408 | 504) => ProviderFailureKind::Timeout,
            Some(429) => ProviderFailureKind::RateLimited,
            Some(400 | 422) => ProviderFailureKind::MalformedResponse,
            Some(500..=599) => ProviderFailureKind::Transport,
            _ => ProviderFailureKind::Unknown,
        }
    };
    let retryable = matches!(
        kind,
        ProviderFailureKind::RateLimited
            | ProviderFailureKind::Timeout
            | ProviderFailureKind::Transport
    );
    ProviderFailure {
        kind,
        retry: RetryMetadata {
            retryable,
            retry_after_seconds: retry_after_seconds.filter(|_| retryable),
        },
    }
}
