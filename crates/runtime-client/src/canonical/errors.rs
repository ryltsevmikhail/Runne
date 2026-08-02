/// Stable client failure disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeApiErrorKind {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Conflict,
    Backpressure,
    Unavailable,
    ResponseTooLarge,
    InvalidResponse,
    Incompatible,
}

/// Typed and redacted canonical client failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeApiError {
    kind: RuntimeApiErrorKind,
    request_id: Option<String>,
}

impl RuntimeApiError {
    pub(crate) const fn new(kind: RuntimeApiErrorKind) -> Self {
        Self {
            kind,
            request_id: None,
        }
    }

    /// Returns the stable failure disposition.
    #[must_use]
    pub const fn kind(&self) -> RuntimeApiErrorKind {
        self.kind
    }

    /// Returns the safe correlation identity supplied by the daemon.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

impl fmt::Display for RuntimeApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            RuntimeApiErrorKind::InvalidRequest => "runtime request is invalid",
            RuntimeApiErrorKind::Unauthorized => "runtime authentication failed",
            RuntimeApiErrorKind::NotFound => "runtime resource was not found",
            RuntimeApiErrorKind::Conflict => "runtime command conflicted",
            RuntimeApiErrorKind::Backpressure => "runtime is busy",
            RuntimeApiErrorKind::Unavailable => "runtime is unavailable",
            RuntimeApiErrorKind::ResponseTooLarge => "runtime response exceeds the allowed size",
            RuntimeApiErrorKind::InvalidResponse => "runtime response is invalid",
            RuntimeApiErrorKind::Incompatible => "runtime profile is incompatible",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RuntimeApiError {}
