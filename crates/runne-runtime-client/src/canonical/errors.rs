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
    ProhibitedInputRejected,
    /// A trust decision may have committed, but its response was lost.
    UnknownAfterSend,
    ManagedPolicy,
    RootUnavailable,
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
            RuntimeApiErrorKind::ProhibitedInputRejected => "runtime rejected prohibited input",
            RuntimeApiErrorKind::UnknownAfterSend => "trust decision outcome is unknown; refresh state",
            RuntimeApiErrorKind::ManagedPolicy => "managed trust policy cannot be changed by the user",
            RuntimeApiErrorKind::RootUnavailable => "current workspace root is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for RuntimeApiError {}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn report_http_diagnostic(
    component: &'static str,
    phase: &'static str,
    status: Option<u16>,
    kind: &'static str,
) {
    match status {
        Some(status) => eprintln!(
            "runne-http-diagnostic component={component} phase={phase} kind={kind} status={status}"
        ),
        None => eprintln!(
            "runne-http-diagnostic component={component} phase={phase} kind={kind} status=none"
        ),
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) const fn diagnostic_error_kind(error: &RuntimeApiError) -> &'static str {
    match error.kind() {
        RuntimeApiErrorKind::InvalidRequest => "invalid_request",
        RuntimeApiErrorKind::Unauthorized => "unauthorized",
        RuntimeApiErrorKind::NotFound => "not_found",
        RuntimeApiErrorKind::Conflict => "conflict",
        RuntimeApiErrorKind::Backpressure => "backpressure",
        RuntimeApiErrorKind::Unavailable => "unavailable",
        RuntimeApiErrorKind::ResponseTooLarge => "response_too_large",
        RuntimeApiErrorKind::InvalidResponse => "invalid_response",
        RuntimeApiErrorKind::Incompatible => "incompatible",
        RuntimeApiErrorKind::ProhibitedInputRejected => "prohibited_input_rejected",
        RuntimeApiErrorKind::UnknownAfterSend => "unknown_after_send",
        RuntimeApiErrorKind::ManagedPolicy => "managed_policy",
        RuntimeApiErrorKind::RootUnavailable => "root_unavailable",
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn report_api_error(
    component: &'static str,
    phase: &'static str,
    status: Option<u16>,
    error: &RuntimeApiError,
) {
    report_http_diagnostic(component, phase, status, diagnostic_error_kind(error));
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) async fn diagnostic_json<T>(
    request: reqwest::RequestBuilder,
    component: &'static str,
    expected_statuses: &[u16],
) -> Result<T, RuntimeApiError>
where
    T: serde::de::DeserializeOwned,
{
    let response = request.send().await.map_err(|_| {
        report_http_diagnostic(component, "transport", None, "unavailable");
        RuntimeApiError::new(RuntimeApiErrorKind::Unavailable)
    })?;
    let status = response.status().as_u16();
    read_success_json(response, expected_statuses)
        .await
        .inspect_err(|error| {
            report_http_diagnostic(
                component,
                "response",
                Some(status),
                diagnostic_error_kind(error),
            );
        })
}
