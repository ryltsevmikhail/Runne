use std::{collections::VecDeque, fmt};

use crate::{ProviderFailure, WireRequest, classify_provider_failure};

/// One offline scripted transport action.
pub enum ScriptedOutcome {
    /// Returns bounded response bytes.
    Response(Vec<u8>),
    /// Returns an already typed failure.
    Failure(ProviderFailure),
    /// Simulates a bounded timeout.
    Timeout,
    /// Simulates a transport failure.
    Transport,
    /// Simulates cancellation before a response.
    Cancelled,
}

impl ScriptedOutcome {
    /// Creates a response action.
    #[must_use]
    pub const fn response(body: Vec<u8>) -> Self {
        Self::Response(body)
    }
    /// Creates a timeout action.
    #[must_use]
    pub const fn timeout() -> Self {
        Self::Timeout
    }
}

impl fmt::Debug for ScriptedOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response(body) => formatter
                .debug_struct("Response")
                .field("body_len", &body.len())
                .finish(),
            Self::Failure(failure) => formatter.debug_tuple("Failure").field(failure).finish(),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::Transport => formatter.write_str("Transport"),
            Self::Cancelled => formatter.write_str("Cancelled"),
        }
    }
}

/// Sanitized observation recorded by the scripted transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestObservation {
    method: String,
    origin: String,
    path: String,
    header_names: Vec<String>,
    body_len: usize,
}

impl RequestObservation {
    /// Returns the observed method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
    /// Returns the observed origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// Returns the observed path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Returns sanitized header names.
    #[must_use]
    pub fn header_names(&self) -> &[String] {
        &self.header_names
    }
    /// Returns the body length only.
    #[must_use]
    pub const fn body_len(&self) -> usize {
        self.body_len
    }
}

/// Idempotent local cancellation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationDisposition {
    /// First cancellation request.
    Requested,
    /// Repeated cancellation request.
    AlreadyRequested,
}

/// Deterministic queue-backed transport with no network implementation.
pub struct ScriptedTransport {
    outcomes: VecDeque<ScriptedOutcome>,
    observations: Vec<RequestObservation>,
    cancelled: bool,
}

impl ScriptedTransport {
    /// Creates a transport from a fixed action sequence.
    pub fn new(outcomes: impl IntoIterator<Item = ScriptedOutcome>) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
            observations: Vec::new(),
            cancelled: false,
        }
    }

    /// Consumes one action and records only non-secret request metadata.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when the next scripted action represents a
    /// timeout, transport failure, cancellation, or exhausted script.
    pub fn send(&mut self, request: &WireRequest) -> Result<Vec<u8>, ProviderFailure> {
        self.observations.push(RequestObservation {
            method: request.method().to_owned(),
            origin: request.origin().to_owned(),
            path: request.path().to_owned(),
            header_names: request
                .header_names()
                .into_iter()
                .map(ToOwned::to_owned)
                .collect(),
            body_len: request.body_len(),
        });
        match self.outcomes.pop_front() {
            Some(ScriptedOutcome::Response(body)) => Ok(body),
            Some(ScriptedOutcome::Failure(failure)) => Err(failure),
            Some(ScriptedOutcome::Timeout) => {
                Err(classify_provider_failure(None, Some("timeout"), None))
            }
            Some(ScriptedOutcome::Transport) => {
                Err(classify_provider_failure(None, Some("transport"), None))
            }
            Some(ScriptedOutcome::Cancelled) => {
                Err(classify_provider_failure(None, Some("cancelled"), None))
            }
            None => Err(classify_provider_failure(None, None, None)),
        }
    }

    /// Returns sanitized request observations.
    #[must_use]
    pub fn observations(&self) -> &[RequestObservation] {
        &self.observations
    }

    /// Records an idempotent local cancellation.
    pub const fn cancel(&mut self) -> CancellationDisposition {
        if self.cancelled {
            CancellationDisposition::AlreadyRequested
        } else {
            self.cancelled = true;
            CancellationDisposition::Requested
        }
    }
}
