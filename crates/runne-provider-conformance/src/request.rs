use std::{collections::BTreeMap, fmt};

use thiserror::Error;

/// Credential-bearing wire request projection used only by offline tests.
#[derive(Clone, PartialEq, Eq)]
pub struct WireRequest {
    method: String,
    origin: String,
    path: String,
    headers: BTreeMap<String, Vec<u8>>,
    body: Vec<u8>,
}

impl WireRequest {
    /// Creates a bounded request projection; header values are never rendered.
    #[must_use]
    pub fn new(
        method: impl Into<String>,
        origin: impl Into<String>,
        path: impl Into<String>,
        headers: BTreeMap<String, Vec<u8>>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            method: method.into(),
            origin: origin.into(),
            path: path.into(),
            headers,
            body,
        }
    }

    /// Returns the HTTP method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
    /// Returns the endpoint origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// Returns the endpoint path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Returns header names without exposing their values.
    #[must_use]
    pub fn header_names(&self) -> Vec<&str> {
        self.headers.keys().map(String::as_str).collect()
    }
    /// Returns the serialized body length without exposing body bytes.
    #[must_use]
    pub const fn body_len(&self) -> usize {
        self.body.len()
    }
}

impl fmt::Debug for WireRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireRequest")
            .field("method", &self.method)
            .field("origin", &self.origin)
            .field("path", &self.path)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl fmt::Display for WireRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {}{} ({} headers, {} body bytes)",
            self.method,
            self.origin,
            self.path,
            self.headers.len(),
            self.body.len()
        )
    }
}

/// Expected endpoint and required header names for one adapter projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContract {
    method: String,
    origin: String,
    path: String,
    required_headers: Vec<String>,
}

impl RequestContract {
    /// Creates an endpoint contract.
    pub fn new(
        method: impl Into<String>,
        origin: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            origin: origin.into(),
            path: path.into(),
            required_headers: Vec::new(),
        }
    }

    /// Adds a case-insensitive required header name.
    #[must_use]
    pub fn require_header(mut self, name: impl AsRef<str>) -> Self {
        self.required_headers
            .push(name.as_ref().to_ascii_lowercase());
        self
    }

    /// Validates routing and header presence without exposing header values.
    ///
    /// # Errors
    ///
    /// Returns [`RequestContractError`] when the route or required header
    /// contract is not satisfied.
    pub fn validate(&self, request: &WireRequest) -> Result<(), RequestContractError> {
        if request.method != self.method
            || request.origin != self.origin
            || request.path != self.path
        {
            return Err(RequestContractError::EndpointMismatch);
        }
        for required in &self.required_headers {
            let Some((_, value)) = request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(required))
            else {
                return Err(RequestContractError::MissingHeader);
            };
            if value.is_empty() {
                return Err(RequestContractError::EmptyHeader);
            }
        }
        Ok(())
    }
}

/// Request contract failure that carries no endpoint body or header values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RequestContractError {
    /// Method, origin, or path differed from the contract.
    #[error("provider request endpoint contract mismatch")]
    EndpointMismatch,
    /// A required header name was absent.
    #[error("provider request required header is missing")]
    MissingHeader,
    /// A required header was present but empty.
    #[error("provider request required header is empty")]
    EmptyHeader,
}

/// Credential-marker check for a provider's serialized request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RedactionError {
    /// The marker was empty and cannot prove absence.
    #[error("credential marker is empty")]
    EmptyMarker,
    /// A secret marker was found in a diagnostic or body.
    #[error("credential marker escaped its protected boundary")]
    SecretLeak,
}

/// Proves that a body does not contain the test-only credential marker.
///
/// # Errors
///
/// Returns [`RedactionError`] when the marker is empty or appears in the body.
pub fn assert_credential_free(body: &[u8], marker: &[u8]) -> Result<(), RedactionError> {
    if marker.is_empty() {
        return Err(RedactionError::EmptyMarker);
    }
    if body.windows(marker.len()).any(|window| window == marker) {
        return Err(RedactionError::SecretLeak);
    }
    Ok(())
}

/// Proves that Debug/Display projections omit a test-only credential marker.
///
/// # Errors
///
/// Returns [`RedactionError`] when the marker is empty or appears in either
/// diagnostic string.
pub fn assert_redacted_diagnostics(
    marker: &[u8],
    debug: &str,
    display: &str,
) -> Result<(), RedactionError> {
    if marker.is_empty() {
        return Err(RedactionError::EmptyMarker);
    }
    let marker = String::from_utf8_lossy(marker);
    if debug.contains(marker.as_ref()) || display.contains(marker.as_ref()) {
        return Err(RedactionError::SecretLeak);
    }
    Ok(())
}
