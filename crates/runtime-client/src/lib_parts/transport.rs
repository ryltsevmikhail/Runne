/// Golden SHA-256 of the exact canonical `bundle.json` bytes.
pub const GOLDEN_BUNDLE_HASH: &str =
    "a3644c77c658c81baa4503d51c8a4207799bea1c9673674f1963defc6f4b8e90";

/// Bundle ID expected from the runtime.
pub const EXPECTED_BUNDLE_ID: &str = "gocode-ui-client/2";

/// Read-only provenance for the observed public `/health` response shape.
///
/// This is evidence for parsing only. It is intentionally distinct from
/// This provenance does not certify transport compatibility.
pub const HEALTH_CONTRACT_EVIDENCE_COMMIT: &str = "72009e0dd3956eebbacb218c4e73dd0918566de1";

const MAXIMUM_HEALTH_BYTES: usize = 4 * 1024;
const MAXIMUM_HEALTH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeEndpoint {
    address: SocketAddr,
}

impl RuntimeEndpoint {
    /// Creates a renderer-inaccessible loopback runtime endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for non-loopback addresses.
    pub const fn loopback(address: SocketAddr) -> Result<Self, RuntimeTransportError> {
        if !address.ip().is_loopback() {
            return Err(RuntimeTransportError::EndpointNotLoopback);
        }
        Ok(Self { address })
    }

    #[must_use]
    pub const fn address(self) -> SocketAddr {
        self.address
    }

    fn health_url(self) -> String {
        format!("http://{}/health", self.address)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeProfile {
    endpoint: RuntimeEndpoint,
}

impl RuntimeProfile {
    /// Validates the exact runtime profile and canonical schema identity.
    ///
    /// # Errors
    ///
    /// Returns an error when either identity differs from the accepted bundle.
    pub fn validate(
        endpoint: RuntimeEndpoint,
        profile_id: &str,
        schema_hash: &str,
    ) -> Result<Self, RuntimeProfileError> {
        if profile_id != EXPECTED_BUNDLE_ID {
            return Err(RuntimeProfileError::ProfileMismatch);
        }
        if schema_hash != GOLDEN_BUNDLE_HASH {
            return Err(RuntimeProfileError::SchemaHashMismatch);
        }
        Ok(Self { endpoint })
    }

    #[must_use]
    pub const fn endpoint(self) -> RuntimeEndpoint {
        self.endpoint
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RuntimeProfileError {
    #[error("runtime profile is incompatible")]
    ProfileMismatch,
    #[error("runtime schema hash is incompatible")]
    SchemaHashMismatch,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RuntimeTransportError {
    #[error("runtime endpoint is not loopback")]
    EndpointNotLoopback,
    #[error("runtime timeout is outside the allowed range")]
    InvalidTimeout,
    #[error("runtime is unavailable")]
    Unavailable,
    #[error("runtime peer identity does not match")]
    PeerIdentityMismatch,
    #[error("runtime response exceeds the allowed size")]
    ResponseTooLarge,
    #[error("runtime returned an unexpected HTTP status")]
    UnexpectedHttpStatus,
    #[error("runtime health response is invalid")]
    InvalidHealth,
}

#[derive(Clone)]
pub struct HttpRuntimeClient {
    client: reqwest::Client,
    endpoint: RuntimeEndpoint,
}

impl HttpRuntimeClient {
    /// Creates a bounded client for one Rust-owned loopback endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or excessive timeouts, or if a redirect-free
    /// HTTP client cannot be constructed.
    pub fn new(profile: RuntimeProfile, timeout: Duration) -> Result<Self, RuntimeTransportError> {
        if timeout.is_zero() || timeout > MAXIMUM_HEALTH_TIMEOUT {
            return Err(RuntimeTransportError::InvalidTimeout);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| RuntimeTransportError::Unavailable)?;
        Ok(Self {
            client,
            endpoint: profile.endpoint(),
        })
    }

    /// Reads and validates the public runtime health response.
    ///
    /// # Errors
    ///
    /// Returns a redacted typed error for transport failure, oversized bodies,
    /// redirects, unexpected status codes or malformed health payloads.
    pub async fn probe_health(&self) -> Result<RuntimeHealth, RuntimeTransportError> {
        let mut response = self
            .client
            .get(self.endpoint.health_url())
            .send()
            .await
            .map_err(|_| RuntimeTransportError::Unavailable)?;
        let status = response.status().as_u16();
        if !matches!(status, 200 | 503) {
            return Err(RuntimeTransportError::UnexpectedHttpStatus);
        }
        if response
            .content_length()
            .is_some_and(|length| length > u64::try_from(MAXIMUM_HEALTH_BYTES).unwrap_or(u64::MAX))
        {
            return Err(RuntimeTransportError::ResponseTooLarge);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| RuntimeTransportError::Unavailable)?
        {
            if body.len().saturating_add(chunk.len()) > MAXIMUM_HEALTH_BYTES {
                return Err(RuntimeTransportError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        RuntimeHealth::parse(status, &body).map_err(|_| RuntimeTransportError::InvalidHealth)
    }
}
