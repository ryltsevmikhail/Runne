//! Runtime transport and schema bundle verification.
//!
//! The canonical schema bundle (`gocode-ui-client/1`) is generated
//! byte-for-byte by the runtime contract generator. This module verifies the
//! exact content-only bundle digest independently from release source evidence.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

mod canonical;
mod local_profile;
mod local_session;
mod replay;
mod sse;

pub use canonical::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, ConversationCreated,
    ConversationMessage, ConversationMessageRole, ConversationMessages, ConversationTextResult,
    CreateConversationRequest, GenerateTextRequest, REQUIRED_RUNTIME_CAPABILITIES, RuntimeApiError,
    RuntimeApiErrorKind, RuntimeSessionAuthority, RuntimeSessionInfo, RuntimeTransportKind,
};
pub use local_profile::{
    LocalProfileError, LocalRuntimeConnectError, LocalRuntimeProfile, default_local_profile_path,
};
pub use local_session::ProtectedBundledRuntimeProfile;
pub use replay::{
    CanonicalReplayEvent, CanonicalReplayPayload, ConversationReplayPayload, LiveDeliveryId,
    ReconnectDecision, ReconnectPolicy, ReconnectRuntime, ReplayAggregateKind, ReplayClientError,
    ReplayClientErrorKind, ReplayCursor, ReplayDelivery, ReplayDeliveryDisposition,
    ReplayIdentityTracker, ReplayLiveSession, ReplayPersistenceBinding, ReplayPersistenceHandoff,
    ReplayRecoveryDisposition, ReplayScope, ReplaySensitivity, ReplaySessionId, ReplayStreamEvent,
    ReplayTerminal, ReplayTerminalCode, TaskRunReplayPayload, replay_persistence_digest,
};
pub use sse::{MAXIMUM_SSE_FRAME_BYTES, SSE_SILENCE_TIMEOUT};

/// Constructs a loopback plaintext client for transport-bound integration
/// tests. This hook is unavailable in release builds.
///
/// # Errors
///
/// Returns an error unless `origin` is an exact loopback HTTP origin.
#[cfg(any(debug_assertions, feature = "test-support"))]
#[doc(hidden)]
pub fn mock_authenticated_runtime_client(
    origin: &str,
    session: RuntimeSessionInfo,
) -> Result<AuthenticatedRuntimeClient, RuntimeTransportError> {
    let (client, origin) = mock_loopback_transport(origin)?;
    Ok(AuthenticatedRuntimeClient::from_local_session(
        client,
        origin,
        RuntimeSessionAuthority::from_local_session([0x5a; 32]),
        session,
    ))
}

/// Constructs a loopback plaintext client marked as protected-bundled for
/// native-host orchestration tests. This hook is unavailable in release
/// builds.
///
/// # Errors
///
/// Returns an error unless `origin` is an exact loopback HTTP origin.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn mock_protected_authenticated_runtime_client(
    origin: &str,
    session: RuntimeSessionInfo,
) -> Result<AuthenticatedRuntimeClient, RuntimeTransportError> {
    let (client, origin) = mock_loopback_transport(origin)?;
    Ok(AuthenticatedRuntimeClient::from_protected_bundled_session(
        client,
        origin,
        RuntimeSessionAuthority::from_local_session([0x5a; 32]),
        session,
    ))
}

#[cfg(any(test, debug_assertions, feature = "test-support"))]
fn mock_loopback_transport(
    origin: &str,
) -> Result<(reqwest::Client, String), RuntimeTransportError> {
    let url =
        reqwest::Url::parse(origin).map_err(|_| RuntimeTransportError::EndpointNotLoopback)?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|host| host.is_loopback());
    if url.scheme() != "http"
        || !loopback
        || url.port().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(RuntimeTransportError::EndpointNotLoopback);
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| RuntimeTransportError::Unavailable)?;
    Ok((client, origin.trim_end_matches('/').to_owned()))
}

/// Golden SHA-256 of the exact canonical `bundle.json` bytes.
pub const GOLDEN_BUNDLE_HASH: &str =
    "dca8e3a64b77171495a5474a4994dcd8c33a715f2d6b492a9fc2d14e30619862";

/// Bundle ID expected from the runtime.
pub const EXPECTED_BUNDLE_ID: &str = "gocode-ui-client/1";

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeConnectionState {
    #[default]
    Unconfigured,
    Connecting,
    Authenticating,
    Reconciling,
    Live,
    Stale,
    Reconnecting,
    Incompatible,
    Revoked,
    Fatal,
}

impl RuntimeConnectionState {
    #[must_use]
    pub const fn allows_mutations(self) -> bool {
        matches!(self, Self::Live)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeHealth {
    Ready { version: String },
    RecoveryBlocked { version: String },
    IntegrityBlocked { version: String },
    ShuttingDown { version: String },
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RuntimeHealthError {
    #[error("runtime health payload is invalid")]
    InvalidPayload,
    #[error("runtime health status is unknown")]
    UnknownStatus,
    #[error("runtime health HTTP status does not match its payload")]
    StatusCodeMismatch,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthPayload {
    status: String,
    version: String,
}

impl RuntimeHealth {
    /// Parses the public `/health` response observed at
    /// `HEALTH_CONTRACT_EVIDENCE_COMMIT`.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed payloads, unknown states, invalid
    /// versions or HTTP status/payload mismatches.
    pub fn parse(status_code: u16, bytes: &[u8]) -> Result<Self, RuntimeHealthError> {
        let payload: HealthPayload =
            serde_json::from_slice(bytes).map_err(|_| RuntimeHealthError::InvalidPayload)?;
        if payload.version.is_empty()
            || payload.version.len() > 64
            || payload.version.chars().any(char::is_control)
        {
            return Err(RuntimeHealthError::InvalidPayload);
        }
        let (health, expected_code) = match payload.status.as_str() {
            "ok" => (
                Self::Ready {
                    version: payload.version,
                },
                200,
            ),
            "degraded" => (
                Self::RecoveryBlocked {
                    version: payload.version,
                },
                200,
            ),
            "unavailable" => (
                Self::IntegrityBlocked {
                    version: payload.version,
                },
                503,
            ),
            "shutting_down" => (
                Self::ShuttingDown {
                    version: payload.version,
                },
                503,
            ),
            _ => return Err(RuntimeHealthError::UnknownStatus),
        };
        if status_code != expected_code {
            return Err(RuntimeHealthError::StatusCodeMismatch);
        }
        Ok(health)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve_once(response: &'static [u8]) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept health request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            while !request.ends_with(b"\r\n\r\n") {
                let read = socket.read(&mut chunk).await.expect("read health request");
                assert!(read > 0, "health request ended before its headers");
                request.extend_from_slice(&chunk[..read]);
                assert!(
                    request.len() <= 4 * 1024,
                    "health request headers too large"
                );
            }
            socket
                .write_all(response)
                .await
                .expect("write health response");
        });
        Ok(address)
    }

    #[test]
    fn runtime_endpoint_accepts_only_loopback_addresses() {
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43123);
        assert_eq!(
            RuntimeEndpoint::loopback(loopback)
                .expect("loopback endpoint")
                .address(),
            loopback
        );

        let external = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 43123);
        assert_eq!(
            RuntimeEndpoint::loopback(external),
            Err(RuntimeTransportError::EndpointNotLoopback)
        );
    }

    #[test]
    fn runtime_profile_accepts_only_the_exact_bundle_identity() {
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43123);
        let endpoint = RuntimeEndpoint::loopback(address).expect("endpoint");

        let profile = RuntimeProfile::validate(endpoint, "gocode-ui-client/1", GOLDEN_BUNDLE_HASH)
            .expect("validated profile");
        assert_eq!(profile.endpoint().address(), address);

        assert_eq!(
            RuntimeProfile::validate(endpoint, "gocode-ui-client/2", GOLDEN_BUNDLE_HASH),
            Err(RuntimeProfileError::ProfileMismatch)
        );
        assert_eq!(
            RuntimeProfile::validate(
                endpoint,
                EXPECTED_BUNDLE_ID,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            Err(RuntimeProfileError::SchemaHashMismatch)
        );
    }

    #[test]
    fn health_transport_disables_system_proxies() {
        let endpoint =
            RuntimeEndpoint::loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 43123))
                .expect("endpoint");
        let profile = RuntimeProfile::validate(endpoint, EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH)
            .expect("profile");
        let client =
            HttpRuntimeClient::new(profile, Duration::from_secs(1)).expect("runtime client");

        assert!(!format!("{:?}", client.client).contains("proxies"));
    }

    #[tokio::test]
    async fn health_transport_reads_the_bounded_loopback_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 33\r\nConnection: close\r\n\r\n{\"status\":\"ok\",\"version\":\"0.1.0\"}";
        let address = serve_once(response).await.expect("health server");
        let profile = RuntimeProfile::validate(
            RuntimeEndpoint::loopback(address).expect("endpoint"),
            EXPECTED_BUNDLE_ID,
            GOLDEN_BUNDLE_HASH,
        )
        .expect("profile");
        let client =
            HttpRuntimeClient::new(profile, Duration::from_secs(1)).expect("runtime client");

        assert_eq!(
            client.probe_health().await.expect("probe health"),
            RuntimeHealth::Ready {
                version: "0.1.0".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn health_transport_rejects_redirects() {
        let response =
            b"HTTP/1.1 302 Found\r\nLocation: http://example.com/\r\nContent-Length: 0\r\n\r\n";
        let address = serve_once(response).await.expect("redirect server");
        let profile = RuntimeProfile::validate(
            RuntimeEndpoint::loopback(address).expect("endpoint"),
            EXPECTED_BUNDLE_ID,
            GOLDEN_BUNDLE_HASH,
        )
        .expect("profile");
        let client =
            HttpRuntimeClient::new(profile, Duration::from_secs(1)).expect("runtime client");

        assert_eq!(
            client.probe_health().await,
            Err(RuntimeTransportError::UnexpectedHttpStatus)
        );
    }

    #[test]
    fn health_payload_maps_only_the_published_runtime_states() {
        assert_eq!(
            RuntimeHealth::parse(200, br#"{"status":"ok","version":"0.1.0"}"#)
                .expect("ready health"),
            RuntimeHealth::Ready {
                version: "0.1.0".to_owned(),
            }
        );
        assert_eq!(
            RuntimeHealth::parse(200, br#"{"status":"degraded","version":"0.1.0"}"#)
                .expect("degraded health"),
            RuntimeHealth::RecoveryBlocked {
                version: "0.1.0".to_owned(),
            }
        );
        assert_eq!(
            RuntimeHealth::parse(503, br#"{"status":"shutting_down","version":"0.1.0"}"#,)
                .expect("shutdown health"),
            RuntimeHealth::ShuttingDown {
                version: "0.1.0".to_owned(),
            }
        );
    }

    #[test]
    fn health_payload_fails_closed_on_unknown_state_or_status_mismatch() {
        assert_eq!(
            RuntimeHealth::parse(200, br#"{"status":"future","version":"0.1.0"}"#),
            Err(RuntimeHealthError::UnknownStatus)
        );
        assert_eq!(
            RuntimeHealth::parse(503, br#"{"status":"ok","version":"0.1.0"}"#),
            Err(RuntimeHealthError::StatusCodeMismatch)
        );
        assert_eq!(
            RuntimeHealth::parse(
                200,
                br#"{"status":"ok","version":"0.1.0","token":"secret"}"#
            ),
            Err(RuntimeHealthError::InvalidPayload)
        );
    }

    #[test]
    fn connection_state_defaults_to_unconfigured_and_only_live_allows_mutations() {
        assert_eq!(
            RuntimeConnectionState::default(),
            RuntimeConnectionState::Unconfigured
        );
        assert!(!RuntimeConnectionState::Unconfigured.allows_mutations());
        assert!(!RuntimeConnectionState::Reconciling.allows_mutations());
        assert!(RuntimeConnectionState::Live.allows_mutations());
    }

    #[test]
    fn health_contract_evidence_commit_is_valid_hex() {
        assert_eq!(HEALTH_CONTRACT_EVIDENCE_COMMIT.len(), 40);
        assert!(
            HEALTH_CONTRACT_EVIDENCE_COMMIT
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn golden_hash_is_valid_hex() {
        assert_eq!(GOLDEN_BUNDLE_HASH.len(), 64);
        assert!(GOLDEN_BUNDLE_HASH.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn bundle_id_is_expected() {
        assert_eq!(EXPECTED_BUNDLE_ID, "gocode-ui-client/1");
    }
}
