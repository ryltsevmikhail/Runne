use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gocode_api::{
    LaunchAuthorityError, PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID, ProtectedActivationKeys,
    ProtectedLaunchRequestV1, ProtectedReadyV1, ProtectedRenewRequestV1, ProtectedRenewTicketV1,
};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::canonical::{
    AuthenticatedRuntimeClient, RuntimeApiError, RuntimeApiErrorKind, RuntimeCredential,
    RuntimeTransportKind,
};
use crate::local_profile::{
    LocalRuntimeProfile, ordered_capability_digest, parse_endpoint, read_bootstrap_secret,
};
use crate::{
    GOLDEN_BUNDLE_HASH, LocalRuntimeConnectError, RuntimeSessionInfo, RuntimeTransportError,
};

const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_BOOTSTRAP_RESPONSE_BYTES: usize = 8 * 1024;
const PROTECTED_RUNTIME_PROFILE_SCHEMA_VERSION: u32 = 1;

struct SessionPeer {
    endpoint: crate::RuntimeEndpoint,
    origin: String,
    certificate_der: Vec<u8>,
    certificate_sha256: [u8; 32],
    authority_id: [u8; 16],
    principal_id: String,
    event_log_lineage_id: uuid::Uuid,
    daemon_instance_id: uuid::Uuid,
    launch_generation: u64,
    expected_session_id: Option<[u8; 16]>,
    schema_hash: [u8; 32],
    capabilities: Vec<String>,
    capability_digest: [u8; 32],
}

enum BootstrapMaterial {
    ExternalPath(PathBuf),
    Protected(Zeroizing<[u8; 32]>),
}

/// Exact in-memory bundled profile produced only from authenticated readiness.
///
/// This type has no credential path and cannot load the external local profile.
pub struct ProtectedBundledRuntimeProfile {
    peer: SessionPeer,
    bootstrap_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for ProtectedBundledRuntimeProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedBundledRuntimeProfile")
            .field("endpoint", &self.peer.endpoint)
            .field("transport", &PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID)
            .field("peer_identity", &"<pinned>")
            .finish_non_exhaustive()
    }
}

impl ProtectedBundledRuntimeProfile {
    /// Verifies exact launch readiness and constructs a path-free bootstrap.
    ///
    /// # Errors
    ///
    /// Returns a closed launch-authority error when readiness, transport,
    /// profile, capability, endpoint, or pinned-certificate identity differs.
    pub fn from_ready(
        ready: &ProtectedReadyV1,
        request: &ProtectedLaunchRequestV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<Self, LaunchAuthorityError> {
        let peer = session_peer_from_ready(ready, request, keys)?;
        Ok(Self {
            peer,
            bootstrap_key: keys.bootstrap_key(),
        })
    }

    /// Constructs the next path-free bootstrap from an authenticated renewal.
    ///
    /// # Errors
    ///
    /// Returns a closed launch-authority error for a stale, mismatched, or
    /// unauthenticated ticket or readiness tuple.
    pub fn from_renewal(
        ready: &ProtectedReadyV1,
        launch_request: &ProtectedLaunchRequestV1,
        renewal_request: &ProtectedRenewRequestV1,
        ticket: &ProtectedRenewTicketV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<Self, LaunchAuthorityError> {
        ticket.verify_exact(renewal_request, keys)?;
        let mut peer = session_peer_from_ready(ready, launch_request, keys)?;
        peer.expected_session_id = Some(*ticket.next_session_id());
        Ok(Self {
            peer,
            bootstrap_key: ticket.bootstrap_ticket(),
        })
    }

    /// Returns the validated loopback endpoint without exposing credentials.
    #[must_use]
    pub const fn endpoint(&self) -> crate::RuntimeEndpoint {
        self.peer.endpoint
    }

    /// Copies the one-time bootstrap key only for test-support leak audits.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    #[must_use]
    pub fn test_bootstrap_material(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.bootstrap_key)
    }

    /// Proves the in-memory one-time bootstrap and opens one bundled session.
    ///
    /// # Errors
    ///
    /// Returns a redacted transport or API error when pinned TLS, the one-time
    /// proof, or the exact authenticated runtime profile cannot be verified.
    pub async fn connect(
        self,
        timeout: Duration,
    ) -> Result<AuthenticatedRuntimeClient, LocalRuntimeConnectError> {
        connect_with_peer(
            self.peer,
            BootstrapMaterial::Protected(self.bootstrap_key),
            RuntimeTransportKind::ProtectedBundled,
            timeout,
        )
        .await
    }
}

fn session_peer_from_ready(
    ready: &ProtectedReadyV1,
    request: &ProtectedLaunchRequestV1,
    keys: &ProtectedActivationKeys,
) -> Result<SessionPeer, LaunchAuthorityError> {
    ready.verify_exact(request, keys)?;
    let expected_schema_hash: [u8; 32] = hex::decode(GOLDEN_BUNDLE_HASH)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(LaunchAuthorityError::ProfileHashMismatch)?;
    let profile = ready.profile();
    let stable = ready.stable();
    if profile.transport_profile_id() != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID {
        return Err(LaunchAuthorityError::DowngradedExternalProfile);
    }
    if profile.runtime_profile_schema_version() != PROTECTED_RUNTIME_PROFILE_SCHEMA_VERSION
        || profile.profile_id() != crate::EXPECTED_BUNDLE_ID
        || profile.profile_hash() != &expected_schema_hash
        || stable.principal_id() != request.principal_id()
        || stable.profile_id() != profile.profile_id()
        || stable.profile_hash() != profile.profile_hash()
        || stable.capability_digest() != profile.capability_digest()
        || !ready
            .capabilities()
            .iter()
            .map(String::as_str)
            .eq(crate::REQUIRED_RUNTIME_CAPABILITIES.iter().copied())
        || ordered_capability_digest(ready.capabilities()) != *profile.capability_digest()
    {
        return Err(LaunchAuthorityError::ProfileHashMismatch);
    }
    let certificate_digest: [u8; 32] = Sha256::digest(ready.certificate_der()).into();
    if &certificate_digest != ready.certificate_sha256() {
        return Err(LaunchAuthorityError::ReadinessProofMismatch);
    }
    let (endpoint, origin) =
        parse_endpoint(ready.endpoint()).map_err(|_| LaunchAuthorityError::InvalidContract)?;
    Ok(SessionPeer {
        endpoint,
        origin,
        certificate_der: ready.certificate_der().to_vec(),
        certificate_sha256: *ready.certificate_sha256(),
        authority_id: *stable.authority_id(),
        principal_id: stable.principal_id().to_owned(),
        event_log_lineage_id: uuid::Uuid::from_bytes(*stable.lineage_id()),
        daemon_instance_id: uuid::Uuid::from_bytes(*ready.daemon_instance_id()),
        launch_generation: ready.launch_generation(),
        expected_session_id: Some(*ready.session_id()),
        schema_hash: *profile.profile_hash(),
        capabilities: ready.capabilities().to_vec(),
        capability_digest: *profile.capability_digest(),
    })
}
