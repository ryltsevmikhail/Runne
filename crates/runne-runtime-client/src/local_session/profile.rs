// Pinned-TLS bootstrap proof and short-lived local session construction.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use runne_api::{
    LaunchAuthorityError, PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProtectedLaunchRequestV1, ProtectedLaunchRequestV2,
    ProtectedReadyV1, ProtectedReadyV2, ProtectedRenewRequestV1, ProtectedRenewRequestV2,
    ProtectedRenewTicketV1, ProtectedRenewTicketV2, ProviderActivationBindingV1,
};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, de::DeserializeOwned};
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
    executable_sha256: [u8; 32],
    launch_authority_id: [u8; 16],
    authority_id: [u8; 16],
    principal_id: String,
    event_log_lineage_id: uuid::Uuid,
    daemon_instance_id: uuid::Uuid,
    launch_generation: u64,
    expected_authorization_epoch: u64,
    expected_session_id: Option<[u8; 16]>,
    schema_hash: [u8; 32],
    capabilities: Vec<String>,
    capability_digest: [u8; 32],
    provider_binding: Option<ProviderActivationBindingV1>,
    native_v3_enrollment_attested: bool,
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
    enrollment_owned_launch: Option<ProtectedCredentialEnrollmentOwnedLaunchV3>,
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
            enrollment_owned_launch: None,
        })
    }

    /// Verifies provider-bound protocol V2 readiness and constructs a path-free bootstrap.
    ///
    /// # Errors
    ///
    /// Returns a closed launch-authority error when either the outer provider
    /// binding or the nested runtime/session readiness tuple differs.
    pub fn from_ready_v2(
        ready: &ProtectedReadyV2,
        request: &ProtectedLaunchRequestV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<Self, LaunchAuthorityError> {
        ready.verify_exact(request, keys)?;
        let mut peer = session_peer_from_ready(
            ready.compatibility_ready(),
            request.compatibility_request(),
            keys,
        )?;
        peer.provider_binding = Some(ready.provider_binding().clone());
        Ok(Self {
            peer,
            bootstrap_key: keys.bootstrap_key(),
            enrollment_owned_launch: None,
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
            enrollment_owned_launch: None,
        })
    }

    /// Constructs the next path-free bootstrap from provider-bound V2 control messages.
    ///
    /// # Errors
    ///
    /// Returns a closed launch-authority error for a stale, changed, replayed,
    /// or unauthenticated provider/session renewal tuple.
    pub fn from_renewal_v2(
        ready: &ProtectedReadyV2,
        launch_request: &ProtectedLaunchRequestV2,
        renewal_request: &ProtectedRenewRequestV2,
        ticket: &ProtectedRenewTicketV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<Self, LaunchAuthorityError> {
        ticket.verify_exact(renewal_request, keys)?;
        ready.verify_exact(launch_request, keys)?;
        let mut peer = session_peer_from_ready(
            ready.compatibility_ready(),
            launch_request.compatibility_request(),
            keys,
        )?;
        peer.expected_session_id = Some(*ticket.next_session_id());
        peer.provider_binding = Some(ready.provider_binding().clone());
        Ok(Self {
            peer,
            bootstrap_key: ticket.bootstrap_ticket(),
            enrollment_owned_launch: None,
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
