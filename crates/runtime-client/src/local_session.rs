//! Pinned-TLS bootstrap proof and short-lived local session construction.

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

pub async fn connect(
    profile: LocalRuntimeProfile,
    timeout: Duration,
) -> Result<AuthenticatedRuntimeClient, LocalRuntimeConnectError> {
    let LocalRuntimeProfile {
        endpoint,
        origin,
        certificate_der,
        certificate_sha256,
        bootstrap_secret_path,
        authority_id,
        principal_id,
        event_log_lineage_id,
        daemon_instance_id,
        launch_generation,
        schema_hash,
        capabilities,
        capability_digest,
    } = profile;
    connect_with_peer(
        SessionPeer {
            endpoint,
            origin,
            certificate_der,
            certificate_sha256,
            authority_id,
            principal_id,
            event_log_lineage_id,
            daemon_instance_id,
            launch_generation,
            expected_session_id: None,
            schema_hash,
            capabilities,
            capability_digest,
        },
        BootstrapMaterial::ExternalPath(bootstrap_secret_path),
        RuntimeTransportKind::ExternalLocal,
        timeout,
    )
    .await
}

async fn connect_with_peer(
    profile: SessionPeer,
    bootstrap_material: BootstrapMaterial,
    transport_kind: RuntimeTransportKind,
    timeout: Duration,
) -> Result<AuthenticatedRuntimeClient, LocalRuntimeConnectError> {
    if timeout.is_zero() || timeout > MAXIMUM_TIMEOUT {
        return Err(RuntimeTransportError::InvalidTimeout.into());
    }
    let certificate =
        reqwest::Certificate::from_der(&profile.certificate_der).map_err(|_| incompatible())?;
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(certificate)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|_| RuntimeTransportError::Unavailable)?;

    let mut client_nonce = [0; 32];
    let mut requested_server_nonce = [0; 32];
    OsRng.fill_bytes(&mut client_nonce);
    OsRng.fill_bytes(&mut requested_server_nonce);
    let challenge_body = serde_json::to_vec(&ChallengeRequest {
        client_nonce: URL_SAFE_NO_PAD.encode(client_nonce),
        server_nonce: URL_SAFE_NO_PAD.encode(requested_server_nonce),
    })
    .map_err(|_| incompatible())?;
    let challenge_response = client
        .post(format!("{}/v1/local-session/challenges", profile.origin))
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .body(challenge_body)
        .send()
        .await
        .map_err(|_| RuntimeTransportError::PeerIdentityMismatch)?;
    let challenge: ChallengeResponse = read_json(challenge_response).await?;
    let challenge_id = decode_16(&challenge.challenge_id)?;
    let server_nonce = decode_32(&challenge.server_nonce)?;
    if server_nonce != requested_server_nonce || challenge_id != server_nonce[..16] {
        return Err(incompatible());
    }

    // The bootstrap secret is deliberately opened only after a pinned TLS
    // response has authenticated the peer that issued this challenge.
    let bootstrap_secret = match bootstrap_material {
        BootstrapMaterial::ExternalPath(path) => Zeroizing::new(read_bootstrap_secret(&path)?),
        BootstrapMaterial::Protected(secret) => secret,
    };
    let transcript = Zeroizing::new(proof_transcript(&profile, server_nonce, client_nonce));
    let mut mac =
        Hmac::<Sha256>::new_from_slice(bootstrap_secret.as_ref()).map_err(|_| incompatible())?;
    mac.update(&transcript);
    let proof = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
    let mut authority = Zeroizing::new([0; 32]);
    while *authority == [0; 32] {
        OsRng.fill_bytes(authority.as_mut());
    }
    let authenticate_body = serde_json::to_vec(&AuthenticateRequest {
        challenge_id: URL_SAFE_NO_PAD.encode(challenge_id),
        proof: URL_SAFE_NO_PAD.encode(proof.as_ref()),
        authority: URL_SAFE_NO_PAD.encode(authority.as_ref()),
    })
    .map_err(|_| incompatible())?;
    let authenticate_response = client
        .post(format!("{}/v1/local-session/authenticate", profile.origin))
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .body(authenticate_body)
        .send()
        .await
        .map_err(|_| RuntimeTransportError::Unavailable)?;
    let authenticated: AuthenticateResponse = read_json(authenticate_response).await?;
    let issued_session_id = decode_lower_hex_16(&authenticated.session_id)?;
    if authenticated.expires_at_monotonic_millis == 0 || issued_session_id == [0; 16] {
        return Err(incompatible());
    }

    let credential = RuntimeCredential::from_local_session(*authority);
    let profile_response = client
        .get(format!("{}/v1/runtime/profile", profile.origin))
        .header(ACCEPT, "application/json")
        .header(AUTHORIZATION, credential.authorization_header()?)
        .send()
        .await
        .map_err(|_| RuntimeTransportError::Unavailable)?;
    let remote: SessionRuntimeProfileWire = read_json(profile_response).await?;
    let session = verify_remote_profile(&profile, remote, issued_session_id)?;
    Ok(match transport_kind {
        RuntimeTransportKind::ExternalLocal => AuthenticatedRuntimeClient::from_local_session(
            client,
            profile.origin,
            credential,
            session,
        ),
        RuntimeTransportKind::ProtectedBundled => {
            AuthenticatedRuntimeClient::from_protected_bundled_session(
                client,
                profile.origin,
                credential,
                session,
            )
        }
    })
}

fn verify_remote_profile(
    local: &SessionPeer,
    remote: SessionRuntimeProfileWire,
    issued_session_id: [u8; 16],
) -> Result<RuntimeSessionInfo, LocalRuntimeConnectError> {
    let session_id = decode_lower_hex_16(&remote.session_id)?;
    if session_id != issued_session_id
        || local
            .expected_session_id
            .is_some_and(|expected| session_id != expected)
        || session_id == *local.daemon_instance_id.as_bytes()
        || remote.profile_id != crate::EXPECTED_BUNDLE_ID
        || remote.schema_hash != GOLDEN_BUNDLE_HASH
        || remote.schema_hash != hex::encode(local.schema_hash)
        || remote.capabilities != local.capabilities
        || remote.capability_digest != hex::encode(local.capability_digest)
        || remote.authority_id != hex::encode(local.authority_id)
        || remote.principal_id != local.principal_id
        || remote.event_log_lineage_id != local.event_log_lineage_id.to_string()
        || remote.daemon_instance_id != local.daemon_instance_id.to_string()
        || remote.launch_generation != local.launch_generation
        || remote.authorization_epoch != 0
        || remote.sensitivity_ceiling != "sensitive"
        || remote.certificate_sha256 != hex::encode(local.certificate_sha256)
        || remote.runtime_version.is_empty()
        || remote.runtime_version.len() > 64
        || remote.runtime_version.chars().any(char::is_control)
    {
        return Err(incompatible());
    }
    Ok(RuntimeSessionInfo {
        profile_id: remote.profile_id,
        schema_hash: remote.schema_hash,
        runtime_version: remote.runtime_version,
        capabilities: remote.capabilities,
        authority_id: remote.authority_id,
        principal_id: remote.principal_id,
        event_log_lineage_id: remote.event_log_lineage_id,
        daemon_instance_id: remote.daemon_instance_id,
        launch_generation: remote.launch_generation,
        session_id: remote.session_id,
        authorization_epoch: remote.authorization_epoch,
        sensitivity_ceiling: remote.sensitivity_ceiling,
        certificate_sha256: remote.certificate_sha256,
        capability_digest: remote.capability_digest,
    })
}

fn proof_transcript(
    profile: &SessionPeer,
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
) -> Vec<u8> {
    let mut output = b"gocode/local-runtime/bootstrap-proof/v2\0".to_vec();
    output.extend_from_slice(&2_u32.to_be_bytes());
    output.extend_from_slice(&profile.certificate_sha256);
    output.extend_from_slice(&server_nonce);
    output.extend_from_slice(&client_nonce);
    output.extend_from_slice(&profile.authority_id);
    append_string(&mut output, &profile.principal_id);
    output.extend_from_slice(profile.event_log_lineage_id.as_bytes());
    output.extend_from_slice(profile.daemon_instance_id.as_bytes());
    output.extend_from_slice(&profile.launch_generation.to_be_bytes());
    append_string(&mut output, crate::EXPECTED_BUNDLE_ID);
    output.extend_from_slice(&profile.schema_hash);
    output.extend_from_slice(&profile.capability_digest);
    output
}

fn append_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

async fn read_json<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, LocalRuntimeConnectError> {
    let status = response.status().as_u16();
    if status != 200 {
        return Err(LocalRuntimeConnectError::Api(RuntimeApiError::new(
            match status {
                401 => RuntimeApiErrorKind::Unauthorized,
                503 => RuntimeApiErrorKind::Unavailable,
                _ => RuntimeApiErrorKind::InvalidResponse,
            },
        )));
    }
    if response.content_length().is_some_and(|length| {
        length > u64::try_from(MAXIMUM_BOOTSTRAP_RESPONSE_BYTES).unwrap_or(u64::MAX)
    }) {
        return Err(LocalRuntimeConnectError::Api(RuntimeApiError::new(
            RuntimeApiErrorKind::ResponseTooLarge,
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| RuntimeTransportError::Unavailable)?;
    if bytes.len() > MAXIMUM_BOOTSTRAP_RESPONSE_BYTES {
        return Err(LocalRuntimeConnectError::Api(RuntimeApiError::new(
            RuntimeApiErrorKind::ResponseTooLarge,
        )));
    }
    serde_json::from_slice(&bytes).map_err(|_| incompatible())
}

fn decode_32(value: &str) -> Result<[u8; 32], LocalRuntimeConnectError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(incompatible)
}

fn decode_16(value: &str) -> Result<[u8; 16], LocalRuntimeConnectError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(incompatible)
}

fn decode_lower_hex_16(value: &str) -> Result<[u8; 16], LocalRuntimeConnectError> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(incompatible());
    }
    let mut output = [0; 16];
    hex::decode_to_slice(value, &mut output).map_err(|_| incompatible())?;
    Ok(output)
}

const fn incompatible() -> LocalRuntimeConnectError {
    LocalRuntimeConnectError::Api(RuntimeApiError::new(RuntimeApiErrorKind::Incompatible))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeRequest {
    client_nonce: String,
    server_nonce: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeResponse {
    challenge_id: String,
    server_nonce: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticateRequest {
    challenge_id: String,
    proof: String,
    authority: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthenticateResponse {
    expires_at_monotonic_millis: u64,
    session_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionRuntimeProfileWire {
    profile_id: String,
    schema_hash: String,
    runtime_version: String,
    capabilities: Vec<String>,
    capability_digest: String,
    authority_id: String,
    principal_id: String,
    event_log_lineage_id: String,
    daemon_instance_id: String,
    launch_generation: u64,
    session_id: String,
    authorization_epoch: u64,
    sensitivity_ceiling: String,
    certificate_sha256: String,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    use super::*;
    use crate::RuntimeEndpoint;
    use gocode_api::{
        ActivationDispositionV1, ExecutableIdentityV1, LaunchSecret, ProtectedLaunchRequestV1,
        ProtectedReadyV1, ProtectedRuntimeProfileV1, StableRuntimeBindingV1,
    };

    #[test]
    fn local_session_authorization_header_is_sensitive() {
        let marker = URL_SAFE_NO_PAD.encode([0x5a; 32]);
        let credential = RuntimeCredential::from_local_session([0x5a; 32]);
        let header = credential.authorization_header().expect("header");

        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains(&marker));
    }

    #[test]
    fn exact_session_tuple_mismatches_are_typed_incompatible() {
        let local = session_peer_fixture();
        verify_remote_profile(&local, remote_profile_fixture(&local), [0x22; 16])
            .expect("exact tuple");

        macro_rules! reject_field {
            ($field:ident, $value:expr) => {{
                let mut remote = remote_profile_fixture(&local);
                remote.$field = $value;
                assert_incompatible(&local, remote, [0x22; 16]);
            }};
        }
        reject_field!(profile_id, "wrong-profile".to_owned());
        reject_field!(schema_hash, "00".repeat(32));
        reject_field!(runtime_version, String::new());
        reject_field!(capabilities, vec!["conversation.create.v1".to_owned()]);
        reject_field!(capability_digest, "00".repeat(32));
        reject_field!(authority_id, "00".repeat(16));
        reject_field!(principal_id, "other-owner".to_owned());
        reject_field!(
            event_log_lineage_id,
            "018f2e3a-7000-7000-8000-000000000004".to_owned()
        );
        reject_field!(
            daemon_instance_id,
            "018f2e3a-7000-7000-8000-000000000005".to_owned()
        );
        reject_field!(launch_generation, 8);
        reject_field!(session_id, "44".repeat(16));
        reject_field!(authorization_epoch, 1);
        reject_field!(sensitivity_ceiling, "internal".to_owned());
        reject_field!(certificate_sha256, "55".repeat(32));
        assert_incompatible(&local, remote_profile_fixture(&local), [0x44; 16]);
    }

    #[test]
    fn protected_profile_is_path_free_and_rejects_external_transport_downgrade() {
        let (request, ready, keys) =
            protected_ready_fixture(PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID);
        let profile = ProtectedBundledRuntimeProfile::from_ready(&ready, &request, &keys)
            .expect("exact protected profile");
        let debug = format!("{profile:?}");
        assert!(debug.contains(PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID));
        assert!(!debug.contains("bootstrap"));
        assert!(!debug.contains("secret"));

        let (external_request, external_ready, external_keys) =
            protected_ready_fixture("gocode-local-runtime/2");
        assert_eq!(
            ProtectedBundledRuntimeProfile::from_ready(
                &external_ready,
                &external_request,
                &external_keys,
            )
            .expect_err("credential-first profile is never bundled"),
            LaunchAuthorityError::DowngradedExternalProfile
        );
    }

    fn session_peer_fixture() -> SessionPeer {
        let schema_hash: [u8; 32] = hex::decode(GOLDEN_BUNDLE_HASH)
            .expect("schema digest")
            .try_into()
            .expect("32 byte schema digest");
        let authority_id = [0x11; 16];
        let event_log_lineage_id =
            uuid::Uuid::parse_str("018f2e3a-7000-7000-8000-000000000003").expect("lineage UUID");
        let daemon_instance_id =
            uuid::Uuid::parse_str("018f2e3a-7000-7000-8000-000000000002").expect("daemon UUID");
        let capabilities = crate::REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();
        let capability_digest = [0x22; 32];
        let certificate_sha256 = [0x33; 32];
        SessionPeer {
            endpoint: RuntimeEndpoint::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 8443)))
                .expect("loopback"),
            origin: "https://127.0.0.1:8443".to_owned(),
            certificate_der: vec![1],
            certificate_sha256,
            authority_id,
            principal_id: "local-owner".to_owned(),
            event_log_lineage_id,
            daemon_instance_id,
            launch_generation: 7,
            expected_session_id: None,
            schema_hash,
            capabilities,
            capability_digest,
        }
    }

    fn remote_profile_fixture(local: &SessionPeer) -> SessionRuntimeProfileWire {
        SessionRuntimeProfileWire {
            profile_id: crate::EXPECTED_BUNDLE_ID.to_owned(),
            schema_hash: GOLDEN_BUNDLE_HASH.to_owned(),
            runtime_version: "0.0.1".to_owned(),
            capabilities: local.capabilities.clone(),
            capability_digest: hex::encode(local.capability_digest),
            authority_id: hex::encode(local.authority_id),
            principal_id: "local-owner".to_owned(),
            event_log_lineage_id: local.event_log_lineage_id.to_string(),
            daemon_instance_id: local.daemon_instance_id.to_string(),
            launch_generation: 7,
            session_id: "22222222222222222222222222222222".to_owned(),
            authorization_epoch: 0,
            sensitivity_ceiling: "sensitive".to_owned(),
            certificate_sha256: hex::encode(local.certificate_sha256),
        }
    }

    fn assert_incompatible(
        local: &SessionPeer,
        remote: SessionRuntimeProfileWire,
        issued_session_id: [u8; 16],
    ) {
        let error = verify_remote_profile(local, remote, issued_session_id)
            .expect_err("tuple mismatch must be rejected");
        assert!(matches!(
            error,
            LocalRuntimeConnectError::Api(ref api)
                if api.kind() == RuntimeApiErrorKind::Incompatible
        ));
    }

    fn protected_ready_fixture(
        transport_profile_id: &str,
    ) -> (
        ProtectedLaunchRequestV1,
        ProtectedReadyV1,
        ProtectedActivationKeys,
    ) {
        let authority = uuid_bytes(1);
        let host = uuid_bytes(2);
        let lineage = uuid_bytes(3);
        let instance = uuid_bytes(4);
        let session = uuid_bytes(5);
        let executable =
            ExecutableIdentityV1::new([0x11; 32], [0x12; 32], 4_096).expect("executable");
        let schema_hash: [u8; 32] = hex::decode(GOLDEN_BUNDLE_HASH)
            .expect("schema hash")
            .try_into()
            .expect("32 byte schema hash");
        let capabilities = crate::REQUIRED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();
        let capability_digest = ordered_capability_digest(&capabilities);
        let runtime_profile = ProtectedRuntimeProfileV1::new(
            transport_profile_id,
            1,
            crate::EXPECTED_BUNDLE_ID,
            schema_hash,
            capability_digest,
        )
        .expect("runtime profile");
        let stable = StableRuntimeBindingV1::new(
            authority,
            "local-owner",
            lineage,
            crate::EXPECTED_BUNDLE_ID,
            schema_hash,
            capability_digest,
        )
        .expect("stable binding");
        let secret = LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret");
        let keys = secret.derive_keys();
        let request = ProtectedLaunchRequestV1::new(
            authority,
            host,
            secret,
            1_000,
            31_000,
            "local-owner",
            runtime_profile.clone(),
            executable.clone(),
            PathBuf::from("/private/tmp/gocode-protected-runtime"),
            ActivationDispositionV1::FirstActivation,
        )
        .expect("launch");
        let certificate_der = vec![1, 2, 3, 4];
        let certificate_sha256 = Sha256::digest(&certificate_der).into();
        let mut ready = ProtectedReadyV1::new(
            authority,
            host,
            executable,
            runtime_profile,
            stable,
            instance,
            7,
            session,
            "https://127.0.0.1:43123",
            certificate_sha256,
            certificate_der,
            capabilities,
        )
        .expect("ready");
        ready.sign(&keys);
        (request, ready, keys)
    }

    fn uuid_bytes(last: u8) -> [u8; 16] {
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, last,
        ]
    }
}
