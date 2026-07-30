//! Pinned-TLS bootstrap proof and short-lived local session construction.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::canonical::{
    AuthenticatedRuntimeClient, RuntimeApiError, RuntimeApiErrorKind, RuntimeCredential,
};
use crate::local_profile::{LocalRuntimeProfile, read_bootstrap_secret};
use crate::{
    GOLDEN_BUNDLE_HASH, LocalRuntimeConnectError, RuntimeSessionInfo, RuntimeTransportError,
};

const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(30);
const MAXIMUM_BOOTSTRAP_RESPONSE_BYTES: usize = 8 * 1024;

pub async fn connect(
    profile: LocalRuntimeProfile,
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
    let bootstrap_secret = Zeroizing::new(read_bootstrap_secret(&profile.bootstrap_secret_path)?);
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
    Ok(AuthenticatedRuntimeClient::from_local_session(
        client,
        profile.origin,
        credential,
        session,
    ))
}

fn verify_remote_profile(
    local: &LocalRuntimeProfile,
    remote: SessionRuntimeProfileWire,
    issued_session_id: [u8; 16],
) -> Result<RuntimeSessionInfo, LocalRuntimeConnectError> {
    let session_id = decode_lower_hex_16(&remote.session_id)?;
    if session_id != issued_session_id
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
    profile: &LocalRuntimeProfile,
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
        let local = local_profile_fixture();
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

    fn local_profile_fixture() -> LocalRuntimeProfile {
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
        LocalRuntimeProfile {
            endpoint: RuntimeEndpoint::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 8443)))
                .expect("loopback"),
            origin: "https://127.0.0.1:8443".to_owned(),
            certificate_der: vec![1],
            certificate_sha256,
            bootstrap_secret_path: PathBuf::from("/unused"),
            authority_id,
            principal_id: "local-owner".to_owned(),
            event_log_lineage_id,
            daemon_instance_id,
            launch_generation: 7,
            schema_hash,
            capabilities,
            capability_digest,
        }
    }

    fn remote_profile_fixture(local: &LocalRuntimeProfile) -> SessionRuntimeProfileWire {
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
        local: &LocalRuntimeProfile,
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
}
