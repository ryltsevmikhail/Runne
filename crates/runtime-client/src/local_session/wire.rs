
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
