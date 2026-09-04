
fn verify_remote_profile(
    local: &SessionPeer,
    remote: SessionRuntimeProfileWire,
    issued_session_id: [u8; 16],
) -> Result<(RuntimeSessionInfo, Vec<runne_api::ProviderStatusSnapshotV1>), LocalRuntimeConnectError> {
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
        || !valid_provider_statuses(&remote.provider_statuses)
        || !selected_provider_matches(&remote.provider_statuses, local.provider_binding.as_ref())
    {
        return Err(incompatible());
    }
    Ok((RuntimeSessionInfo {
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
    }, remote.provider_statuses))
}

fn selected_provider_matches(
    statuses: &[runne_api::ProviderStatusSnapshotV1],
    binding: Option<&runne_api::ProviderActivationBindingV1>,
) -> bool {
    let Some(binding) = binding else {
        return true;
    };
    let Some(selected) = statuses.iter().find(|status| status.selected()) else {
        return false;
    };
    selected.provider_id() == provider_id(binding.mode())
        && selected.mode() == binding.mode().as_str()
        && selected.profile_id() == binding.profile_id()
        && selected.profile_digest() == hex::encode(binding.profile_digest())
}

const fn provider_id(mode: runne_api::ProviderActivationModeV1) -> &'static str {
    match mode {
        runne_api::ProviderActivationModeV1::DeterministicV1 => "deterministic",
        runne_api::ProviderActivationModeV1::OpenAiResponsesTextV1 => "openai",
        runne_api::ProviderActivationModeV1::DeepSeekResponsesTextV1 => "deepseek",
        runne_api::ProviderActivationModeV1::LocalEngineTextV1 => "local",
    }
}

fn valid_provider_statuses(statuses: &[runne_api::ProviderStatusSnapshotV1]) -> bool {
    if statuses.len() > 8 {
        return false;
    }
    let mut selected = 0_usize;
    for (index, status) in statuses.iter().enumerate() {
        if status.validate().is_err() {
            return false;
        }
        if status.selected() {
            selected += 1;
        }
        if statuses[..index]
            .iter()
            .any(|previous| previous.provider_id() == status.provider_id())
        {
            return false;
        }
    }
    selected <= 1
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

async fn verify_pinned_peer(
    client: &reqwest::Client,
    origin: &str,
) -> Result<(), LocalRuntimeConnectError> {
    let response = client
        .get(format!("{origin}/health"))
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| RuntimeTransportError::PeerIdentityMismatch)?;
    if response.status().as_u16() != 200
        || response.content_length().is_some_and(|length| {
            length > u64::try_from(MAXIMUM_BOOTSTRAP_RESPONSE_BYTES).unwrap_or(u64::MAX)
        })
    {
        return Err(incompatible());
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| RuntimeTransportError::Unavailable)?;
    if body.len() > MAXIMUM_BOOTSTRAP_RESPONSE_BYTES {
        return Err(incompatible());
    }
    Ok(())
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
    provider_statuses: Vec<runne_api::ProviderStatusSnapshotV1>,
}
