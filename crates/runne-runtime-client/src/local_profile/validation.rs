fn schema_version(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("schemaVersion")?
        .as_u64()
}

pub fn parse_endpoint(value: &str) -> Result<(RuntimeEndpoint, String), LocalProfileError> {
    let url: reqwest::Url = value
        .parse()
        .map_err(|_| LocalProfileError::InvalidProfile)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(LocalProfileError::InvalidProfile);
    }
    let ip = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .ok_or(LocalProfileError::InvalidProfile)?;
    if !ip.is_loopback() {
        return Err(LocalProfileError::InvalidProfile);
    }
    let port = url.port().ok_or(LocalProfileError::InvalidProfile)?;
    let address = SocketAddr::new(ip, port);
    let endpoint =
        RuntimeEndpoint::loopback(address).map_err(|_| LocalProfileError::InvalidProfile)?;
    Ok((endpoint, format!("https://{address}")))
}

fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], LocalProfileError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LocalProfileError::InvalidProfile);
    }
    let mut output = [0; 32];
    hex::decode_to_slice(value, &mut output).map_err(|_| LocalProfileError::InvalidProfile)?;
    Ok(output)
}

fn decode_lower_hex_16(value: &str) -> Result<[u8; 16], LocalProfileError> {
    if value.len() != 32
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LocalProfileError::InvalidProfile);
    }
    let mut output = [0; 16];
    hex::decode_to_slice(value, &mut output).map_err(|_| LocalProfileError::InvalidProfile)?;
    Ok(output)
}

fn parse_uuid_v7(value: &str) -> Result<uuid::Uuid, LocalProfileError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| LocalProfileError::InvalidProfile)?;
    validate_uuid_v7(parsed)?;
    if parsed.to_string() != value {
        return Err(LocalProfileError::InvalidProfile);
    }
    Ok(parsed)
}

fn validate_uuid_v7(value: uuid::Uuid) -> Result<(), LocalProfileError> {
    if value.get_version_num() != 7 || value.get_variant() != uuid::Variant::RFC4122 {
        return Err(LocalProfileError::InvalidProfile);
    }
    Ok(())
}

pub fn ordered_capability_digest(capabilities: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"runne/local-runtime/capability-digest/v1\0");
    hasher.update(
        u32::try_from(capabilities.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for capability in capabilities {
        let bytes = capability.as_bytes();
        hasher.update(u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}
