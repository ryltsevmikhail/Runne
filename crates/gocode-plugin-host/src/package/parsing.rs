struct ParsedManifest {
    package_id: PluginId,
    package_version: PluginVersion,
    host_identity: PluginIdentity,
    plugin_identity: PluginIdentity,
    target_identity: TargetIdentity,
    entrypoint: EntrypointIdentity,
    file_table_digest: PluginDigest,
    protocol_profile_id: gocode_plugin_protocol::id::ProfileId,
    protocol_profile_digest: PluginDigest,
    files: Vec<DeclaredPackageFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeclaredPackageFile {
    path: String,
    kind: PluginPackageFileKind,
    size: u64,
    digest: PluginDigest,
}

/// The manifest/profile grammar is intentionally small, ordered and bounded.
/// It is a registry ingestion format, not a caller-controlled metadata API.
fn parse_manifest(bytes: &[u8]) -> Result<ParsedManifest, TrustedRegistryLoadError> {
    let text =
        core::str::from_utf8(bytes).map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let mut lines = text.lines();
    if lines.next() != Some("GOCODE_PLUGIN_MANIFEST_V1") {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    let package_id = PluginId::new(next_value(&mut lines, "package_id=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let package_version = PluginVersion::new(next_value(&mut lines, "package_version=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let host_identity = PluginIdentity::new(next_value(&mut lines, "host_identity=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let plugin_identity = PluginIdentity::new(next_value(&mut lines, "plugin_identity=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let target_identity = TargetIdentity::new(next_value(&mut lines, "target_identity=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let entrypoint = EntrypointIdentity::new(next_value(&mut lines, "entrypoint=")?)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let file_table_digest = parse_tagged_digest(next_value(&mut lines, "file_table_digest=")?)?;
    let profile_declaration = next_value(&mut lines, "protocol_profile=")?;
    let (profile_id, profile_digest) = profile_declaration
        .split_once('|')
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    let protocol_profile_id = gocode_plugin_protocol::id::ProfileId::new(profile_id)
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let protocol_profile_digest = parse_tagged_digest(profile_digest)?;
    let mut files = Vec::new();
    for line in lines {
        let declaration = line
            .strip_prefix("file=")
            .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
        files.push(parse_file_declaration(declaration)?);
        if files.len() > MAX_PACKAGE_FILES {
            return Err(TrustedRegistryLoadError::MalformedAuthority);
        }
    }
    if files.is_empty()
        || files.windows(2).any(|pair| pair[0].path >= pair[1].path)
        || files.iter().enumerate().any(|(index, file)| {
            files[index + 1..]
                .iter()
                .any(|other| file.path.eq_ignore_ascii_case(&other.path))
        })
    {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    Ok(ParsedManifest {
        package_id,
        package_version,
        host_identity,
        plugin_identity,
        target_identity,
        entrypoint,
        file_table_digest,
        protocol_profile_id,
        protocol_profile_digest,
        files,
    })
}

fn parse_file_declaration(value: &str) -> Result<DeclaredPackageFile, TrustedRegistryLoadError> {
    let mut parts = value.split('|');
    let path = parts
        .next()
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?
        .to_owned();
    validate_package_path(&path).map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let kind = match parts.next() {
        Some("data") => PluginPackageFileKind::Data,
        Some("executable") => PluginPackageFileKind::Executable,
        _ => return Err(TrustedRegistryLoadError::MalformedAuthority),
    };
    let size = parts
        .next()
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?
        .parse::<u64>()
        .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let digest = parse_tagged_digest(
        parts
            .next()
            .ok_or(TrustedRegistryLoadError::MalformedAuthority)?,
    )?;
    if parts.next().is_some() {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    Ok(DeclaredPackageFile {
        path,
        kind,
        size,
        digest,
    })
}

fn parse_tagged_digest(value: &str) -> Result<PluginDigest, TrustedRegistryLoadError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    if hex.len() != 64
        || hex
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_digit() && !matches!(*byte, b'a'..=b'f'))
    {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    let mut bytes = [0; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
        let low = hex_nibble(chunk[1]).ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
        bytes[index] = (high << 4) | low;
    }
    Ok(PluginDigest::from_bytes(bytes))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn parse_profile(bytes: &[u8]) -> Result<ProtocolSupportProfile, TrustedRegistryLoadError> {
    let text =
        core::str::from_utf8(bytes).map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let mut lines = text.lines();
    if lines.next() != Some("GOCODE_PLUGIN_PROFILE_V1") {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    let profile_id =
        gocode_plugin_protocol::id::ProfileId::new(next_value(&mut lines, "profile_id=")?)
            .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?;
    let version = next_value(&mut lines, "version=")?;
    let (major, minor) = version
        .split_once('.')
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    let version = ProtocolVersion::new(
        major
            .parse()
            .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?,
        minor
            .parse()
            .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)?,
    );
    let bootstrap = parse_tagged_digest(next_value(&mut lines, "bootstrap_schema_digest=")?)?;
    let wire = parse_tagged_digest(next_value(&mut lines, "wire_contract_digest=")?)?;
    let schema = parse_tagged_digest(next_value(&mut lines, "session_schema_bundle_digest=")?)?;
    let feature_line = lines
        .next()
        .and_then(|line| line.strip_prefix("features="))
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    let features = if feature_line.is_empty() {
        Vec::new()
    } else {
        feature_line.split(',').map(str::to_owned).collect()
    };
    let bounds = parse_tagged_digest(next_value(&mut lines, "bounds_profile_digest=")?)?;
    if lines.next().is_some() {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    ProtocolSupportProfile::new(
        profile_id,
        version,
        BootstrapSchemaDigest::from_bytes(*bootstrap.as_bytes()),
        WireContractDigest::from_bytes(*wire.as_bytes()),
        SchemaBundleDigest::from_bytes(*schema.as_bytes()),
        BoundsProfileDigest::from_bytes(*bounds.as_bytes()),
        features,
    )
    .map_err(|_| TrustedRegistryLoadError::MalformedAuthority)
}

fn next_value<'a>(
    lines: &mut core::str::Lines<'a>,
    prefix: &str,
) -> Result<&'a str, TrustedRegistryLoadError> {
    let line = lines
        .next()
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    let value = line
        .strip_prefix(prefix)
        .ok_or(TrustedRegistryLoadError::MalformedAuthority)?;
    if value.is_empty() {
        return Err(TrustedRegistryLoadError::MalformedAuthority);
    }
    // The returned slice is borrowed from the manifest bytes carried by `lines`.
    Ok(value)
}

fn negotiation_snapshot(
    source: &PluginPackageSource,
    generation: PluginGeneration,
) -> ProtocolNegotiationSnapshotDigest {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATION_SNAPSHOT_DIGEST_DOMAIN);
    hasher.update(source.package_digest.as_bytes());
    hasher.update(source.manifest_digest.as_bytes());
    hasher.update(source.protocol_profile_digest.as_bytes());
    hasher.update(generation.get().to_be_bytes());
    nonzero_snapshot(hasher.finalize().into())
}

#[allow(dead_code)] // Reserved for the crate-owned registry evolution boundary.
fn negotiation_snapshot_from_authority(
    authority: &PluginPackageAuthority,
    generation: PluginGeneration,
) -> ProtocolNegotiationSnapshotDigest {
    let mut hasher = Sha256::new();
    hasher.update(NEGOTIATION_SNAPSHOT_DIGEST_DOMAIN);
    hasher.update(authority.package_digest.as_bytes());
    hasher.update(authority.manifest_digest.as_bytes());
    hasher.update(authority.protocol_profile_digest.as_bytes());
    hasher.update(generation.get().to_be_bytes());
    nonzero_snapshot(hasher.finalize().into())
}

fn nonzero_snapshot(mut bytes: [u8; 32]) -> ProtocolNegotiationSnapshotDigest {
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[31] = 1;
    }
    ProtocolNegotiationSnapshotDigest::from_bytes(bytes)
}
