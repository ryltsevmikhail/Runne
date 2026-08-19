// ── Decode helpers ────────────────────────────────────────────────────────

fn decode_host_hello(dec: &mut CborDecoder) -> Result<BootstrapMessage, DecodeError> {
    let mut nonce = None;
    let mut host_identity = None;
    let mut supported_profiles = BoundedProfileRefVec::new();
    let mut negotiation_snapshot = None;

    let mut seen = [false; 5]; // keys 1-4
    for _ in 0..4 {
        let key = dec.read_unsigned(10)?;
        if key < 1 || key > 4 || seen[key as usize] {
            return Err(DecodeError::DuplicateMapKey { key });
        }
        seen[key as usize] = true;
        match key {
            1 => nonce = Some(decode_nonce(dec)?),
            2 => host_identity = Some(decode_host_identity(dec)?),
            3 => supported_profiles = decode_profile_ref_vec(dec)?,
            4 => negotiation_snapshot = Some(decode_negotiation_snapshot_digest(dec)?),
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }

    Ok(BootstrapMessage::HostHello(HostHello {
        nonce: nonce.ok_or(DecodeError::MissingRequiredField { key: 1 })?,
        host_identity: host_identity.ok_or(DecodeError::MissingRequiredField { key: 2 })?,
        supported_profiles,
        negotiation_snapshot: negotiation_snapshot
            .ok_or(DecodeError::MissingRequiredField { key: 4 })?,
    }))
}

fn decode_plugin_hello(dec: &mut CborDecoder) -> Result<BootstrapMessage, DecodeError> {
    let mut host_nonce = None;
    let mut plugin_nonce = None;
    let mut host_identity = None;
    let mut package_id = None;
    let mut package_digest = None;
    let mut package_version = None;
    let mut manifest_digest = None;
    let mut plugin_identity = None;
    let mut target_identity = None;
    let mut supported_profiles = BoundedProfileRefVec::new();
    let mut entrypoint = None;

    let mut seen = [false; 12]; // keys 1-11
    for _ in 0..11 {
        let key = dec.read_unsigned(12)?;
        if key < 1 || key > 11 || seen[key as usize] {
            return Err(DecodeError::DuplicateMapKey { key });
        }
        seen[key as usize] = true;
        match key {
            1 => host_nonce = Some(decode_nonce(dec)?),
            2 => plugin_nonce = Some(decode_nonce(dec)?),
            3 => host_identity = Some(decode_host_identity(dec)?),
            4 => package_id = Some(decode_plugin_id(dec)?),
            5 => package_digest = Some(decode_package_digest(dec)?),
            6 => package_version = Some(decode_plugin_version(dec)?),
            7 => manifest_digest = Some(decode_manifest_digest(dec)?),
            8 => plugin_identity = Some(decode_host_identity(dec)?),
            9 => target_identity = Some(decode_target_identity(dec)?),
            10 => supported_profiles = decode_profile_ref_vec(dec)?,
            11 => entrypoint = Some(decode_entrypoint_identity(dec)?),
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }

    Ok(BootstrapMessage::PluginHello(PluginHello {
        host_nonce: host_nonce.ok_or(DecodeError::MissingRequiredField { key: 1 })?,
        plugin_nonce: plugin_nonce.ok_or(DecodeError::MissingRequiredField { key: 2 })?,
        host_identity: host_identity.ok_or(DecodeError::MissingRequiredField { key: 3 })?,
        package_id: package_id.ok_or(DecodeError::MissingRequiredField { key: 4 })?,
        package_digest: package_digest.ok_or(DecodeError::MissingRequiredField { key: 5 })?,
        package_version: package_version.ok_or(DecodeError::MissingRequiredField { key: 6 })?,
        manifest_digest: manifest_digest.ok_or(DecodeError::MissingRequiredField { key: 7 })?,
        plugin_identity: plugin_identity.ok_or(DecodeError::MissingRequiredField { key: 8 })?,
        target_identity: target_identity.ok_or(DecodeError::MissingRequiredField { key: 9 })?,
        entrypoint: entrypoint.ok_or(DecodeError::MissingRequiredField { key: 11 })?,
        supported_profiles,
    }))
}

fn decode_negotiation_rejected(dec: &mut CborDecoder) -> Result<BootstrapMessage, DecodeError> {
    let key = dec.read_unsigned(10)?;
    if key != 1 {
        return Err(DecodeError::UnknownField { key });
    }
    let reason_code = dec.read_unsigned(10)?;
    let reason = reject_reason_from_code(reason_code)
        .ok_or(DecodeError::UnknownField { key: reason_code })?;
    Ok(BootstrapMessage::NegotiationRejected(NegotiationRejected {
        reason,
    }))
}

fn decode_profile_selected(dec: &mut CborDecoder) -> Result<BootstrapMessage, DecodeError> {
    let mut host_nonce = None;
    let mut plugin_nonce = None;
    let mut session_id = None;
    let mut profile_id = None;
    let mut profile_digest = None;

    let mut seen = [false; 6]; // keys 1-5
    for _ in 0..5 {
        let key = dec.read_unsigned(6)?;
        if key < 1 || key > 5 || seen[key as usize] {
            return Err(DecodeError::DuplicateMapKey { key });
        }
        seen[key as usize] = true;
        match key {
            1 => host_nonce = Some(decode_nonce(dec)?),
            2 => plugin_nonce = Some(decode_nonce(dec)?),
            3 => session_id = Some(decode_session_id(dec)?),
            4 => profile_id = Some(decode_profile_id(dec)?),
            5 => profile_digest = Some(decode_profile_digest(dec)?),
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }

    Ok(BootstrapMessage::ProfileSelected(ProfileSelected {
        host_nonce: host_nonce.ok_or(DecodeError::MissingRequiredField { key: 1 })?,
        plugin_nonce: plugin_nonce.ok_or(DecodeError::MissingRequiredField { key: 2 })?,
        session_id: session_id.ok_or(DecodeError::MissingRequiredField { key: 3 })?,
        profile_id: profile_id.ok_or(DecodeError::MissingRequiredField { key: 4 })?,
        profile_digest: profile_digest.ok_or(DecodeError::MissingRequiredField { key: 5 })?,
    }))
}

// ── Field-level decoders ──────────────────────────────────────────────────

fn decode_nonce(dec: &mut CborDecoder) -> Result<Nonce, DecodeError> {
    let bytes = dec.read_byte_string(16)?;
    if bytes.len() != 16 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    Ok(Nonce::from_bytes(arr))
}

fn decode_session_id(dec: &mut CborDecoder) -> Result<ProtocolSessionId, DecodeError> {
    let bytes = dec.read_byte_string(16)?;
    if bytes.len() != 16 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    // Check UUID version/variant
    if arr[6] >> 4 != 7 {
        return Err(DecodeError::InvalidUuidVariant { offset: 0 });
    }
    if arr[8] >> 6 != 0b10 {
        return Err(DecodeError::InvalidUuidVariant { offset: 0 });
    }
    Ok(ProtocolSessionId::from_bytes(arr))
}

fn decode_profile_id(dec: &mut CborDecoder) -> Result<ProfileId, DecodeError> {
    let s = dec.read_text_string(256)?;
    ProfileId::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_profile_digest(dec: &mut CborDecoder) -> Result<ProfileDigest, DecodeError> {
    let bytes = dec.read_byte_string(32)?;
    if bytes.len() != 32 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(ProfileDigest::from_bytes(arr))
}

fn decode_plugin_id(dec: &mut CborDecoder) -> Result<PluginId, DecodeError> {
    let s = dec.read_text_string(256)?;
    PluginId::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_plugin_version(dec: &mut CborDecoder) -> Result<PluginVersion, DecodeError> {
    let s = dec.read_text_string(256)?;
    PluginVersion::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_target_identity(dec: &mut CborDecoder) -> Result<TargetIdentity, DecodeError> {
    let s = dec.read_text_string(256)?;
    TargetIdentity::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_entrypoint_identity(dec: &mut CborDecoder) -> Result<EntrypointIdentity, DecodeError> {
    let s = dec.read_text_string(512)?;
    EntrypointIdentity::new(s).map_err(|_| DecodeError::InvalidUtf8 { offset: 0 })
}

fn decode_negotiation_snapshot_digest(
    dec: &mut CborDecoder,
) -> Result<ProtocolNegotiationSnapshotDigest, DecodeError> {
    let bytes = dec.read_byte_string(32)?;
    if bytes.len() != 32 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(ProtocolNegotiationSnapshotDigest::from_bytes(arr))
}

fn decode_manifest_digest(dec: &mut CborDecoder) -> Result<ManifestDigest, DecodeError> {
    let bytes = dec.read_byte_string(32)?;
    if bytes.len() != 32 {
        return Err(DecodeError::TruncatedCbor { offset: 0 });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(ManifestDigest::from_bytes(arr))
}

fn decode_package_digest(dec: &mut CborDecoder) -> Result<PackageDigest, DecodeError> {
    let _map_len = dec.read_map_header(4)?;
    let mut algorithm = None;
    let mut digest_bytes = None;
    let mut seen_algo = false;
    for _ in 0..2 {
        let key = dec.read_unsigned(4)?;
        match key {
            1 => {
                if seen_algo {
                    return Err(DecodeError::DuplicateMapKey { key: 1 });
                }
                seen_algo = true;
                let code = dec.read_unsigned(10)?;
                algorithm = match code {
                    1 => Some(DigestAlgorithm::Sha256),
                    _ => return Err(DecodeError::UnknownField { key: code }),
                };
            }
            2 => {
                if digest_bytes.is_some() {
                    return Err(DecodeError::DuplicateMapKey { key: 2 });
                }
                let bytes = dec.read_byte_string(32)?;
                if bytes.len() != 32 {
                    return Err(DecodeError::TruncatedCbor { offset: 0 });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                digest_bytes = Some(arr);
            }
            _ => return Err(DecodeError::UnknownField { key }),
        }
    }
    Ok(PackageDigest::new(
        algorithm.ok_or(DecodeError::MissingRequiredField { key: 1 })?,
        digest_bytes.ok_or(DecodeError::MissingRequiredField { key: 2 })?,
    ))
}

fn decode_profile_ref_vec(dec: &mut CborDecoder) -> Result<BoundedProfileRefVec, DecodeError> {
    let array_len = dec.read_array_header(64)?;
    // Not truly bounded at decode — BoundedProfileRefVec is just a vec wrapper
    // for bootstrap. A proper limit should be enforced, but for now it's
    // bounded at construction time by the encode-side contract.
    let mut entries = Vec::new();
    for _ in 0..array_len {
        let _map_len = dec.read_map_header(4)?;
        let mut profile_id = None;
        let mut profile_digest = None;
        for _ in 0..2 {
            let key = dec.read_unsigned(3)?;
            match key {
                1 => {
                    if profile_id.is_some() {
                        return Err(DecodeError::DuplicateMapKey { key: 1 });
                    }
                    profile_id = Some(decode_profile_id(dec)?);
                }
                2 => {
                    if profile_digest.is_some() {
                        return Err(DecodeError::DuplicateMapKey { key: 2 });
                    }
                    profile_digest = Some(decode_profile_digest(dec)?);
                }
                _ => return Err(DecodeError::UnknownField { key }),
            }
        }
        let id = profile_id.ok_or(DecodeError::MissingRequiredField { key: 1 })?;
        let digest = profile_digest.ok_or(DecodeError::MissingRequiredField { key: 2 })?;
        entries.push(ProtocolProfileRef::new(id, digest));
    }
    Ok(BoundedProfileRefVec::from_vec(entries))
}
