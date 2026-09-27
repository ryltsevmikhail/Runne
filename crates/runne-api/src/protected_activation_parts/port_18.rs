
impl DeterministicCodec for ProtectedShutdownAckV2 {
    const MESSAGE_TYPE_ID: u32 = 26;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(5)? != 5 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch_v2(decoder)?;
        expect_key(decoder, 3)?;
        let graceful = decoder.read_bool()?;
        expect_key(decoder, 4)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            graceful,
            proof,
        })
    }
}

fn encode_provider_binding(encoder: &mut CborEncoder, binding: &ProviderActivationBindingV1) {
    encoder.write_map_header(3);
    write_key(encoder, 1);
    encoder.write_unsigned(binding.mode.wire_code());
    write_key(encoder, 2);
    encoder.write_text_string(&binding.profile_id);
    write_key(encoder, 3);
    encoder.write_byte_string(&binding.profile_digest);
}

fn decode_provider_binding(
    decoder: &mut CborDecoder<'_>,
) -> Result<ProviderActivationBindingV1, DecodeError> {
    if decoder.read_map_header(3)? != 3 {
        return Err(DecodeError::UnknownField { key: 3 });
    }
    expect_key(decoder, 1)?;
    let mode = ProviderActivationModeV1::from_wire_code(
        decoder.read_unsigned(ProviderActivationModeV1::MAX_WIRE_CODE)?,
    )?;
    expect_key(decoder, 2)?;
    let profile_id = decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned();
    expect_key(decoder, 3)?;
    let profile_digest = decode_fixed::<32>(decoder)?;
    ProviderActivationBindingV1::new(mode, profile_id, profile_digest)
        .map_err(|_| DecodeError::UnknownField { key: 3 })
}

fn encode_owned_launch_v2(encoder: &mut CborEncoder, owned: &ProtectedOwnedLaunchV2) {
    encoder.write_map_header(2);
    write_key(encoder, 1);
    encode_owned_launch(encoder, &owned.compatibility_owned_launch);
    write_key(encoder, 2);
    encode_provider_binding(encoder, &owned.provider_binding);
}

fn decode_owned_launch_v2(
    decoder: &mut CborDecoder<'_>,
) -> Result<ProtectedOwnedLaunchV2, DecodeError> {
    if decoder.read_map_header(2)? != 2 {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 1)?;
    let compatibility_owned_launch = decode_owned_launch(decoder)?;
    expect_key(decoder, 2)?;
    let provider_binding = decode_provider_binding(decoder)?;
    ProtectedOwnedLaunchV2::new(compatibility_owned_launch, provider_binding)
        .map_err(|_| DecodeError::UnknownField { key: 2 })
}

fn derive_key(secret: &[u8; 32], role: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts fixed keys");
    mac.update(KEY_DERIVATION_DOMAIN);
    mac.update(role);
    mac.finalize().into_bytes().into()
}

fn authenticated_mac(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> [u8; 32] {
    authenticated_mac_version(key, domain, PROTOCOL_SCHEMA_VERSION, payload)
}

fn authenticated_mac_version(
    key: &[u8; 32],
    domain: &[u8],
    schema_version: u32,
    payload: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts fixed keys");
    mac.update(domain);
    mac.update(&[0]);
    mac.update(&schema_version.to_be_bytes());
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(|character| character.is_control())
}

fn write_key(encoder: &mut CborEncoder, key: u64) {
    encoder.write_unsigned(key);
}

fn expect_key(decoder: &mut CborDecoder<'_>, expected: u64) -> Result<(), DecodeError> {
    let key = decoder.read_unsigned(expected.max(16))?;
    if key == expected {
        Ok(())
    } else {
        Err(DecodeError::UnknownField { key })
    }
}

fn expect_message_type(decoder: &mut CborDecoder<'_>, expected: u32) -> Result<(), DecodeError> {
    let actual = decoder.read_unsigned(u64::from(u32::MAX))?;
    if actual == u64::from(expected) {
        Ok(())
    } else {
        Err(DecodeError::UnknownMessageType {
            type_id: u32::try_from(actual).unwrap_or(u32::MAX),
        })
    }
}

fn expect_schema(decoder: &mut CborDecoder<'_>) -> Result<(), DecodeError> {
    expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION)
}

fn expect_schema_version(decoder: &mut CborDecoder<'_>, expected: u32) -> Result<(), DecodeError> {
    expect_key(decoder, 1)?;
    if decoder.read_unsigned(u64::from(u32::MAX))? == u64::from(expected) {
        Ok(())
    } else {
        Err(DecodeError::UnknownField { key: 1 })
    }
}

fn decode_fixed<const N: usize>(decoder: &mut CborDecoder<'_>) -> Result<[u8; N], DecodeError> {
    let bytes = decoder.read_byte_string(N)?;
    if bytes.len() != N {
        return Err(DecodeError::TruncatedCbor {
            offset: decoder.position(),
        });
    }
    let mut output = [0; N];
    output.copy_from_slice(bytes);
    Ok(output)
}

fn encode_executable(encoder: &mut CborEncoder, executable: &ExecutableIdentityV1) {
    encoder.write_map_header(3);
    write_key(encoder, 1);
    encoder.write_byte_string(&executable.executable_sha256);
    write_key(encoder, 2);
    encoder.write_byte_string(&executable.canonical_path_sha256);
    write_key(encoder, 3);
    encoder.write_unsigned(executable.byte_length);
}

fn decode_executable(decoder: &mut CborDecoder<'_>) -> Result<ExecutableIdentityV1, DecodeError> {
    if decoder.read_map_header(3)? != 3 {
        return Err(DecodeError::UnknownField { key: 9 });
    }
    expect_key(decoder, 1)?;
    let executable_sha256 = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 2)?;
    let canonical_path_sha256 = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 3)?;
    let byte_length = decoder.read_unsigned(u64::MAX)?;
    ExecutableIdentityV1::new(executable_sha256, canonical_path_sha256, byte_length)
        .map_err(|_| DecodeError::UnknownField { key: 3 })
}

fn encode_profile(encoder: &mut CborEncoder, profile: &ProtectedRuntimeProfileV1) {
    encoder.write_map_header(5);
    write_key(encoder, 1);
    encoder.write_text_string(&profile.transport_profile_id);
    write_key(encoder, 2);
    encoder.write_unsigned(u64::from(profile.runtime_profile_schema_version));
    write_key(encoder, 3);
    encoder.write_text_string(&profile.profile_id);
    write_key(encoder, 4);
    encoder.write_byte_string(&profile.profile_hash);
    write_key(encoder, 5);
    encoder.write_byte_string(&profile.capability_digest);
}

fn decode_profile(decoder: &mut CborDecoder<'_>) -> Result<ProtectedRuntimeProfileV1, DecodeError> {
    if decoder.read_map_header(5)? != 5 {
        return Err(DecodeError::UnknownField { key: 8 });
    }
    expect_key(decoder, 1)?;
    let transport_profile_id = decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned();
    expect_key(decoder, 2)?;
    let schema = u32::try_from(decoder.read_unsigned(u64::from(u32::MAX))?)
        .map_err(|_| DecodeError::UnknownField { key: 2 })?;
    expect_key(decoder, 3)?;
    let profile_id = decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned();
    expect_key(decoder, 4)?;
    let profile_hash = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 5)?;
    let capability_digest = decode_fixed::<32>(decoder)?;
    ProtectedRuntimeProfileV1::new(
        transport_profile_id,
        schema,
        profile_id,
        profile_hash,
        capability_digest,
    )
    .map_err(|_| DecodeError::UnknownField { key: 5 })
}

fn encode_stable(encoder: &mut CborEncoder, stable: &StableRuntimeBindingV1) {
    encoder.write_map_header(6);
    write_key(encoder, 1);
    encoder.write_byte_string(&stable.authority_id);
    write_key(encoder, 2);
    encoder.write_text_string(&stable.principal_id);
    write_key(encoder, 3);
    encoder.write_byte_string(&stable.lineage_id);
    write_key(encoder, 4);
    encoder.write_text_string(&stable.profile_id);
    write_key(encoder, 5);
    encoder.write_byte_string(&stable.profile_hash);
    write_key(encoder, 6);
    encoder.write_byte_string(&stable.capability_digest);
}
