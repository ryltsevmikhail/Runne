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
