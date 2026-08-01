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

fn decode_stable(decoder: &mut CborDecoder<'_>) -> Result<StableRuntimeBindingV1, DecodeError> {
    if decoder.read_map_header(6)? != 6 {
        return Err(DecodeError::UnknownField { key: 6 });
    }
    expect_key(decoder, 1)?;
    let authority_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 2)?;
    let principal_id = decoder.read_text_string(MAX_PRINCIPAL_ID_BYTES)?.to_owned();
    expect_key(decoder, 3)?;
    let lineage_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 4)?;
    let profile_id = decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned();
    expect_key(decoder, 5)?;
    let profile_hash = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 6)?;
    let capability_digest = decode_fixed::<32>(decoder)?;
    StableRuntimeBindingV1::new(
        authority_id,
        principal_id,
        lineage_id,
        profile_id,
        profile_hash,
        capability_digest,
    )
    .map_err(|_| DecodeError::UnknownField { key: 6 })
}

fn encode_owned_launch(encoder: &mut CborEncoder, owned: &ProtectedOwnedLaunchV1) {
    encoder.write_map_header(8);
    write_key(encoder, 1);
    encoder.write_byte_string(&owned.launch_authority_id);
    write_key(encoder, 2);
    encoder.write_byte_string(&owned.desktop_host_instance_id);
    write_key(encoder, 3);
    encode_executable(encoder, &owned.executable);
    write_key(encoder, 4);
    encode_profile(encoder, &owned.profile);
    write_key(encoder, 5);
    encode_stable(encoder, &owned.stable);
    write_key(encoder, 6);
    encoder.write_byte_string(&owned.daemon_instance_id);
    write_key(encoder, 7);
    encoder.write_unsigned(owned.launch_generation);
    write_key(encoder, 8);
    encoder.write_byte_string(&owned.session_id);
}

fn decode_owned_launch(
    decoder: &mut CborDecoder<'_>,
) -> Result<ProtectedOwnedLaunchV1, DecodeError> {
    if decoder.read_map_header(8)? != 8 {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 1)?;
    let launch_authority_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 2)?;
    let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 3)?;
    let executable = decode_executable(decoder)?;
    expect_key(decoder, 4)?;
    let profile = decode_profile(decoder)?;
    expect_key(decoder, 5)?;
    let stable = decode_stable(decoder)?;
    expect_key(decoder, 6)?;
    let daemon_instance_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 7)?;
    let launch_generation = decoder.read_unsigned(u64::MAX)?;
    expect_key(decoder, 8)?;
    let session_id = decode_fixed::<16>(decoder)?;
    ProtectedOwnedLaunchV1::new(
        launch_authority_id,
        desktop_host_instance_id,
        executable,
        profile,
        stable,
        daemon_instance_id,
        launch_generation,
        session_id,
    )
    .map_err(|_| DecodeError::UnknownField { key: 8 })
}
