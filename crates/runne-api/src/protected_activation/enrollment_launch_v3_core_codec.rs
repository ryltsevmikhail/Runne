fn encode_launch_core(encoder: &mut CborEncoder, core: &EnrollmentLaunchCoreV3) {
    encoder.write_map_header(10);
    write_key(encoder, 1);
    encoder.write_byte_string(&core.authority_id);
    write_key(encoder, 2);
    encoder.write_byte_string(&core.desktop_id);
    write_key(encoder, 3);
    encoder.write_byte_string(core.secret.0.as_ref());
    write_key(encoder, 4);
    encoder.write_unsigned(core.issued);
    write_key(encoder, 5);
    encoder.write_unsigned(core.expires);
    write_key(encoder, 6);
    encoder.write_text_string(&core.principal);
    write_key(encoder, 7);
    encode_profile(encoder, &core.profile);
    write_key(encoder, 8);
    encode_executable(encoder, &core.executable);
    write_key(encoder, 9);
    encoder.write_text_string(core.runtime_root.to_str().expect("validated runtime root"));
    write_key(encoder, 10);
    encode_disposition(encoder, &core.disposition);
}

fn enrollment_launch_request_digest(
    request: &ProtectedCredentialEnrollmentLaunchRequestV3,
) -> [u8; 32] {
    let mut encoder = CborEncoder::new();
    encoder.write_map_header(3);
    write_key(&mut encoder, 1);
    encode_launch_core_without_secret(&mut encoder, &request.core);
    write_key(&mut encoder, 2);
    encode_provider_binding(&mut encoder, &request.provider);
    write_key(&mut encoder, 3);
    encode_enrollment_binding(&mut encoder, &request.enrollment);
    let mut bytes = Zeroizing::new(encoder.into_bytes());
    let mut hasher = Sha256::new();
    hasher.update(ENROLLMENT_REQUEST_BINDING_DOMAIN_V3);
    hasher.update(PROTOCOL_SCHEMA_VERSION_V3.to_be_bytes());
    hasher.update(bytes.as_slice());
    let digest = hasher.finalize().into();
    bytes.zeroize();
    digest
}

fn encode_launch_core_without_secret(encoder: &mut CborEncoder, core: &EnrollmentLaunchCoreV3) {
    encoder.write_map_header(9);
    write_key(encoder, 1);
    encoder.write_byte_string(&core.authority_id);
    write_key(encoder, 2);
    encoder.write_byte_string(&core.desktop_id);
    write_key(encoder, 4);
    encoder.write_unsigned(core.issued);
    write_key(encoder, 5);
    encoder.write_unsigned(core.expires);
    write_key(encoder, 6);
    encoder.write_text_string(&core.principal);
    write_key(encoder, 7);
    encode_profile(encoder, &core.profile);
    write_key(encoder, 8);
    encode_executable(encoder, &core.executable);
    write_key(encoder, 9);
    encoder.write_text_string(core.runtime_root.to_str().expect("validated runtime root"));
    write_key(encoder, 10);
    encode_disposition(encoder, &core.disposition);
}

fn decode_launch_core(
    decoder: &mut CborDecoder<'_>,
) -> Result<EnrollmentLaunchCoreV3, DecodeError> {
    if decoder.read_map_header(10)? != 10 {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 1)?;
    let authority_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 2)?;
    let desktop_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 3)?;
    let secret = LaunchSecret::from_bytes(decode_fixed::<32>(decoder)?)
        .map_err(|_| DecodeError::UnknownField { key: 3 })?;
    expect_key(decoder, 4)?;
    let issued = decoder.read_unsigned(u64::MAX)?;
    expect_key(decoder, 5)?;
    let expires = decoder.read_unsigned(u64::MAX)?;
    expect_key(decoder, 6)?;
    let principal = decoder
        .read_text_string(MAX_PRINCIPAL_ID_BYTES)?
        .to_owned();
    expect_key(decoder, 7)?;
    let profile = decode_profile(decoder)?;
    expect_key(decoder, 8)?;
    let executable = decode_executable(decoder)?;
    expect_key(decoder, 9)?;
    let runtime_root = PathBuf::from(decoder.read_text_string(MAX_TEXT_BYTES)?);
    expect_key(decoder, 10)?;
    let disposition = decode_disposition(decoder)?;
    let value = ProtectedLaunchRequestV1::new(
        authority_id,
        desktop_id,
        secret,
        issued,
        expires,
        principal,
        profile,
        executable,
        runtime_root,
        disposition,
    )
    .map_err(|_| DecodeError::UnknownField { key: 2 })?;
    Ok(EnrollmentLaunchCoreV3::from_v1(value))
}

fn encode_owned_core(encoder: &mut CborEncoder, core: &EnrollmentOwnedCoreV3) {
    encoder.write_map_header(8);
    write_key(encoder, 1);
    encoder.write_byte_string(&core.authority_id);
    write_key(encoder, 2);
    encoder.write_byte_string(&core.desktop_id);
    write_key(encoder, 3);
    encode_executable(encoder, &core.executable);
    write_key(encoder, 4);
    encode_profile(encoder, &core.profile);
    write_key(encoder, 5);
    encode_stable(encoder, &core.stable);
    write_key(encoder, 6);
    encoder.write_byte_string(&core.daemon_id);
    write_key(encoder, 7);
    encoder.write_unsigned(core.generation);
    write_key(encoder, 8);
    encoder.write_byte_string(&core.session_id);
}

fn decode_owned_core(decoder: &mut CborDecoder<'_>) -> Result<EnrollmentOwnedCoreV3, DecodeError> {
    if decoder.read_map_header(8)? != 8 {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 1)?;
    let authority = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 2)?;
    let desktop = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 3)?;
    let executable = decode_executable(decoder)?;
    expect_key(decoder, 4)?;
    let profile = decode_profile(decoder)?;
    expect_key(decoder, 5)?;
    let stable = decode_stable(decoder)?;
    expect_key(decoder, 6)?;
    let daemon = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 7)?;
    let generation = decoder.read_unsigned(u64::MAX)?;
    expect_key(decoder, 8)?;
    let session = decode_fixed::<16>(decoder)?;
    EnrollmentOwnedCoreV3::new(
        authority, desktop, executable, profile, stable, daemon, generation, session,
    )
    .map_err(|_| DecodeError::UnknownField { key: 2 })
}

fn encode_v3_frame<T: DeterministicCodec>(value: &T) -> Result<Vec<u8>, EncodeError> {
    encode_codec_frame(
        value,
        &FrameLimits {
            max_frame_bytes: MAX_FRAME_BYTES,
        },
    )
}

fn decode_v3_frame<T: DeterministicCodec>(frame: &[u8]) -> Result<T, DecodeError> {
    decode_codec_frame(frame, &decode_limits())
}
