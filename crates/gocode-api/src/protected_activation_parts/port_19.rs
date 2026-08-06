
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

fn encode_disposition(encoder: &mut CborEncoder, disposition: &ActivationDispositionV1) {
    match disposition {
        ActivationDispositionV1::FirstActivation => {
            encoder.write_map_header(1);
            write_key(encoder, 1);
            encoder.write_unsigned(1);
        }
        ActivationDispositionV1::Existing(stable) => {
            encoder.write_map_header(2);
            write_key(encoder, 1);
            encoder.write_unsigned(2);
            write_key(encoder, 2);
            encode_stable(encoder, stable);
        }
        ActivationDispositionV1::ResumeFirstActivation(pending) => {
            encoder.write_map_header(2);
            write_key(encoder, 1);
            encoder.write_unsigned(3);
            write_key(encoder, 2);
            encode_pending(encoder, pending);
        }
    }
}

fn decode_disposition(
    decoder: &mut CborDecoder<'_>,
) -> Result<ActivationDispositionV1, DecodeError> {
    let length = decoder.read_map_header(2)?;
    expect_key(decoder, 1)?;
    match decoder.read_unsigned(3)? {
        1 if length == 1 => Ok(ActivationDispositionV1::FirstActivation),
        2 if length == 2 => {
            expect_key(decoder, 2)?;
            Ok(ActivationDispositionV1::Existing(Box::new(decode_stable(
                decoder,
            )?)))
        }
        3 if length == 2 => {
            expect_key(decoder, 2)?;
            Ok(ActivationDispositionV1::ResumeFirstActivation(Box::new(
                decode_pending(decoder)?,
            )))
        }
        value => Err(DecodeError::UnknownField { key: value }),
    }
}

fn encode_pending(encoder: &mut CborEncoder, pending: &PendingFirstActivationV1) {
    encoder.write_map_header(5);
    write_key(encoder, 1);
    encoder.write_byte_string(&pending.preparation_id);
    write_key(encoder, 2);
    encoder.write_byte_string(&pending.runtime_root_identity);
    write_key(encoder, 3);
    encode_stable(encoder, &pending.stable);
    write_key(encoder, 4);
    encode_executable(encoder, &pending.executable);
    write_key(encoder, 5);
    encode_profile(encoder, &pending.profile);
}

fn decode_pending(decoder: &mut CborDecoder<'_>) -> Result<PendingFirstActivationV1, DecodeError> {
    if decoder.read_map_header(5)? != 5 {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 1)?;
    let preparation_id = decode_fixed::<16>(decoder)?;
    expect_key(decoder, 2)?;
    let runtime_root_identity = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 3)?;
    let stable = decode_stable(decoder)?;
    expect_key(decoder, 4)?;
    let executable = decode_executable(decoder)?;
    expect_key(decoder, 5)?;
    let profile = decode_profile(decoder)?;
    PendingFirstActivationV1::new(
        preparation_id,
        runtime_root_identity,
        stable,
        executable,
        profile,
    )
    .map_err(|_| DecodeError::UnknownField { key: 5 })
}

fn decode_limits() -> DecodeLimits {
    DecodeLimits {
        max_frame_bytes: MAX_FRAME_BYTES,
        max_recursion_depth: 16,
        max_array_items: MAX_CAPABILITIES as u32,
        max_map_items: 32,
        max_text_bytes: MAX_TEXT_BYTES,
        max_byte_string_bytes: MAX_CERTIFICATE_DER_BYTES,
        max_unsigned: u64::MAX,
        min_signed: i64::MIN,
        max_signed: i64::MAX,
        max_string_bytes: MAX_TEXT_BYTES,
        max_nesting_depth: 16,
    }
}

const _: usize = MAX_PAYLOAD_BYTES;
