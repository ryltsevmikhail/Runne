fn encode_enrollment_binding(
    encoder: &mut CborEncoder,
    binding: &ProtectedCredentialEnrollmentLaunchBindingV1,
) {
    encoder.write_map_header(8);
    write_key(encoder, 1);
    encoder.write_unsigned(binding.platform as u64);
    write_key(encoder, 2);
    encoder.write_unsigned(binding.architecture as u64);
    for (key, value) in [
        (3, &binding.installation_identity_digest),
        (4, &binding.release_tuple_digest),
        (5, &binding.qualification_binding_digest),
        (6, &binding.desktop_peer_binding_digest),
    ] {
        write_key(encoder, key);
        encoder.write_byte_string(value);
    }
    write_key(encoder, 7);
    encoder.write_unsigned(binding.desktop_supervisor_generation);
    write_key(encoder, 8);
    encoder.write_byte_string(&binding.broker_transfer_commitment.0);
}

fn decode_enrollment_binding(
    decoder: &mut CborDecoder<'_>,
) -> Result<ProtectedCredentialEnrollmentLaunchBindingV1, DecodeError> {
    if decoder.read_map_header(8)? != 8 {
        return Err(DecodeError::UnknownField { key: 12 });
    }
    expect_key(decoder, 1)?;
    let platform = decoder.read_unsigned(2)?;
    if platform != EnrollmentPlatformV1::Macos as u64
        && platform != EnrollmentPlatformV1::Linux as u64
    {
        return Err(DecodeError::UnknownField { key: 1 });
    }
    expect_key(decoder, 2)?;
    let architecture = decoder.read_unsigned(3)?;
    if architecture != EnrollmentArchitectureV1::AppleSiliconAarch64 as u64
        && architecture != EnrollmentArchitectureV1::Arm64 as u64
        && architecture != EnrollmentArchitectureV1::X86_64 as u64
    {
        return Err(DecodeError::UnknownField { key: 2 });
    }
    expect_key(decoder, 3)?;
    let installation = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 4)?;
    let release = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 5)?;
    let qualification = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 6)?;
    let peer = decode_fixed::<32>(decoder)?;
    expect_key(decoder, 7)?;
    let generation = decoder.read_unsigned(u64::MAX)?;
    expect_key(decoder, 8)?;
    let commitment = decode_fixed::<32>(decoder)?;
    let binding = match platform {
        p if p == EnrollmentPlatformV1::Macos as u64
            && architecture == EnrollmentArchitectureV1::AppleSiliconAarch64 as u64 =>
        {
            ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
                installation,
                release,
                qualification,
                peer,
                generation,
                CredentialBrokerTransferCommitment::from_authenticated_bytes(commitment),
            )
        }
        p if p == EnrollmentPlatformV1::Linux as u64
            && architecture == EnrollmentArchitectureV1::Arm64 as u64 =>
        {
            ProtectedCredentialEnrollmentLaunchBindingV1::linux_arm64(
                installation,
                release,
                qualification,
                peer,
                generation,
                CredentialBrokerTransferCommitment::from_authenticated_bytes(commitment),
            )
        }
        p if p == EnrollmentPlatformV1::Linux as u64
            && architecture == EnrollmentArchitectureV1::X86_64 as u64 =>
        {
            ProtectedCredentialEnrollmentLaunchBindingV1::linux_x86_64(
                installation,
                release,
                qualification,
                peer,
                generation,
                CredentialBrokerTransferCommitment::from_authenticated_bytes(commitment),
            )
        }
        _ => return Err(DecodeError::UnknownField { key: 2 }),
    };
    binding.map_err(|_| DecodeError::UnknownField { key: 12 })
}
