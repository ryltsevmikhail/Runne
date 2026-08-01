impl DeterministicCodec for ProtectedReadyV1 {
    const MESSAGE_TYPE_ID: u32 = 2;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true)
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(15)? != 15 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_key(decoder, 1)?;
        if decoder.read_unsigned(u64::from(u32::MAX))? != u64::from(PROTOCOL_SCHEMA_VERSION) {
            return Err(DecodeError::UnknownField { key: 1 });
        }
        expect_key(decoder, 2)?;
        let launch_authority_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?;
        let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?;
        let executable = decode_executable(decoder)?;
        expect_key(decoder, 5)?;
        let profile = decode_profile(decoder)?;
        expect_key(decoder, 6)?;
        let stable = decode_stable(decoder)?;
        expect_key(decoder, 7)?;
        let daemon_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 8)?;
        let launch_generation = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 9)?;
        let session_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 10)?;
        let endpoint = decoder.read_text_string(MAX_TEXT_BYTES)?.to_owned();
        expect_key(decoder, 11)?;
        let certificate_sha256 = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 12)?;
        let certificate_der = decoder
            .read_byte_string(MAX_CERTIFICATE_DER_BYTES)?
            .to_vec();
        expect_key(decoder, 13)?;
        let count = usize::try_from(decoder.read_array_header(MAX_CAPABILITIES as u32)?)
            .map_err(|_| DecodeError::UnknownField { key: 13 })?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned());
        }
        expect_key(decoder, 14)?;
        let readiness_proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(
            launch_authority_id,
            desktop_host_instance_id,
            executable,
            profile,
            stable,
            daemon_instance_id,
            launch_generation,
            session_id,
            endpoint,
            certificate_sha256,
            certificate_der,
            capabilities,
        )
        .map_err(|_| DecodeError::UnknownField { key: 14 })?;
        value.readiness_proof = readiness_proof;
        Ok(value)
    }
}
