impl DeterministicCodec for ProtectedCredentialEnrollmentReadyV3 {
    const MESSAGE_TYPE_ID: u32 = 28;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.fields(encoder, true)
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(12)? != 12 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V3)?;
        expect_key(decoder, 2)?;
        let core = decode_owned_core(decoder)?;
        expect_key(decoder, 3)?;
        let provider = decode_provider_binding(decoder)?;
        if require_credential_provider(&provider).is_err() {
            return Err(DecodeError::UnknownField { key: 3 });
        }
        expect_key(decoder, 4)?;
        let enrollment = decode_enrollment_binding(decoder)?;
        expect_key(decoder, 5)?;
        let request_digest = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 6)?;
        let readiness = ProviderActivationReadinessV1::from_wire_code(
            decoder.read_unsigned(u64::MAX)?,
        )
        .ok_or(DecodeError::UnknownField { key: 6 })?;
        expect_key(decoder, 7)?;
        let endpoint = decoder.read_text_string(MAX_TEXT_BYTES)?.to_owned();
        expect_key(decoder, 8)?;
        let certificate_sha256 = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 9)?;
        let certificate_der = decoder
            .read_byte_string(MAX_CERTIFICATE_DER_BYTES)?
            .to_vec();
        expect_key(decoder, 10)?;
        let count = decoder.read_array_header(MAX_CAPABILITIES as u32)? as usize;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(
                decoder
                    .read_text_string(MAX_PROFILE_ID_BYTES)?
                    .to_owned(),
            );
        }
        expect_key(decoder, 11)?;
        let proof = decode_fixed::<32>(decoder)?;
        if request_digest == [0; 32]
            || !valid_text(&endpoint, MAX_TEXT_BYTES)
            || certificate_sha256 == [0; 32]
            || certificate_der.is_empty()
            || capabilities.is_empty()
            || capabilities
                .iter()
                .any(|capability| !valid_text(capability, MAX_PROFILE_ID_BYTES))
        {
            return Err(DecodeError::UnknownField { key: 6 });
        }
        Ok(Self {
            core,
            provider,
            enrollment,
            request_digest,
            readiness,
            endpoint,
            certificate_sha256,
            certificate_der,
            capabilities,
            proof,
        })
    }
}
