
impl DeterministicCodec for ProtectedLaunchRequestV1 {
    const MESSAGE_TYPE_ID: u32 = 1;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        encoder.write_map_header(12);
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encoder.write_byte_string(&self.launch_authority_id);
        write_key(encoder, 3);
        encoder.write_byte_string(&self.desktop_host_instance_id);
        write_key(encoder, 4);
        encoder.write_byte_string(self.launch_secret.as_bytes());
        write_key(encoder, 5);
        encoder.write_unsigned(self.issued_at_unix_millis);
        write_key(encoder, 6);
        encoder.write_unsigned(self.expires_at_unix_millis);
        write_key(encoder, 7);
        encoder.write_text_string(&self.principal_id);
        write_key(encoder, 8);
        encode_profile(encoder, &self.profile);
        write_key(encoder, 9);
        encode_executable(encoder, &self.executable);
        write_key(encoder, 10);
        encoder.write_text_string(
            self.runtime_root
                .to_str()
                .expect("validated UTF-8 runtime root"),
        );
        write_key(encoder, 11);
        encode_disposition(encoder, &self.activation_disposition);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(12)? != 12 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_key(decoder, 1)?;
        let schema = decoder.read_unsigned(u64::from(u32::MAX))?;
        if schema != u64::from(PROTOCOL_SCHEMA_VERSION) {
            return Err(DecodeError::UnknownField { key: 1 });
        }
        expect_key(decoder, 2)?;
        let launch_authority_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?;
        let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?;
        let launch_secret = LaunchSecret::from_bytes(decode_fixed::<32>(decoder)?)
            .map_err(|_| DecodeError::UnknownField { key: 4 })?;
        expect_key(decoder, 5)?;
        let issued_at_unix_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 6)?;
        let expires_at_unix_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 7)?;
        let principal_id = decoder.read_text_string(MAX_PRINCIPAL_ID_BYTES)?.to_owned();
        expect_key(decoder, 8)?;
        let profile = decode_profile(decoder)?;
        expect_key(decoder, 9)?;
        let executable = decode_executable(decoder)?;
        expect_key(decoder, 10)?;
        let runtime_root = PathBuf::from(decoder.read_text_string(MAX_TEXT_BYTES)?);
        expect_key(decoder, 11)?;
        let activation_disposition = decode_disposition(decoder)?;
        Self::new(
            launch_authority_id,
            desktop_host_instance_id,
            launch_secret,
            issued_at_unix_millis,
            expires_at_unix_millis,
            principal_id,
            profile,
            executable,
            runtime_root,
            activation_disposition,
        )
        .map_err(|_| DecodeError::UnknownField { key: 11 })
    }
}

/// Runtime-prepared non-secret first-activation record with exact HMAC proof.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedFirstActivationPreparedV1 {
    protocol_schema_version: u32,
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    pending: PendingFirstActivationV1,
    proof: [u8; 32],
}

impl ProtectedFirstActivationPreparedV1 {
    /// Builds an unsigned prepared response.
    #[must_use]
    pub const fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        pending: PendingFirstActivationV1,
    ) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            launch_authority_id,
            desktop_host_instance_id,
            pending,
            proof: [0; 32],
        }
    }

    /// Signs the exact canonical prepare transcript.
    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.readiness_key(),
            FIRST_ACTIVATION_PREPARE_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    /// Verifies request binding, prepared identity, and HMAC.
    pub fn verify_exact(
        &self,
        request: &ProtectedLaunchRequestV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if self.launch_authority_id != request.launch_authority_id
            || self.desktop_host_instance_id != request.desktop_host_instance_id
        {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        if self.pending.executable != request.executable || self.pending.profile != request.profile
        {
            return Err(LaunchAuthorityError::FirstActivationPreparationMismatch);
        }
        match request.activation_disposition() {
            ActivationDispositionV1::FirstActivation => {}
            ActivationDispositionV1::ResumeFirstActivation(expected)
                if expected.as_ref() == &self.pending => {}
            _ => return Err(LaunchAuthorityError::FirstActivationPreparationMismatch),
        }
        let expected = authenticated_mac(
            keys.readiness_key(),
            FIRST_ACTIVATION_PREPARE_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    /// Returns the durable non-secret record after proof verification.
    pub const fn pending(&self) -> &PendingFirstActivationV1 {
        &self.pending
    }

    /// Encodes the deterministic bounded prepare frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    /// Decodes one deterministic bounded prepare frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 6 } else { 5 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encoder.write_byte_string(&self.launch_authority_id);
        write_key(encoder, 3);
        encoder.write_byte_string(&self.desktop_host_instance_id);
        write_key(encoder, 4);
        encode_pending(encoder, &self.pending);
        if include_proof {
            write_key(encoder, 5);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedFirstActivationPreparedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedFirstActivationPreparedV1")
            .field("protocol_schema_version", &self.protocol_schema_version)
            .field("pending", &self.pending)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}
