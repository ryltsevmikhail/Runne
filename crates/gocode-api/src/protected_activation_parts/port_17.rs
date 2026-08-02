
impl ProtectedShutdownV2 {
    #[must_use]
    pub const fn new(owned_launch: ProtectedOwnedLaunchV2) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            proof: [0; 32],
        }
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.owned_launch.verify_exact(expected)?;
        let proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn owned_launch(&self) -> &ProtectedOwnedLaunchV2 {
        &self.owned_launch
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 4 } else { 3 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch_v2(encoder, &self.owned_launch);
        if include_proof {
            write_key(encoder, 3);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedShutdownV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedShutdownV2")
            .field("provider_binding", self.owned_launch.provider_binding())
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedShutdownV2 {
    const MESSAGE_TYPE_ID: u32 = 25;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(4)? != 4 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch_v2(decoder)?;
        expect_key(decoder, 3)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            proof,
        })
    }
}

/// V2 acknowledgement that the exact provider-bound launch accepted shutdown.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedShutdownAckV2 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV2,
    graceful: bool,
    proof: [u8; 32],
}

impl ProtectedShutdownAckV2 {
    #[must_use]
    pub const fn new(owned_launch: ProtectedOwnedLaunchV2, graceful: bool) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            owned_launch,
            graceful,
            proof: [0; 32],
        }
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.owned_launch.verify_exact(expected)?;
        let proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn graceful(&self) -> bool {
        self.graceful
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 5 } else { 4 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch_v2(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_bool(self.graceful);
        if include_proof {
            write_key(encoder, 4);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedShutdownAckV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedShutdownAckV2")
            .field("graceful", &self.graceful)
            .field("provider_binding", self.owned_launch.provider_binding())
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}
