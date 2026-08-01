/// HMAC-authenticated orderly shutdown request for an exact owned launch.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedShutdownV1 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV1,
    proof: [u8; 32],
}

impl ProtectedShutdownV1 {
    #[must_use]
    pub const fn new(owned_launch: ProtectedOwnedLaunchV1) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            proof: [0; 32],
        }
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if &self.owned_launch != expected {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let proof = authenticated_mac(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    pub const fn owned_launch(&self) -> &ProtectedOwnedLaunchV1 {
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
        encode_owned_launch(encoder, &self.owned_launch);
        if include_proof {
            write_key(encoder, 3);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedShutdownV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedShutdownV1")
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedShutdownV1 {
    const MESSAGE_TYPE_ID: u32 = 5;

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
        expect_schema(decoder)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch(decoder)?;
        expect_key(decoder, 3)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            proof,
        })
    }
}

/// Protected acknowledgement that the exact owned launch accepted shutdown.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedShutdownAckV1 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV1,
    graceful: bool,
    proof: [u8; 32],
}

impl ProtectedShutdownAckV1 {
    #[must_use]
    pub const fn new(owned_launch: ProtectedOwnedLaunchV1, graceful: bool) -> Self {
        Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            graceful,
            proof: [0; 32],
        }
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if &self.owned_launch != expected {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let proof = authenticated_mac(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

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
        encode_owned_launch(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_bool(self.graceful);
        if include_proof {
            write_key(encoder, 4);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedShutdownAckV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedShutdownAckV1")
            .field("graceful", &self.graceful)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedShutdownAckV1 {
    const MESSAGE_TYPE_ID: u32 = 6;

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
        expect_schema(decoder)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch(decoder)?;
        expect_key(decoder, 3)?;
        let graceful = decoder.read_bool()?;
        expect_key(decoder, 4)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            graceful,
            proof,
        })
    }
}
