/// Monotonic protected request for one replacement HTTP session authority.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedRenewRequestV1 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV1,
    sequence: u64,
    nonce: [u8; 32],
    proof: [u8; 32],
}

impl ProtectedRenewRequestV1 {
    /// Builds an unsigned renewal request.
    pub fn new(
        owned_launch: ProtectedOwnedLaunchV1,
        sequence: u64,
        nonce: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        if sequence == 0 || nonce == [0; 32] {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            owned_launch,
            sequence,
            nonce,
            proof: [0; 32],
        })
    }

    /// Signs the exact canonical renewal transcript.
    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac(
            keys.renewal_key_ref(),
            RENEW_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    /// Verifies exact ownership, strictly next sequence, and proof.
    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV1,
        last_sequence: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if &self.owned_launch != expected {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        if self.sequence != last_sequence.saturating_add(1) || self.nonce == [0; 32] {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        let expected_proof = authenticated_mac(
            keys.renewal_key_ref(),
            RENEW_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(expected_proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    pub const fn owned_launch(&self) -> &ProtectedOwnedLaunchV1 {
        &self.owned_launch
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
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
        encoder.write_map_header(if include_proof { 6 } else { 5 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encode_owned_launch(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_unsigned(self.sequence);
        write_key(encoder, 4);
        encoder.write_byte_string(&self.nonce);
        if include_proof {
            write_key(encoder, 5);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedRenewRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedRenewRequestV1")
            .field("sequence", &self.sequence)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedRenewRequestV1 {
    const MESSAGE_TYPE_ID: u32 = 3;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(6)? != 6 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema(decoder)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch(decoder)?;
        expect_key(decoder, 3)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 4)?;
        let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 5)?;
        let proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(owned_launch, sequence, nonce)
            .map_err(|_| DecodeError::UnknownField { key: 4 })?;
        value.proof = proof;
        Ok(value)
    }
}
