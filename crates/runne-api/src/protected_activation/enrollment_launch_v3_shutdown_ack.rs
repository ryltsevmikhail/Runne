#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialEnrollmentShutdownAckV3 {
    owned: ProtectedCredentialEnrollmentOwnedLaunchV3,
    graceful: bool,
    proof: [u8; 32],
}

impl ProtectedCredentialEnrollmentShutdownAckV3 {
    #[must_use]
    pub const fn new(owned: ProtectedCredentialEnrollmentOwnedLaunchV3, graceful: bool) -> Self {
        Self {
            owned,
            graceful,
            proof: [0; 32],
        }
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V3,
            PROTOCOL_SCHEMA_VERSION_V3,
            &self.unsigned(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.owned.exact(expected)?;
        let expected_proof = authenticated_mac_version(
            keys.shutdown_key_ref(),
            SHUTDOWN_DOMAIN_V3,
            PROTOCOL_SCHEMA_VERSION_V3,
            &self.unsigned(),
        );
        if !bool::from(expected_proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub const fn owned_launch(&self) -> &ProtectedCredentialEnrollmentOwnedLaunchV3 {
        &self.owned
    }

    #[must_use]
    pub const fn graceful(&self) -> bool {
        self.graceful
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_v3_frame(self)
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_v3_frame(frame)
    }

    fn unsigned(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false);
        encoder.into_bytes()
    }

    fn encode_fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 7 } else { 6 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(PROTOCOL_SCHEMA_VERSION_V3));
        write_key(encoder, 2);
        encode_owned_core(encoder, &self.owned.core);
        write_key(encoder, 3);
        encode_provider_binding(encoder, &self.owned.provider);
        write_key(encoder, 4);
        encode_enrollment_binding(encoder, &self.owned.enrollment);
        write_key(encoder, 5);
        encoder.write_bool(self.graceful);
        if include_proof {
            write_key(encoder, 6);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedCredentialEnrollmentShutdownAckV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedCredentialEnrollmentShutdownAckV3(<redacted>)")
    }
}

impl DeterministicCodec for ProtectedCredentialEnrollmentShutdownAckV3 {
    const MESSAGE_TYPE_ID: u32 = 32;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(7)? != 7 {
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
        let graceful = decoder.read_bool()?;
        expect_key(decoder, 6)?;
        let proof = decode_fixed::<32>(decoder)?;
        Ok(Self {
            owned: ProtectedCredentialEnrollmentOwnedLaunchV3 {
                core,
                provider,
                enrollment,
            },
            graceful,
            proof,
        })
    }
}
