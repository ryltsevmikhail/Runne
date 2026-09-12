/// Distinct authenticated read-only status frame. It copies V2 claims but never
/// serializes the transition prepare proof, so it cannot enter that protocol.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialStatusRequestV2 {
    owned_launch: ProtectedOwnedLaunchV2,
    sequence: u64,
    nonce: [u8; 32],
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
    desktop_peer_binding_digest: [u8; 32],
    desktop_supervisor_generation: u64,
    proof: [u8; 32],
}

impl ProtectedCredentialStatusRequestV2 {
    /// Validates the signed prepare in memory before deriving this independent frame.
    pub fn new(
        prepare: ProtectedCredentialEnrollmentPrepareV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<Self, LaunchAuthorityError> {
        let prior = prepare
            .sequence()
            .checked_sub(1)
            .ok_or(LaunchAuthorityError::RenewalReplay)?;
        prepare.verify_exact(prepare.owned_launch(), prior, keys)?;
        let mut request = Self {
            owned_launch: prepare.owned_launch().clone(),
            sequence: prepare.sequence(),
            nonce: *prepare.nonce(),
            release_tuple_digest: *prepare.release_tuple_digest(),
            qualification_binding_digest: *prepare.qualification_binding_digest(),
            desktop_peer_binding_digest: *prepare.desktop_peer_binding_digest(),
            desktop_supervisor_generation: prepare.desktop_supervisor_generation(),
            proof: [0; 32],
        };
        request.sign(keys);
        Ok(request)
    }

    fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            CREDENTIAL_STATUS_REQUEST_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned(),
        );
    }

    /// `sequence` is status-specific and may advance over gaps, but never replay.
    pub fn verify_exact_view<'a>(
        &'a self,
        expected: &ProtectedOwnedLaunchV2,
        last_sequence: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<VerifiedProtectedCredentialStatusRequestV2<'a>, LaunchAuthorityError> {
        self.owned_launch.verify_exact(expected)?;
        if self.sequence <= last_sequence {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        let proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            CREDENTIAL_STATUS_REQUEST_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(VerifiedProtectedCredentialStatusRequestV2 {
            request: self,
            prepare_claims:
                VerifiedProtectedCredentialEnrollmentPrepareV2::from_verified_status_claims(
                    self.release_tuple_digest,
                    self.qualification_binding_digest,
                    self.desktop_peer_binding_digest,
                    self.desktop_supervisor_generation,
                    *self.owned_launch.launch_authority_id(),
                    *self.owned_launch.desktop_host_instance_id(),
                ),
        })
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
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

    fn unsigned(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.fields(&mut encoder, false);
        encoder.into_bytes()
    }

    pub(super) fn transcript(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.fields(&mut encoder, true);
        encoder.into_bytes()
    }

    fn fields(&self, encoder: &mut CborEncoder, proof: bool) {
        encoder.write_map_header(if proof { 10 } else { 9 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(PROTOCOL_SCHEMA_VERSION_V2));
        write_key(encoder, 2);
        encode_owned_launch_v2(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_unsigned(self.sequence);
        for (key, value) in [
            (4, &self.nonce),
            (5, &self.release_tuple_digest),
            (6, &self.qualification_binding_digest),
            (7, &self.desktop_peer_binding_digest),
        ] {
            write_key(encoder, key);
            encoder.write_byte_string(value);
        }
        write_key(encoder, 8);
        encoder.write_unsigned(self.desktop_supervisor_generation);
        if proof {
            write_key(encoder, 9);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl std::fmt::Debug for ProtectedCredentialStatusRequestV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedCredentialStatusRequestV2(<redacted>)")
    }
}

impl DeterministicCodec for ProtectedCredentialStatusRequestV2 {
    const MESSAGE_TYPE_ID: u32 = 36;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(10)? != 10 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch_v2(decoder)?;
        expect_key(decoder, 3)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 4)?;
        let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 5)?;
        let release_tuple_digest = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 6)?;
        let qualification_binding_digest = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 7)?;
        let desktop_peer_binding_digest = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 8)?;
        let desktop_supervisor_generation = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 9)?;
        let proof = decode_fixed::<32>(decoder)?;
        if sequence == 0
            || nonce == [0; 32]
            || release_tuple_digest == [0; 32]
            || qualification_binding_digest == [0; 32]
            || desktop_peer_binding_digest == [0; 32]
            || desktop_supervisor_generation == 0
        {
            return Err(DecodeError::UnknownField { key: 3 });
        }
        Ok(Self {
            owned_launch,
            sequence,
            nonce,
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            proof,
        })
    }
}
