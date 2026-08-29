const ENROLLMENT_TRANSITION_PREPARE_DOMAIN_V2: &[u8] =
    b"gocode/credential-enrollment-transition/prepare/v2";
const ENROLLMENT_TRANSITION_REQUEST_BINDING_DOMAIN_V2: &[u8] =
    b"gocode/credential-enrollment-transition/request-binding/v2";

/// Authenticated Desktop claims for an exact current V2 enrollment transition.
///
/// These release, qualification, installation, and peer digests are claims
/// only. Their decoding or MAC verification grants no native qualification or
/// launch authority; the daemon must independently verify each native fact.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialEnrollmentPrepareV2 {
    owned_launch: ProtectedOwnedLaunchV2,
    sequence: u64,
    nonce: [u8; 32],
    installation_identity_digest: [u8; 32],
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
    desktop_peer_binding_digest: [u8; 32],
    desktop_supervisor_generation: u64,
    proof: [u8; 32],
}

impl ProtectedCredentialEnrollmentPrepareV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owned_launch: ProtectedOwnedLaunchV2,
        sequence: u64,
        nonce: [u8; 32],
        installation_identity_digest: [u8; 32],
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        desktop_supervisor_generation: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if sequence == 0
            || nonce == [0; 32]
            || installation_identity_digest == [0; 32]
            || release_tuple_digest == [0; 32]
            || qualification_binding_digest == [0; 32]
            || desktop_peer_binding_digest == [0; 32]
            || desktop_supervisor_generation == 0
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            owned_launch,
            sequence,
            nonce,
            installation_identity_digest,
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            proof: [0; 32],
        })
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            ENROLLMENT_TRANSITION_PREPARE_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned(),
        );
    }

    pub fn verify_exact(
        &self,
        expected: &ProtectedOwnedLaunchV2,
        last_sequence: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.owned_launch.verify_exact(expected)?;
        if self.sequence
            != last_sequence
                .checked_add(1)
                .ok_or(LaunchAuthorityError::RenewalReplay)?
        {
            return Err(LaunchAuthorityError::RenewalReplay);
        }
        let proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            ENROLLMENT_TRANSITION_PREPARE_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned(),
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

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    #[must_use]
    pub const fn installation_identity_digest(&self) -> &[u8; 32] {
        &self.installation_identity_digest
    }

    #[must_use]
    pub const fn release_tuple_digest(&self) -> &[u8; 32] {
        &self.release_tuple_digest
    }

    #[must_use]
    pub const fn qualification_binding_digest(&self) -> &[u8; 32] {
        &self.qualification_binding_digest
    }

    #[must_use]
    pub const fn desktop_peer_binding_digest(&self) -> &[u8; 32] {
        &self.desktop_peer_binding_digest
    }

    #[must_use]
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.desktop_supervisor_generation
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

    fn transcript(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.fields(&mut encoder, true);
        encoder.into_bytes()
    }

    fn fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 11 } else { 10 });
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
            (5, &self.installation_identity_digest),
            (6, &self.release_tuple_digest),
            (7, &self.qualification_binding_digest),
            (8, &self.desktop_peer_binding_digest),
        ] {
            write_key(encoder, key);
            encoder.write_byte_string(value);
        }
        write_key(encoder, 9);
        encoder.write_unsigned(self.desktop_supervisor_generation);
        if include_proof {
            write_key(encoder, 10);
            encoder.write_byte_string(&self.proof);
        }
    }
}

impl fmt::Debug for ProtectedCredentialEnrollmentPrepareV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedCredentialEnrollmentPrepareV2(<redacted>)")
    }
}

impl DeterministicCodec for ProtectedCredentialEnrollmentPrepareV2 {
    const MESSAGE_TYPE_ID: u32 = 34;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(11)? != 11 {
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
        let installation = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 6)?;
        let release = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 7)?;
        let qualification = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 8)?;
        let peer = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 9)?;
        let generation = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 10)?;
        let proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(
            owned_launch,
            sequence,
            nonce,
            installation,
            release,
            qualification,
            peer,
            generation,
        )
        .map_err(|_| DecodeError::UnknownField { key: 3 })?;
        value.proof = proof;
        Ok(value)
    }
}

fn enrollment_transition_prepare_digest(
    request: &ProtectedCredentialEnrollmentPrepareV2,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ENROLLMENT_TRANSITION_REQUEST_BINDING_DOMAIN_V2);
    hasher.update(PROTOCOL_SCHEMA_VERSION_V2.to_be_bytes());
    hasher.update(request.transcript());
    hasher.finalize().into()
}
