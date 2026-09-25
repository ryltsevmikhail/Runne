const ENROLLMENT_TRANSITION_PREPARE_DOMAIN_V2: &[u8] =
    b"gocode/credential-enrollment-transition/prepare/v2";
const ENROLLMENT_TRANSITION_REQUEST_BINDING_DOMAIN_V2: &[u8] =
    b"gocode/credential-enrollment-transition/request-binding/v2";
const ENROLLMENT_TRANSITION_SCHEMA_V3: u32 = 3;

/// Authenticated Desktop claims for an exact current V2 enrollment transition.
///
/// These release, qualification, and peer digests are claims only. Their
/// decoding or MAC verification grants no native qualification or launch
/// authority; the daemon must independently verify each native fact. The
/// installation anchor remains daemon-owned and exists only in its prelude.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialEnrollmentPrepareV2 {
    owned_launch: ProtectedOwnedLaunchV2,
    sequence: u64,
    nonce: [u8; 32],
    release_tuple_digest: [u8; 32],
    qualification_binding_digest: [u8; 32],
    desktop_peer_binding_digest: [u8; 32],
    desktop_supervisor_generation: u64,
    schema_version: u32,
    resource_directory_hint: Option<String>,
    proof: [u8; 32],
}

impl ProtectedCredentialEnrollmentPrepareV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owned_launch: ProtectedOwnedLaunchV2,
        sequence: u64,
        nonce: [u8; 32],
        release_tuple_digest: [u8; 32],
        qualification_binding_digest: [u8; 32],
        desktop_peer_binding_digest: [u8; 32],
        desktop_supervisor_generation: u64,
    ) -> Result<Self, LaunchAuthorityError> {
        if sequence == 0
            || nonce == [0; 32]
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
            release_tuple_digest,
            qualification_binding_digest,
            desktop_peer_binding_digest,
            desktop_supervisor_generation,
            schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            resource_directory_hint: None,
            proof: [0; 32],
        })
    }

    /// Adds the authenticated Linux bundle resource locator. It is a locator
    /// only; the daemon must verify it against the authenticated peer and
    /// signed installed tuple before deriving any writer artifact.
    pub fn with_resource_directory_hint(
        mut self,
        hint: &str,
    ) -> Result<Self, LaunchAuthorityError> {
        if hint.len() > MAX_TEXT_BYTES
            || !valid_text(hint, MAX_TEXT_BYTES)
            || !std::path::Path::new(hint).is_absolute()
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.schema_version = ENROLLMENT_TRANSITION_SCHEMA_V3;
        self.resource_directory_hint = Some(hint.to_owned());
        Ok(self)
    }

    #[must_use]
    pub fn resource_directory_hint(&self) -> Option<&str> {
        self.resource_directory_hint.as_deref()
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            ENROLLMENT_TRANSITION_PREPARE_DOMAIN_V2,
            self.schema_version,
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
            self.schema_version,
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
        let extended = self.resource_directory_hint.is_some();
        encoder.write_map_header(9 + u64::from(include_proof) + u64::from(extended));
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.schema_version));
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
        if let Some(hint) = &self.resource_directory_hint {
            write_key(encoder, 9);
            encoder.write_text_string(hint);
        }
        if include_proof {
            write_key(encoder, if extended { 10 } else { 9 });
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
        if type_id != Self::MESSAGE_TYPE_ID {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        let map_len = decoder.read_map_header(11)?;
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_key(decoder, 1)?;
        let schema_version = u32::try_from(decoder.read_unsigned(u64::from(u32::MAX))?)
            .map_err(|_| DecodeError::UnknownField { key: 1 })?;
        let extended = match (schema_version, map_len) {
            (PROTOCOL_SCHEMA_VERSION_V2, 10) => false,
            (ENROLLMENT_TRANSITION_SCHEMA_V3, 11) => true,
            _ => return Err(DecodeError::UnknownField { key: 1 }),
        };
        expect_key(decoder, 2)?;
        let owned_launch = decode_owned_launch_v2(decoder)?;
        expect_key(decoder, 3)?;
        let sequence = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 4)?;
        let nonce = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 5)?;
        let release = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 6)?;
        let qualification = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 7)?;
        let peer = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 8)?;
        let generation = decoder.read_unsigned(u64::MAX)?;
        let resource_directory_hint = if extended {
            expect_key(decoder, 9)?;
            let hint = decoder.read_text_string(MAX_TEXT_BYTES)?.to_owned();
            if !valid_text(&hint, MAX_TEXT_BYTES) || !std::path::Path::new(&hint).is_absolute() {
                return Err(DecodeError::UnknownField { key: 9 });
            }
            Some(hint)
        } else {
            None
        };
        expect_key(decoder, if extended { 10 } else { 9 })?;
        let proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(
            owned_launch,
            sequence,
            nonce,
            release,
            qualification,
            peer,
            generation,
        )
        .map_err(|_| DecodeError::UnknownField { key: 3 })?;
        value.schema_version = schema_version;
        value.resource_directory_hint = resource_directory_hint;
        value.proof = proof;
        Ok(value)
    }
}

fn enrollment_transition_prepare_digest(
    request: &ProtectedCredentialEnrollmentPrepareV2,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ENROLLMENT_TRANSITION_REQUEST_BINDING_DOMAIN_V2);
    hasher.update(request.schema_version.to_be_bytes());
    hasher.update(request.transcript());
    hasher.finalize().into()
}
