const ENROLLMENT_TRANSITION_PRELUDE_DOMAIN_V2: &[u8] =
    b"gocode/credential-enrollment-transition/prelude/v2";

/// Daemon evidence binding one exact V2 prepare transcript to a V3 prelude.
///
/// The symmetric envelope authenticates current V2 session membership, not a
/// daemon role. The embedded prelude remains evidence, not launch authority;
/// the coordinator must independently mint every daemon-owned state change.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialEnrollmentPreludeV2 {
    owned_launch: ProtectedOwnedLaunchV2,
    sequence: u64,
    nonce: [u8; 32],
    request_digest: [u8; 32],
    prelude: DaemonEnrollmentLaunchPreludeV1,
    proof: [u8; 32],
}

impl ProtectedCredentialEnrollmentPreludeV2 {
    pub fn new(
        request: &ProtectedCredentialEnrollmentPrepareV2,
        nonce: [u8; 32],
        prelude: DaemonEnrollmentLaunchPreludeV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if nonce == [0; 32] || !prelude_matches_request(&prelude, request) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(Self {
            owned_launch: request.owned_launch.clone(),
            sequence: request.sequence,
            nonce,
            request_digest: enrollment_transition_prepare_digest(request),
            prelude,
            proof: [0; 32],
        })
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            ENROLLMENT_TRANSITION_PRELUDE_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned(),
        );
    }

    pub fn verify_exact_at(
        &self,
        request: &ProtectedCredentialEnrollmentPrepareV2,
        expected: &ProtectedOwnedLaunchV2,
        last_sequence: u64,
        now_unix_millis: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        request.verify_exact(expected, last_sequence, keys)?;
        self.owned_launch.verify_exact(&request.owned_launch)?;
        if self.sequence != request.sequence
            || self.request_digest != enrollment_transition_prepare_digest(request)
            || self.nonce == [0; 32]
            || !prelude_matches_request(&self.prelude, request)
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let proof = authenticated_mac_version(
            keys.renewal_key_ref(),
            ENROLLMENT_TRANSITION_PRELUDE_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned(),
        );
        if !bool::from(proof.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        self.prelude.validate_freshness(now_unix_millis)?;
        Ok(())
    }

    #[must_use]
    pub const fn prelude(&self) -> &DaemonEnrollmentLaunchPreludeV1 {
        &self.prelude
    }

    #[must_use]
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
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

    fn fields(&self, encoder: &mut CborEncoder, include_proof: bool) {
        encoder.write_map_header(if include_proof { 8 } else { 7 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(PROTOCOL_SCHEMA_VERSION_V2));
        write_key(encoder, 2);
        encode_owned_launch_v2(encoder, &self.owned_launch);
        write_key(encoder, 3);
        encoder.write_unsigned(self.sequence);
        write_key(encoder, 4);
        encoder.write_byte_string(&self.nonce);
        write_key(encoder, 5);
        encoder.write_byte_string(&self.request_digest);
        write_key(encoder, 6);
        self.prelude
            .encode(encoder)
            .expect("valid prelude encoding");
        if include_proof {
            write_key(encoder, 7);
            encoder.write_byte_string(&self.proof);
        }
    }
}

fn prelude_matches_request(
    prelude: &DaemonEnrollmentLaunchPreludeV1,
    request: &ProtectedCredentialEnrollmentPrepareV2,
) -> bool {
    prelude.launch_authority_id() == *request.owned_launch.launch_authority_id()
        && prelude.desktop_host_instance_id() == *request.owned_launch.desktop_host_instance_id()
        && prelude.installation_identity_digest() == request.installation_identity_digest()
        && prelude.desktop_peer_binding_digest() == request.desktop_peer_binding_digest()
        && prelude.supervisor_generation() == request.desktop_supervisor_generation()
}

impl fmt::Debug for ProtectedCredentialEnrollmentPreludeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedCredentialEnrollmentPreludeV2(<redacted>)")
    }
}

impl DeterministicCodec for ProtectedCredentialEnrollmentPreludeV2 {
    const MESSAGE_TYPE_ID: u32 = 35;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.fields(encoder, true);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(8)? != 8 {
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
        let request_digest = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 6)?;
        let prelude = DaemonEnrollmentLaunchPreludeV1::decode(
            DaemonEnrollmentLaunchPreludeV1::MESSAGE_TYPE_ID,
            decoder,
        )?;
        expect_key(decoder, 7)?;
        let proof = decode_fixed::<32>(decoder)?;
        if sequence == 0
            || nonce == [0; 32]
            || request_digest == [0; 32]
            || prelude.launch_authority_id() != *owned_launch.launch_authority_id()
            || prelude.desktop_host_instance_id()
                != *owned_launch.desktop_host_instance_id()
        {
            return Err(DecodeError::UnknownField { key: 6 });
        }
        Ok(Self {
            owned_launch,
            sequence,
            nonce,
            request_digest,
            prelude,
            proof,
        })
    }
}
