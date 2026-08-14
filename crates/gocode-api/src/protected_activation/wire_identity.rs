
impl ProtectedReadyV2 {
    pub fn new(
        compatibility_ready: ProtectedReadyV1,
        provider_binding: ProviderActivationBindingV1,
        provider_readiness: ProviderActivationReadinessV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if compatibility_ready.profile.transport_profile_id
            != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            compatibility_ready,
            provider_binding,
            provider_readiness,
            readiness_proof: [0; 32],
        })
    }

    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.compatibility_ready.sign(keys);
        self.readiness_proof = authenticated_mac_version(
            keys.readiness_key(),
            READINESS_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
    }

    pub fn verify_exact(
        &self,
        request: &ProtectedLaunchRequestV2,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.provider_binding
            .verify_exact(request.provider_binding())?;
        self.compatibility_ready
            .verify_exact(request.compatibility_request(), keys)?;
        let expected = authenticated_mac_version(
            keys.readiness_key(),
            READINESS_DOMAIN_V2,
            PROTOCOL_SCHEMA_VERSION_V2,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.readiness_proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
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

    #[must_use]
    pub const fn compatibility_ready(&self) -> &ProtectedReadyV1 {
        &self.compatibility_ready
    }

    #[must_use]
    pub const fn provider_binding(&self) -> &ProviderActivationBindingV1 {
        &self.provider_binding
    }

    #[must_use]
    pub const fn provider_readiness(&self) -> ProviderActivationReadinessV1 {
        self.provider_readiness
    }

    #[must_use]
    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        self.compatibility_ready.stable()
    }

    #[must_use]
    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        self.compatibility_ready.profile()
    }

    #[must_use]
    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        self.compatibility_ready.executable()
    }

    #[must_use]
    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        self.compatibility_ready.daemon_instance_id()
    }

    #[must_use]
    pub const fn launch_generation(&self) -> u64 {
        self.compatibility_ready.launch_generation()
    }

    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        self.compatibility_ready.session_id()
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        self.compatibility_ready.endpoint()
    }

    #[must_use]
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        self.compatibility_ready.certificate_sha256()
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.compatibility_ready.certificate_der()
    }

    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        self.compatibility_ready.capabilities()
    }

    #[must_use]
    pub fn owned_launch(&self) -> ProtectedOwnedLaunchV2 {
        ProtectedOwnedLaunchV2::new(
            self.compatibility_ready.owned_launch(),
            self.provider_binding.clone(),
        )
        .expect("validated V2 readiness has a valid owned-launch tuple")
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false)
            .expect("validated V2 readiness is encodable");
        encoder.into_bytes()
    }

    fn encode_fields(
        &self,
        encoder: &mut CborEncoder,
        include_proof: bool,
    ) -> Result<(), EncodeError> {
        encoder.write_map_header(if include_proof { 6 } else { 5 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        self.compatibility_ready.encode(encoder)?;
        write_key(encoder, 3);
        encode_provider_binding(encoder, &self.provider_binding);
        write_key(encoder, 4);
        encoder.write_unsigned(self.provider_readiness.wire_code());
        if include_proof {
            write_key(encoder, 5);
            encoder.write_byte_string(&self.readiness_proof);
        }
        Ok(())
    }
}

impl fmt::Debug for ProtectedReadyV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedReadyV2")
            .field("launch_generation", &self.launch_generation())
            .field("provider_binding", &self.provider_binding)
            .field("provider_readiness", &self.provider_readiness)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedReadyV2 {
    const MESSAGE_TYPE_ID: u32 = 22;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true)
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(6)? != 6 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let compatibility_ready =
            ProtectedReadyV1::decode(ProtectedReadyV1::MESSAGE_TYPE_ID, decoder)?;
        expect_key(decoder, 3)?;
        let provider_binding = decode_provider_binding(decoder)?;
        expect_key(decoder, 4)?;
        let readiness_code = decoder.read_unsigned(u64::MAX)?;
        let provider_readiness = ProviderActivationReadinessV1::from_wire_code(readiness_code)
            .ok_or(DecodeError::UnknownField { key: 4 })?;
        expect_key(decoder, 5)?;
        let readiness_proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(compatibility_ready, provider_binding, provider_readiness)
            .map_err(|_| DecodeError::UnknownField { key: 3 })?;
        value.readiness_proof = readiness_proof;
        Ok(value)
    }
}

/// Monotonic V2 protected request for one replacement HTTP session authority.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedRenewRequestV2 {
    protocol_schema_version: u32,
    owned_launch: ProtectedOwnedLaunchV2,
    sequence: u64,
    nonce: [u8; 32],
    proof: [u8; 32],
}
