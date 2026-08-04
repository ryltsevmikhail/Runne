
impl fmt::Debug for ProtectedReadyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedReadyV1")
            .field("protocol_schema_version", &self.protocol_schema_version)
            .field("launch_generation", &self.launch_generation)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedReadyV1 {
    const MESSAGE_TYPE_ID: u32 = 2;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        self.encode_fields(encoder, true)
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(15)? != 15 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_key(decoder, 1)?;
        if decoder.read_unsigned(u64::from(u32::MAX))? != u64::from(PROTOCOL_SCHEMA_VERSION) {
            return Err(DecodeError::UnknownField { key: 1 });
        }
        expect_key(decoder, 2)?;
        let launch_authority_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?;
        let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?;
        let executable = decode_executable(decoder)?;
        expect_key(decoder, 5)?;
        let profile = decode_profile(decoder)?;
        expect_key(decoder, 6)?;
        let stable = decode_stable(decoder)?;
        expect_key(decoder, 7)?;
        let daemon_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 8)?;
        let launch_generation = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 9)?;
        let session_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 10)?;
        let endpoint = decoder.read_text_string(MAX_TEXT_BYTES)?.to_owned();
        expect_key(decoder, 11)?;
        let certificate_sha256 = decode_fixed::<32>(decoder)?;
        expect_key(decoder, 12)?;
        let certificate_der = decoder
            .read_byte_string(MAX_CERTIFICATE_DER_BYTES)?
            .to_vec();
        expect_key(decoder, 13)?;
        let count = usize::try_from(decoder.read_array_header(MAX_CAPABILITIES as u32)?)
            .map_err(|_| DecodeError::UnknownField { key: 13 })?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(decoder.read_text_string(MAX_PROFILE_ID_BYTES)?.to_owned());
        }
        expect_key(decoder, 14)?;
        let readiness_proof = decode_fixed::<32>(decoder)?;
        let mut value = Self::new(
            launch_authority_id,
            desktop_host_instance_id,
            executable,
            profile,
            stable,
            daemon_instance_id,
            launch_generation,
            session_id,
            endpoint,
            certificate_sha256,
            certificate_der,
            capabilities,
        )
        .map_err(|_| DecodeError::UnknownField { key: 14 })?;
        value.readiness_proof = readiness_proof;
        Ok(value)
    }
}

/// Protocol V2 protected launch request with an authenticated provider binding.
///
/// The nested V1 request is a compatibility core only. The outer V2 message
/// type and schema are the negotiated wire contract, so a V1 reader rejects
/// the frame instead of silently discarding the provider binding.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedLaunchRequestV2 {
    protocol_schema_version: u32,
    compatibility_request: ProtectedLaunchRequestV1,
    provider_binding: ProviderActivationBindingV1,
}

impl ProtectedLaunchRequestV2 {
    /// Promotes one protected V1 launch core into the provider-bound V2 wire.
    pub fn new(
        compatibility_request: ProtectedLaunchRequestV1,
        provider_binding: ProviderActivationBindingV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if compatibility_request.profile.transport_profile_id
            != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION_V2,
            compatibility_request,
            provider_binding,
        })
    }

    /// Validates the launch core and exact expected provider mode/profile.
    pub fn validate(
        &self,
        now_unix_millis: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
        expected_provider: &ProviderActivationBindingV1,
    ) -> Result<(), LaunchAuthorityError> {
        self.compatibility_request
            .validate(now_unix_millis, expected)?;
        self.provider_binding.verify_exact(expected_provider)
    }

    /// Rechecks the launch deadline without consuming the provider binding.
    pub fn validate_freshness(&self, now_unix_millis: u64) -> Result<(), LaunchAuthorityError> {
        if self.protocol_schema_version != PROTOCOL_SCHEMA_VERSION_V2 {
            return Err(LaunchAuthorityError::StaleLaunchAuthority);
        }
        self.compatibility_request
            .validate_freshness(now_unix_millis)
    }

    /// Encodes the strict bounded V2 launch frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    /// Decodes only the exact V2 launch frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    /// Returns the reader-only V1 core used by first-activation migration.
    #[must_use]
    pub const fn compatibility_request(&self) -> &ProtectedLaunchRequestV1 {
        &self.compatibility_request
    }

    #[must_use]
    pub const fn provider_binding(&self) -> &ProviderActivationBindingV1 {
        &self.provider_binding
    }

    #[must_use]
    pub const fn launch_authority_id(&self) -> [u8; 16] {
        self.compatibility_request.launch_authority_id()
    }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> [u8; 16] {
        self.compatibility_request.desktop_host_instance_id()
    }

    #[must_use]
    pub fn principal_id(&self) -> &str {
        self.compatibility_request.principal_id()
    }

    #[must_use]
    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        self.compatibility_request.profile()
    }

    #[must_use]
    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        self.compatibility_request.executable()
    }

    #[must_use]
    pub fn runtime_root(&self) -> &std::path::Path {
        self.compatibility_request.runtime_root()
    }

    #[must_use]
    pub const fn activation_disposition(&self) -> &ActivationDispositionV1 {
        self.compatibility_request.activation_disposition()
    }

    #[must_use]
    pub fn derive_keys(&self) -> ProtectedActivationKeys {
        self.compatibility_request.derive_keys()
    }

    pub fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        self.compatibility_request.derive_keys_and_forget()
    }
}

impl fmt::Debug for ProtectedLaunchRequestV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedLaunchRequestV2")
            .field("protocol_schema_version", &self.protocol_schema_version)
            .field("provider_binding", &self.provider_binding)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}
