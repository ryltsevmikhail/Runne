/// Direct native V3 launch request for credential enrollment.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialEnrollmentLaunchRequestV3 {
    core: EnrollmentLaunchCoreV3,
    provider: ProviderActivationBindingV1,
    enrollment: ProtectedCredentialEnrollmentLaunchBindingV1,
}

impl ProtectedCredentialEnrollmentLaunchRequestV3 {
    pub fn new(
        request: ProtectedLaunchRequestV1,
        provider: ProviderActivationBindingV1,
        enrollment: ProtectedCredentialEnrollmentLaunchBindingV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if request.profile.transport_profile_id != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        require_credential_provider(&provider)?;
        Ok(Self {
            core: EnrollmentLaunchCoreV3::from_v1(request),
            provider,
            enrollment,
        })
    }

    pub fn validate(
        &self,
        now: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
        provider: &ProviderActivationBindingV1,
        enrollment: &ProtectedCredentialEnrollmentLaunchBindingV1,
    ) -> Result<(), LaunchAuthorityError> {
        self.core.validate(now, expected)?;
        self.provider.verify_exact(provider)?;
        if &self.enrollment != enrollment {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(())
    }

    /// Rechecks the V3 launch deadline without projecting to a lower protocol.
    pub fn validate_freshness(&self, now: u64) -> Result<(), LaunchAuthorityError> {
        self.core.validate_freshness(now)
    }

    #[must_use]
    pub fn derive_keys(&self) -> ProtectedActivationKeys {
        self.core.keys()
    }

    #[must_use]
    pub fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        self.core.keys_and_forget()
    }

    #[must_use]
    pub const fn launch_authority_id(&self) -> [u8; 16] {
        self.core.authority_id
    }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> [u8; 16] {
        self.core.desktop_id
    }

    #[must_use]
    pub const fn expires_at_unix_millis(&self) -> u64 {
        self.core.expires
    }

    #[must_use]
    pub fn principal_id(&self) -> &str {
        &self.core.principal
    }

    #[must_use]
    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.core.profile
    }

    #[must_use]
    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.core.executable
    }

    #[must_use]
    pub fn runtime_root(&self) -> &std::path::Path {
        &self.core.runtime_root
    }

    #[must_use]
    pub const fn activation_disposition(&self) -> &ActivationDispositionV1 {
        &self.core.disposition
    }

    #[must_use]
    pub const fn provider_binding(&self) -> &ProviderActivationBindingV1 {
        &self.provider
    }

    #[must_use]
    pub const fn enrollment_binding(&self) -> &ProtectedCredentialEnrollmentLaunchBindingV1 {
        &self.enrollment
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_v3_frame(self)
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_v3_frame(frame)
    }
}

impl fmt::Debug for ProtectedCredentialEnrollmentLaunchRequestV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedCredentialEnrollmentLaunchRequestV3")
            .field("provider", &self.provider)
            .field("enrollment", &self.enrollment)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

impl DeterministicCodec for ProtectedCredentialEnrollmentLaunchRequestV3 {
    const MESSAGE_TYPE_ID: u32 = 27;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        encoder.write_map_header(5);
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(PROTOCOL_SCHEMA_VERSION_V3));
        write_key(encoder, 2);
        encode_launch_core(encoder, &self.core);
        write_key(encoder, 3);
        encode_provider_binding(encoder, &self.provider);
        write_key(encoder, 4);
        encode_enrollment_binding(encoder, &self.enrollment);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(5)? != 5 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V3)?;
        expect_key(decoder, 2)?;
        let core = decode_launch_core(decoder)?;
        expect_key(decoder, 3)?;
        let provider = decode_provider_binding(decoder)?;
        if require_credential_provider(&provider).is_err() {
            return Err(DecodeError::UnknownField { key: 3 });
        }
        expect_key(decoder, 4)?;
        let enrollment = decode_enrollment_binding(decoder)?;
        Ok(Self {
            core,
            provider,
            enrollment,
        })
    }
}

fn require_credential_provider(
    provider: &ProviderActivationBindingV1,
) -> Result<(), LaunchAuthorityError> {
    match provider.mode() {
        ProviderActivationModeV1::OpenAiResponsesTextV1
        | ProviderActivationModeV1::DeepSeekResponsesTextV1 => Ok(()),
        // Local Engine execution is credential-free by contract: it is
        // admitted through the launch binding, not through enrollment.
        ProviderActivationModeV1::LocalEngineTextV1
        | ProviderActivationModeV1::DeterministicV1 => {
            Err(LaunchAuthorityError::ProviderModeMismatch)
        }
    }
}
