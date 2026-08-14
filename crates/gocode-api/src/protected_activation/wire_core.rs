
impl DeterministicCodec for ProtectedLaunchRequestV2 {
    const MESSAGE_TYPE_ID: u32 = 21;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        encoder.write_map_header(4);
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        self.compatibility_request.encode(encoder)?;
        write_key(encoder, 3);
        encode_provider_binding(encoder, &self.provider_binding);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(4)? != 4 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_schema_version(decoder, PROTOCOL_SCHEMA_VERSION_V2)?;
        expect_key(decoder, 2)?;
        let compatibility_request =
            ProtectedLaunchRequestV1::decode(ProtectedLaunchRequestV1::MESSAGE_TYPE_ID, decoder)?;
        expect_key(decoder, 3)?;
        let provider_binding = decode_provider_binding(decoder)?;
        Self::new(compatibility_request, provider_binding)
            .map_err(|_| DecodeError::UnknownField { key: 3 })
    }
}

/// Exact V2 launch tuple required by renewal and shutdown ownership proofs.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedOwnedLaunchV2 {
    compatibility_owned_launch: ProtectedOwnedLaunchV1,
    provider_binding: ProviderActivationBindingV1,
}

impl ProtectedOwnedLaunchV2 {
    pub fn new(
        compatibility_owned_launch: ProtectedOwnedLaunchV1,
        provider_binding: ProviderActivationBindingV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if compatibility_owned_launch.profile.transport_profile_id
            != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        Ok(Self {
            compatibility_owned_launch,
            provider_binding,
        })
    }

    #[must_use]
    pub const fn compatibility_owned_launch(&self) -> &ProtectedOwnedLaunchV1 {
        &self.compatibility_owned_launch
    }

    #[must_use]
    pub const fn provider_binding(&self) -> &ProviderActivationBindingV1 {
        &self.provider_binding
    }

    #[must_use]
    pub const fn launch_authority_id(&self) -> &[u8; 16] {
        self.compatibility_owned_launch.launch_authority_id()
    }

    #[must_use]
    pub const fn desktop_host_instance_id(&self) -> &[u8; 16] {
        self.compatibility_owned_launch.desktop_host_instance_id()
    }

    #[must_use]
    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        self.compatibility_owned_launch.daemon_instance_id()
    }

    #[must_use]
    pub const fn launch_generation(&self) -> u64 {
        self.compatibility_owned_launch.launch_generation()
    }

    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        self.compatibility_owned_launch.session_id()
    }

    fn verify_exact(&self, expected: &Self) -> Result<(), LaunchAuthorityError> {
        if self.compatibility_owned_launch != expected.compatibility_owned_launch {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        self.provider_binding
            .verify_exact(&expected.provider_binding)
    }
}

impl fmt::Debug for ProtectedOwnedLaunchV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedOwnedLaunchV2")
            .field("launch_generation", &self.launch_generation())
            .field("provider_binding", &self.provider_binding)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}

/// Authenticated V2 readiness with exact provider mode/profile binding.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedReadyV2 {
    protocol_schema_version: u32,
    compatibility_ready: ProtectedReadyV1,
    provider_binding: ProviderActivationBindingV1,
    provider_readiness: ProviderActivationReadinessV1,
    readiness_proof: [u8; 32],
}
