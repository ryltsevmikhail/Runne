/// Direct native V3 readiness; its proof covers every launch, provider, and enrollment field.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedCredentialEnrollmentReadyV3 {
    core: EnrollmentOwnedCoreV3,
    provider: ProviderActivationBindingV1,
    enrollment: ProtectedCredentialEnrollmentLaunchBindingV1,
    request_digest: [u8; 32],
    readiness: ProviderActivationReadinessV1,
    endpoint: String,
    certificate_sha256: [u8; 32],
    certificate_der: Vec<u8>,
    capabilities: Vec<String>,
    proof: [u8; 32],
}

impl ProtectedCredentialEnrollmentReadyV3 {
    pub fn new(
        ready: ProtectedReadyV1,
        provider: ProviderActivationBindingV1,
        enrollment: ProtectedCredentialEnrollmentLaunchBindingV1,
        readiness: ProviderActivationReadinessV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if ready.profile.transport_profile_id != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        require_credential_provider(&provider)?;
        let core = EnrollmentOwnedCoreV3::new(
            ready.launch_authority_id,
            ready.desktop_host_instance_id,
            ready.executable,
            ready.profile,
            ready.stable,
            ready.daemon_instance_id,
            ready.launch_generation,
            ready.session_id,
        )?;
        Ok(Self {
            core,
            provider,
            enrollment,
            request_digest: [0; 32],
            readiness,
            endpoint: ready.endpoint,
            certificate_sha256: ready.certificate_sha256,
            certificate_der: ready.certificate_der,
            capabilities: ready.capabilities,
            proof: [0; 32],
        })
    }

    pub fn sign(
        &mut self,
        request: &ProtectedCredentialEnrollmentLaunchRequestV3,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.matches_request(request)?;
        self.request_digest = enrollment_launch_request_digest(request);
        self.proof = authenticated_mac_version(
            keys.readiness_key(),
            READINESS_DOMAIN_V3,
            PROTOCOL_SCHEMA_VERSION_V3,
            &self.unsigned(),
        );
        Ok(())
    }

    pub fn verify_exact(
        &self,
        request: &ProtectedCredentialEnrollmentLaunchRequestV3,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        self.matches_request(request)?;
        if self.request_digest != enrollment_launch_request_digest(request) {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let expected = authenticated_mac_version(
            keys.readiness_key(),
            READINESS_DOMAIN_V3,
            PROTOCOL_SCHEMA_VERSION_V3,
            &self.unsigned(),
        );
        if !bool::from(expected.ct_eq(&self.proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    #[allow(clippy::possible_missing_else)]
    fn matches_request(
        &self,
        request: &ProtectedCredentialEnrollmentLaunchRequestV3,
    ) -> Result<(), LaunchAuthorityError> {
        if self.core.authority_id != request.core.authority_id
            || self.core.desktop_id != request.core.desktop_id
            || self.core.executable != request.core.executable
            || self.core.profile != request.core.profile
        {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        if let Some(stable) = request.core.disposition.expected_stable()
            && self.core.stable != *stable
        {
            return Err(LaunchAuthorityError::ProfileHashMismatch);
        }
        self.provider.verify_exact(&request.provider)?;
        if self.enrollment != request.enrollment {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn owned_launch(&self) -> ProtectedCredentialEnrollmentOwnedLaunchV3 {
        ProtectedCredentialEnrollmentOwnedLaunchV3 {
            core: self.core.clone(),
            provider: self.provider.clone(),
            enrollment: self.enrollment.clone(),
        }
    }

    #[must_use]
    pub const fn provider_readiness(&self) -> ProviderActivationReadinessV1 {
        self.readiness
    }

    #[must_use]
    pub const fn provider_binding(&self) -> &ProviderActivationBindingV1 {
        &self.provider
    }

    #[must_use]
    pub const fn enrollment_binding(&self) -> &ProtectedCredentialEnrollmentLaunchBindingV1 {
        &self.enrollment
    }

    #[must_use]
    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        &self.core.stable
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
    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        &self.core.daemon_id
    }

    #[must_use]
    pub const fn launch_generation(&self) -> u64 {
        self.core.generation
    }

    #[must_use]
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.core.session_id
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[must_use]
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }

    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_v3_frame(self)
    }

    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_v3_frame(frame)
    }

    fn unsigned(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.fields(&mut encoder, false)
            .expect("valid V3 ready fields");
        encoder.into_bytes()
    }

    fn fields(
        &self,
        encoder: &mut CborEncoder,
        include_proof: bool,
    ) -> Result<(), EncodeError> {
        encoder.write_map_header(if include_proof { 12 } else { 11 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(PROTOCOL_SCHEMA_VERSION_V3));
        write_key(encoder, 2);
        encode_owned_core(encoder, &self.core);
        write_key(encoder, 3);
        encode_provider_binding(encoder, &self.provider);
        write_key(encoder, 4);
        encode_enrollment_binding(encoder, &self.enrollment);
        write_key(encoder, 5);
        encoder.write_byte_string(&self.request_digest);
        write_key(encoder, 6);
        encoder.write_unsigned(self.readiness.wire_code());
        write_key(encoder, 7);
        encoder.write_text_string(&self.endpoint);
        write_key(encoder, 8);
        encoder.write_byte_string(&self.certificate_sha256);
        write_key(encoder, 9);
        encoder.write_byte_string(&self.certificate_der);
        write_key(encoder, 10);
        encoder.write_array_header(self.capabilities.len() as u64);
        for capability in &self.capabilities {
            encoder.write_text_string(capability);
        }
        if include_proof {
            write_key(encoder, 11);
            encoder.write_byte_string(&self.proof);
        }
        Ok(())
    }
}

impl fmt::Debug for ProtectedCredentialEnrollmentReadyV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedCredentialEnrollmentReadyV3")
            .field("provider", &self.provider)
            .field("enrollment", &self.enrollment)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}
