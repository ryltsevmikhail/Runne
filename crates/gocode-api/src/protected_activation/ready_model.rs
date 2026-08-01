/// Authenticated readiness for exactly one protected launch.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedReadyV1 {
    protocol_schema_version: u32,
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    executable: ExecutableIdentityV1,
    profile: ProtectedRuntimeProfileV1,
    stable: StableRuntimeBindingV1,
    daemon_instance_id: [u8; 16],
    launch_generation: u64,
    session_id: [u8; 16],
    endpoint: String,
    certificate_sha256: [u8; 32],
    certificate_der: Vec<u8>,
    capabilities: Vec<String>,
    readiness_proof: [u8; 32],
}

impl ProtectedReadyV1 {
    /// Builds an unsigned exact readiness value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        executable: ExecutableIdentityV1,
        profile: ProtectedRuntimeProfileV1,
        stable: StableRuntimeBindingV1,
        daemon_instance_id: [u8; 16],
        launch_generation: u64,
        session_id: [u8; 16],
        endpoint: impl Into<String>,
        certificate_sha256: [u8; 32],
        certificate_der: Vec<u8>,
        capabilities: Vec<String>,
    ) -> Result<Self, LaunchAuthorityError> {
        let endpoint = endpoint.into();
        if validate_uuid_v7_bytes(&launch_authority_id).is_err()
            || validate_uuid_v7_bytes(&desktop_host_instance_id).is_err()
            || validate_uuid_v7_bytes(&daemon_instance_id).is_err()
            || validate_uuid_v7_bytes(&session_id).is_err()
            || daemon_instance_id == session_id
            || launch_generation == 0
            || !valid_text(&endpoint, MAX_TEXT_BYTES)
            || certificate_sha256 == [0; 32]
            || certificate_der.is_empty()
            || certificate_der.len() > MAX_CERTIFICATE_DER_BYTES
            || capabilities.is_empty()
            || capabilities.len() > MAX_CAPABILITIES
            || capabilities
                .iter()
                .any(|capability| !valid_text(capability, MAX_PROFILE_ID_BYTES))
        {
            return Err(LaunchAuthorityError::InstanceGenerationSessionMismatch);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
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
            readiness_proof: [0; 32],
        })
    }

    /// Signs the exact canonical readiness transcript.
    pub fn sign(&mut self, keys: &ProtectedActivationKeys) {
        self.readiness_proof = authenticated_mac(
            keys.readiness_key(),
            READINESS_DOMAIN,
            &self.unsigned_payload(),
        );
    }

    /// Verifies proof plus every launch-pinned stable field.
    pub fn verify_exact(
        &self,
        request: &ProtectedLaunchRequestV1,
        keys: &ProtectedActivationKeys,
    ) -> Result<(), LaunchAuthorityError> {
        if self.launch_authority_id != request.launch_authority_id
            || self.desktop_host_instance_id != request.desktop_host_instance_id
        {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        if self.executable != request.executable {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        if self.profile != request.profile {
            return Err(
                if self.profile.transport_profile_id == EXTERNAL_TRANSPORT_PROFILE_ID {
                    LaunchAuthorityError::DowngradedExternalProfile
                } else {
                    LaunchAuthorityError::ProfileHashMismatch
                },
            );
        }
        if let Some(expected) = request.activation_disposition.expected_stable()
            && self.stable != *expected
        {
            return Err(LaunchAuthorityError::ProfileHashMismatch);
        }
        if self.launch_generation == 0
            || self.daemon_instance_id == self.session_id
            || validate_uuid_v7_bytes(&self.daemon_instance_id).is_err()
            || validate_uuid_v7_bytes(&self.session_id).is_err()
        {
            return Err(LaunchAuthorityError::InstanceGenerationSessionMismatch);
        }
        let expected = authenticated_mac(
            keys.readiness_key(),
            READINESS_DOMAIN,
            &self.unsigned_payload(),
        );
        if !bool::from(expected.ct_eq(&self.readiness_proof)) {
            return Err(LaunchAuthorityError::ReadinessProofMismatch);
        }
        Ok(())
    }

    /// Encodes the signed deterministic bounded readiness frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    /// Decodes one exact deterministic bounded readiness frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        &self.stable
    }

    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.profile
    }

    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.executable
    }

    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        &self.daemon_instance_id
    }

    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }

    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Returns the exact non-secret ownership tuple for control messages.
    #[must_use]
    pub fn owned_launch(&self) -> ProtectedOwnedLaunchV1 {
        ProtectedOwnedLaunchV1::new(
            self.launch_authority_id,
            self.desktop_host_instance_id,
            self.executable.clone(),
            self.profile.clone(),
            self.stable.clone(),
            self.daemon_instance_id,
            self.launch_generation,
            self.session_id,
        )
        .expect("validated readiness always has a valid owned-launch tuple")
    }

    fn unsigned_payload(&self) -> Vec<u8> {
        let mut encoder = CborEncoder::new();
        self.encode_fields(&mut encoder, false)
            .expect("in-memory validated readiness is encodable");
        encoder.into_bytes()
    }

    fn encode_fields(
        &self,
        encoder: &mut CborEncoder,
        include_proof: bool,
    ) -> Result<(), EncodeError> {
        encoder.write_map_header(if include_proof { 15 } else { 14 });
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encoder.write_byte_string(&self.launch_authority_id);
        write_key(encoder, 3);
        encoder.write_byte_string(&self.desktop_host_instance_id);
        write_key(encoder, 4);
        encode_executable(encoder, &self.executable);
        write_key(encoder, 5);
        encode_profile(encoder, &self.profile);
        write_key(encoder, 6);
        encode_stable(encoder, &self.stable);
        write_key(encoder, 7);
        encoder.write_byte_string(&self.daemon_instance_id);
        write_key(encoder, 8);
        encoder.write_unsigned(self.launch_generation);
        write_key(encoder, 9);
        encoder.write_byte_string(&self.session_id);
        write_key(encoder, 10);
        encoder.write_text_string(&self.endpoint);
        write_key(encoder, 11);
        encoder.write_byte_string(&self.certificate_sha256);
        write_key(encoder, 12);
        encoder.write_byte_string(&self.certificate_der);
        write_key(encoder, 13);
        encoder.write_array_header(self.capabilities.len() as u64);
        for capability in &self.capabilities {
            encoder.write_text_string(capability);
        }
        if include_proof {
            write_key(encoder, 14);
            encoder.write_byte_string(&self.readiness_proof);
        }
        Ok(())
    }
}

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
