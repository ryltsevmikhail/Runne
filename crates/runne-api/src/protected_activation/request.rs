
/// Protected launch request sent once over the inherited channel.
#[derive(Clone, Eq, PartialEq)]
pub struct ProtectedLaunchRequestV1 {
    protocol_schema_version: u32,
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    launch_secret: LaunchSecret,
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    principal_id: String,
    profile: ProtectedRuntimeProfileV1,
    executable: ExecutableIdentityV1,
    runtime_root: PathBuf,
    activation_disposition: ActivationDispositionV1,
}

impl ProtectedLaunchRequestV1 {
    /// Builds a bounded one-time launch request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        launch_secret: LaunchSecret,
        issued_at_unix_millis: u64,
        expires_at_unix_millis: u64,
        principal_id: impl Into<String>,
        profile: ProtectedRuntimeProfileV1,
        executable: ExecutableIdentityV1,
        runtime_root: PathBuf,
        activation_disposition: ActivationDispositionV1,
    ) -> Result<Self, LaunchAuthorityError> {
        let principal_id = principal_id.into();
        let root_text = runtime_root
            .to_str()
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        if validate_uuid_v7_bytes(&launch_authority_id).is_err()
            || validate_uuid_v7_bytes(&desktop_host_instance_id).is_err()
            || !valid_text(&principal_id, MAX_PRINCIPAL_ID_BYTES)
            || !runtime_root.is_absolute()
            || !valid_text(root_text, MAX_TEXT_BYTES)
            || issued_at_unix_millis >= expires_at_unix_millis
            || expires_at_unix_millis.saturating_sub(issued_at_unix_millis) > MAX_LAUNCH_TTL_MILLIS
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            protocol_schema_version: PROTOCOL_SCHEMA_VERSION,
            launch_authority_id,
            desktop_host_instance_id,
            launch_secret,
            issued_at_unix_millis,
            expires_at_unix_millis,
            principal_id,
            profile,
            executable,
            runtime_root,
            activation_disposition,
        })
    }

    /// Validates TTL and all caller-pinned non-secret launch values.
    pub fn validate(
        &self,
        now_unix_millis: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
    ) -> Result<(), LaunchAuthorityError> {
        self.validate_freshness(now_unix_millis)?;
        if self.profile.transport_profile_id == EXTERNAL_TRANSPORT_PROFILE_ID
            || expected.profile.transport_profile_id == EXTERNAL_TRANSPORT_PROFILE_ID
            || self.profile.transport_profile_id != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
            || expected.profile.transport_profile_id != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID
        {
            return Err(LaunchAuthorityError::DowngradedExternalProfile);
        }
        if self.principal_id != expected.principal_id {
            return Err(LaunchAuthorityError::MissingLaunchAuthority);
        }
        if self.executable != *expected.executable {
            return Err(LaunchAuthorityError::ExecutableIdentityMismatch);
        }
        if self.profile.profile_hash != expected.profile.profile_hash
            || self.profile.profile_id != expected.profile.profile_id
            || self.profile.runtime_profile_schema_version
                != expected.profile.runtime_profile_schema_version
            || self.profile.capability_digest != expected.profile.capability_digest
        {
            return Err(LaunchAuthorityError::ProfileHashMismatch);
        }
        Ok(())
    }

    /// Enforces the reader-only V1 compatibility boundary.
    ///
    /// V1 has no authenticated provider binding and therefore can activate
    /// only the credential-free deterministic provider. OpenAI activation must
    /// use [`ProtectedLaunchRequestV2`].
    pub const fn validate_provider_mode(
        &self,
        mode: ProviderActivationModeV1,
    ) -> Result<(), LaunchAuthorityError> {
        match mode {
            ProviderActivationModeV1::DeterministicV1 => Ok(()),
            ProviderActivationModeV1::OpenAiResponsesTextV1
            | ProviderActivationModeV1::DeepSeekResponsesTextV1
            | ProviderActivationModeV1::LocalEngineTextV1 => {
                Err(LaunchAuthorityError::MissingProviderBinding)
            }
        }
    }

    /// Rechecks the signed launch-authority deadline immediately before use.
    pub fn validate_freshness(&self, now_unix_millis: u64) -> Result<(), LaunchAuthorityError> {
        if self.protocol_schema_version != PROTOCOL_SCHEMA_VERSION
            || now_unix_millis < self.issued_at_unix_millis
            || now_unix_millis > self.expires_at_unix_millis
        {
            return Err(LaunchAuthorityError::StaleLaunchAuthority);
        }
        Ok(())
    }

    /// Encodes the exact deterministic bounded launch frame.
    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodeError> {
        encode_codec_frame(
            self,
            &FrameLimits {
                max_frame_bytes: MAX_FRAME_BYTES,
            },
        )
    }

    /// Decodes one exact deterministic bounded launch frame.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, DecodeError> {
        decode_codec_frame(frame, &decode_limits())
    }

    pub const fn launch_authority_id(&self) -> [u8; 16] {
        self.launch_authority_id
    }

    pub const fn expires_at_unix_millis(&self) -> u64 {
        self.expires_at_unix_millis
    }

    pub const fn desktop_host_instance_id(&self) -> [u8; 16] {
        self.desktop_host_instance_id
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.profile
    }

    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.executable
    }

    pub fn runtime_root(&self) -> &std::path::Path {
        &self.runtime_root
    }

    pub const fn activation_disposition(&self) -> &ActivationDispositionV1 {
        &self.activation_disposition
    }

    /// Derives the native-only launch keys.
    #[must_use]
    pub fn derive_keys(&self) -> ProtectedActivationKeys {
        self.launch_secret.derive_keys()
    }

    /// Derives native-only keys and immediately zeroizes the raw launch secret.
    pub fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        let keys = self.launch_secret.derive_keys();
        self.launch_secret.0.zeroize();
        keys
    }
}

impl fmt::Debug for ProtectedLaunchRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedLaunchRequestV1")
            .field("protocol_schema_version", &self.protocol_schema_version)
            .field("activation_disposition", &self.activation_disposition)
            .field("protected_fields", &"<redacted>")
            .finish()
    }
}
