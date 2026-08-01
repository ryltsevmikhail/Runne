/// Exact non-secret values the daemon must match before consuming authority.
pub struct LaunchAuthorityValidationV1<'a> {
    pub principal_id: &'a str,
    pub profile: &'a ProtectedRuntimeProfileV1,
    pub executable: &'a ExecutableIdentityV1,
}

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

impl DeterministicCodec for ProtectedLaunchRequestV1 {
    const MESSAGE_TYPE_ID: u32 = 1;

    fn encode(&self, encoder: &mut CborEncoder) -> Result<(), EncodeError> {
        encoder.write_map_header(12);
        write_key(encoder, 0);
        encoder.write_unsigned(u64::from(Self::MESSAGE_TYPE_ID));
        write_key(encoder, 1);
        encoder.write_unsigned(u64::from(self.protocol_schema_version));
        write_key(encoder, 2);
        encoder.write_byte_string(&self.launch_authority_id);
        write_key(encoder, 3);
        encoder.write_byte_string(&self.desktop_host_instance_id);
        write_key(encoder, 4);
        encoder.write_byte_string(self.launch_secret.as_bytes());
        write_key(encoder, 5);
        encoder.write_unsigned(self.issued_at_unix_millis);
        write_key(encoder, 6);
        encoder.write_unsigned(self.expires_at_unix_millis);
        write_key(encoder, 7);
        encoder.write_text_string(&self.principal_id);
        write_key(encoder, 8);
        encode_profile(encoder, &self.profile);
        write_key(encoder, 9);
        encode_executable(encoder, &self.executable);
        write_key(encoder, 10);
        encoder.write_text_string(
            self.runtime_root
                .to_str()
                .expect("validated UTF-8 runtime root"),
        );
        write_key(encoder, 11);
        encode_disposition(encoder, &self.activation_disposition);
        Ok(())
    }

    fn decode(type_id: u32, decoder: &mut CborDecoder<'_>) -> Result<Self, DecodeError> {
        if type_id != Self::MESSAGE_TYPE_ID || decoder.read_map_header(12)? != 12 {
            return Err(DecodeError::UnknownMessageType { type_id });
        }
        expect_key(decoder, 0)?;
        expect_message_type(decoder, Self::MESSAGE_TYPE_ID)?;
        expect_key(decoder, 1)?;
        let schema = decoder.read_unsigned(u64::from(u32::MAX))?;
        if schema != u64::from(PROTOCOL_SCHEMA_VERSION) {
            return Err(DecodeError::UnknownField { key: 1 });
        }
        expect_key(decoder, 2)?;
        let launch_authority_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 3)?;
        let desktop_host_instance_id = decode_fixed::<16>(decoder)?;
        expect_key(decoder, 4)?;
        let launch_secret = LaunchSecret::from_bytes(decode_fixed::<32>(decoder)?)
            .map_err(|_| DecodeError::UnknownField { key: 4 })?;
        expect_key(decoder, 5)?;
        let issued_at_unix_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 6)?;
        let expires_at_unix_millis = decoder.read_unsigned(u64::MAX)?;
        expect_key(decoder, 7)?;
        let principal_id = decoder.read_text_string(MAX_PRINCIPAL_ID_BYTES)?.to_owned();
        expect_key(decoder, 8)?;
        let profile = decode_profile(decoder)?;
        expect_key(decoder, 9)?;
        let executable = decode_executable(decoder)?;
        expect_key(decoder, 10)?;
        let runtime_root = PathBuf::from(decoder.read_text_string(MAX_TEXT_BYTES)?);
        expect_key(decoder, 11)?;
        let activation_disposition = decode_disposition(decoder)?;
        Self::new(
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
        )
        .map_err(|_| DecodeError::UnknownField { key: 11 })
    }
}
