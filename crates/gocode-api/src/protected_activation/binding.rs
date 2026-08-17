
impl ProviderActivationBindingV1 {
    /// Creates a bounded exact provider activation binding.
    pub fn new(
        mode: ProviderActivationModeV1,
        profile_id: impl Into<String>,
        profile_digest: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        let profile_id = profile_id.into();
        let expected = match mode {
            ProviderActivationModeV1::DeterministicV1 => (
                DETERMINISTIC_PROVIDER_PROFILE_ID,
                DETERMINISTIC_PROVIDER_PROFILE_DIGEST,
            ),
            ProviderActivationModeV1::OpenAiResponsesTextV1 => (
                OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_ID,
                OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
            ),
            ProviderActivationModeV1::DeepSeekResponsesTextV1 => (
                DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_ID,
                DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
            ),
        };
        if !valid_text(&profile_id, MAX_PROFILE_ID_BYTES)
            || profile_id != expected.0
            || profile_digest != expected.1
        {
            return Err(LaunchAuthorityError::ProviderProfileMismatch);
        }
        Ok(Self {
            mode,
            profile_id,
            profile_digest,
        })
    }

    /// Returns the released deterministic provider binding.
    #[must_use]
    pub fn deterministic_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::DeterministicV1,
            profile_id: DETERMINISTIC_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: DETERMINISTIC_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the released exact OpenAI Responses text provider binding.
    #[must_use]
    pub fn openai_responses_text_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::OpenAiResponsesTextV1,
            profile_id: OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: OPENAI_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the released exact DeepSeek Responses text provider binding.
    #[must_use]
    pub fn deepseek_responses_text_v1() -> Self {
        Self {
            mode: ProviderActivationModeV1::DeepSeekResponsesTextV1,
            profile_id: DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_ID.to_owned(),
            profile_digest: DEEPSEEK_RESPONSES_TEXT_PROVIDER_PROFILE_DIGEST,
        }
    }

    /// Returns the exact activation mode.
    #[must_use]
    pub const fn mode(&self) -> ProviderActivationModeV1 {
        self.mode
    }

    /// Returns the exact immutable provider profile identifier.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the exact immutable provider profile digest.
    #[must_use]
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }

    fn verify_exact(&self, expected: &Self) -> Result<(), LaunchAuthorityError> {
        if self.mode != expected.mode {
            return Err(LaunchAuthorityError::ProviderModeMismatch);
        }
        if self.profile_id != expected.profile_id || self.profile_digest != expected.profile_digest
        {
            return Err(LaunchAuthorityError::ProviderProfileMismatch);
        }
        Ok(())
    }
}

/// Stable runtime identity expected across daemon restarts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StableRuntimeBindingV1 {
    authority_id: [u8; 16],
    principal_id: String,
    lineage_id: [u8; 16],
    profile_id: String,
    profile_hash: [u8; 32],
    capability_digest: [u8; 32],
}

impl StableRuntimeBindingV1 {
    /// Creates a validated stable runtime binding.
    pub fn new(
        authority_id: [u8; 16],
        principal_id: impl Into<String>,
        lineage_id: [u8; 16],
        profile_id: impl Into<String>,
        profile_hash: [u8; 32],
        capability_digest: [u8; 32],
    ) -> Result<Self, LaunchAuthorityError> {
        let principal_id = principal_id.into();
        let profile_id = profile_id.into();
        if validate_uuid_v7_bytes(&authority_id).is_err()
            || validate_uuid_v7_bytes(&lineage_id).is_err()
            || !valid_text(&principal_id, MAX_PRINCIPAL_ID_BYTES)
            || !valid_text(&profile_id, MAX_PROFILE_ID_BYTES)
            || profile_hash == [0; 32]
            || capability_digest == [0; 32]
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        Ok(Self {
            authority_id,
            principal_id,
            lineage_id,
            profile_id,
            profile_hash,
            capability_digest,
        })
    }

    pub const fn authority_id(&self) -> &[u8; 16] {
        &self.authority_id
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub const fn lineage_id(&self) -> &[u8; 16] {
        &self.lineage_id
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub const fn profile_hash(&self) -> &[u8; 32] {
        &self.profile_hash
    }

    pub const fn capability_digest(&self) -> &[u8; 32] {
        &self.capability_digest
    }
}

/// Durable, non-secret recovery record for an interrupted first activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingFirstActivationV1 {
    preparation_id: [u8; 16],
    runtime_root_identity: [u8; 32],
    stable: StableRuntimeBindingV1,
    executable: ExecutableIdentityV1,
    profile: ProtectedRuntimeProfileV1,
}

impl PendingFirstActivationV1 {
    /// Creates an exact first-activation recovery record.
    pub fn new(
        preparation_id: [u8; 16],
        runtime_root_identity: [u8; 32],
        stable: StableRuntimeBindingV1,
        executable: ExecutableIdentityV1,
        profile: ProtectedRuntimeProfileV1,
    ) -> Result<Self, LaunchAuthorityError> {
        if validate_uuid_v7_bytes(&preparation_id).is_err() || runtime_root_identity == [0; 32] {
            return Err(LaunchAuthorityError::FirstActivationPreparationMismatch);
        }
        Ok(Self {
            preparation_id,
            runtime_root_identity,
            stable,
            executable,
            profile,
        })
    }

    pub const fn preparation_id(&self) -> &[u8; 16] {
        &self.preparation_id
    }

    pub const fn runtime_root_identity(&self) -> &[u8; 32] {
        &self.runtime_root_identity
    }

    pub const fn stable(&self) -> &StableRuntimeBindingV1 {
        &self.stable
    }

    pub const fn executable(&self) -> &ExecutableIdentityV1 {
        &self.executable
    }

    pub const fn profile(&self) -> &ProtectedRuntimeProfileV1 {
        &self.profile
    }
}

/// Stable-profile admission mode for one protected launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationDispositionV1 {
    FirstActivation,
    Existing(Box<StableRuntimeBindingV1>),
    ResumeFirstActivation(Box<PendingFirstActivationV1>),
}

impl ActivationDispositionV1 {
    fn expected_stable(&self) -> Option<&StableRuntimeBindingV1> {
        match self {
            Self::FirstActivation => None,
            Self::Existing(stable) => Some(stable.as_ref()),
            Self::ResumeFirstActivation(pending) => Some(pending.stable()),
        }
    }
}

/// Exact non-secret values the daemon must match before consuming authority.
pub struct LaunchAuthorityValidationV1<'a> {
    pub principal_id: &'a str,
    pub profile: &'a ProtectedRuntimeProfileV1,
    pub executable: &'a ExecutableIdentityV1,
}
