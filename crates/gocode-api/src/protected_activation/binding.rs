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
