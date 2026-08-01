#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredExecutableV1 {
    executable_sha256: [u8; 32],
    canonical_path_sha256: [u8; 32],
    byte_length: u64,
}

impl StoredExecutableV1 {
    const fn from_contract(value: &ExecutableIdentityV1) -> Self {
        Self {
            executable_sha256: *value.executable_sha256(),
            canonical_path_sha256: *value.canonical_path_sha256(),
            byte_length: value.byte_length(),
        }
    }

    fn into_contract(self) -> Result<ExecutableIdentityV1, ProtectedBundledRuntimeError> {
        ExecutableIdentityV1::new(
            self.executable_sha256,
            self.canonical_path_sha256,
            self.byte_length,
        )
        .map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProfileV1 {
    transport_profile_id: String,
    runtime_profile_schema_version: u32,
    profile_id: String,
    profile_hash: [u8; 32],
    capability_digest: [u8; 32],
}

impl StoredProfileV1 {
    fn from_contract(value: &ProtectedRuntimeProfileV1) -> Self {
        Self {
            transport_profile_id: value.transport_profile_id().to_owned(),
            runtime_profile_schema_version: value.runtime_profile_schema_version(),
            profile_id: value.profile_id().to_owned(),
            profile_hash: *value.profile_hash(),
            capability_digest: *value.capability_digest(),
        }
    }

    fn into_contract(self) -> Result<ProtectedRuntimeProfileV1, ProtectedBundledRuntimeError> {
        ProtectedRuntimeProfileV1::new(
            self.transport_profile_id,
            self.runtime_profile_schema_version,
            self.profile_id,
            self.profile_hash,
            self.capability_digest,
        )
        .map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredStableV1 {
    schema_version: u32,
    authority_id: [u8; 16],
    principal_id: String,
    lineage_id: [u8; 16],
    profile_id: String,
    profile_hash: [u8; 32],
    capability_digest: [u8; 32],
}

impl StoredStableV1 {
    fn from_contract(value: &StableRuntimeBindingV1) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            authority_id: *value.authority_id(),
            principal_id: value.principal_id().to_owned(),
            lineage_id: *value.lineage_id(),
            profile_id: value.profile_id().to_owned(),
            profile_hash: *value.profile_hash(),
            capability_digest: *value.capability_digest(),
        }
    }

    fn into_contract(self) -> Result<StableRuntimeBindingV1, ProtectedBundledRuntimeError> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        StableRuntimeBindingV1::new(
            self.authority_id,
            self.principal_id,
            self.lineage_id,
            self.profile_id,
            self.profile_hash,
            self.capability_digest,
        )
        .map_err(Into::into)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPendingV1 {
    schema_version: u32,
    preparation_id: [u8; 16],
    runtime_root_identity: [u8; 32],
    stable: StoredStableV1,
    executable: StoredExecutableV1,
    profile: StoredProfileV1,
}

impl StoredPendingV1 {
    fn from_contract(value: &PendingFirstActivationV1) -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            preparation_id: *value.preparation_id(),
            runtime_root_identity: *value.runtime_root_identity(),
            stable: StoredStableV1::from_contract(value.stable()),
            executable: StoredExecutableV1::from_contract(value.executable()),
            profile: StoredProfileV1::from_contract(value.profile()),
        }
    }

    fn into_contract(self) -> Result<PendingFirstActivationV1, ProtectedBundledRuntimeError> {
        if self.schema_version != STATE_SCHEMA_VERSION {
            return Err(ProtectedBundledRuntimeError::ActivationStateUnavailable);
        }
        PendingFirstActivationV1::new(
            self.preparation_id,
            self.runtime_root_identity,
            self.stable.into_contract()?,
            self.executable.into_contract()?,
            self.profile.into_contract()?,
        )
        .map_err(Into::into)
    }
}
