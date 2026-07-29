//! Local runtime-session binding contracts.

use gocode_domain::event::Sensitivity;
use gocode_domain::id::{EventLogLineageId, InvalidIdReason, validate_uuid_v7_bytes};

use crate::ApiPrincipalId;

pub use gocode_domain::id::DaemonInstanceId;

/// Stable identity shared by every local runtime launch for one authority.
#[derive(Clone, PartialEq, Eq)]
pub struct StableRuntimeBinding {
    authority_id: [u8; 16],
    principal_id: ApiPrincipalId,
    lineage_id: EventLogLineageId,
    profile_id: String,
    schema_hash: [u8; 32],
    capability_digest: [u8; 32],
}

impl StableRuntimeBinding {
    /// Creates a stable binding after validating its canonical identity inputs.
    pub fn new(
        authority_id: [u8; 16],
        principal_id: ApiPrincipalId,
        lineage_id: EventLogLineageId,
        profile_id: impl Into<String>,
        schema_hash: [u8; 32],
        capability_digest: [u8; 32],
    ) -> Result<Self, LocalSessionContractError> {
        validate_uuid_v7_bytes(&authority_id)
            .map_err(LocalSessionContractError::InvalidAuthorityId)?;
        let profile_id = profile_id.into();
        if profile_id.is_empty() {
            return Err(LocalSessionContractError::EmptyProfileId);
        }
        if capability_digest == [0; 32] {
            return Err(LocalSessionContractError::EmptyCapabilityDigest);
        }
        Ok(Self {
            authority_id,
            principal_id,
            lineage_id,
            profile_id,
            schema_hash,
            capability_digest,
        })
    }

    pub const fn authority_id(&self) -> &[u8; 16] {
        &self.authority_id
    }
    pub const fn principal_id(&self) -> &ApiPrincipalId {
        &self.principal_id
    }
    pub const fn lineage_id(&self) -> &EventLogLineageId {
        &self.lineage_id
    }
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub const fn schema_hash(&self) -> &[u8; 32] {
        &self.schema_hash
    }
    pub const fn capability_digest(&self) -> &[u8; 32] {
        &self.capability_digest
    }
}

impl core::fmt::Debug for StableRuntimeBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StableRuntimeBinding")
            .field("authority_id", &"[redacted]")
            .field("principal_id", &self.principal_id)
            .field("lineage_id", &self.lineage_id)
            .field("profile_id", &self.profile_id)
            .finish_non_exhaustive()
    }
}

/// Launch-specific identity which cannot be reused across daemon restarts.
#[derive(Clone, PartialEq, Eq)]
pub struct EphemeralRuntimeBinding {
    daemon_instance_id: DaemonInstanceId,
    launch_generation: u64,
    session_id: [u8; 16],
    authorization_epoch: u64,
    sensitivity_ceiling: Sensitivity,
}

impl EphemeralRuntimeBinding {
    /// Creates an ephemeral binding for one local daemon launch.
    pub fn new(
        daemon_instance_id: DaemonInstanceId,
        launch_generation: u64,
        authorization_epoch: u64,
        sensitivity_ceiling: Sensitivity,
    ) -> Result<Self, LocalSessionContractError> {
        validate_uuid_v7_bytes(daemon_instance_id.as_bytes())
            .map_err(LocalSessionContractError::InvalidDaemonInstanceId)?;
        if launch_generation == 0 {
            return Err(LocalSessionContractError::InvalidLaunchGeneration);
        }
        Ok(Self {
            daemon_instance_id,
            launch_generation,
            session_id: daemon_instance_id.into_bytes(),
            authorization_epoch,
            sensitivity_ceiling,
        })
    }

    pub const fn daemon_instance_id(&self) -> DaemonInstanceId {
        self.daemon_instance_id
    }
    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }
    pub const fn authorization_epoch(&self) -> u64 {
        self.authorization_epoch
    }
    pub const fn sensitivity_ceiling(&self) -> Sensitivity {
        self.sensitivity_ceiling
    }
}

impl core::fmt::Debug for EphemeralRuntimeBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EphemeralRuntimeBinding")
            .field("daemon_instance_id", &self.daemon_instance_id)
            .field("launch_generation", &self.launch_generation)
            .field("authorization_epoch", &self.authorization_epoch)
            .field("sensitivity_ceiling", &self.sensitivity_ceiling)
            .finish_non_exhaustive()
    }
}

/// Complete local session binding joining stable authority and one launch.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeSessionBinding {
    stable: StableRuntimeBinding,
    ephemeral: EphemeralRuntimeBinding,
    certificate_sha256: [u8; 32],
}

impl RuntimeSessionBinding {
    /// Creates a session binding for one daemon launch.
    pub fn new(
        stable: StableRuntimeBinding,
        daemon_instance_id: DaemonInstanceId,
        launch_generation: u64,
        authorization_epoch: u64,
        sensitivity_ceiling: Sensitivity,
    ) -> Result<Self, LocalSessionContractError> {
        let ephemeral = EphemeralRuntimeBinding::new(
            daemon_instance_id,
            launch_generation,
            authorization_epoch,
            sensitivity_ceiling,
        )?;
        Ok(Self {
            stable,
            ephemeral,
            certificate_sha256: [0; 32],
        })
    }

    pub const fn stable(&self) -> &StableRuntimeBinding {
        &self.stable
    }
    pub const fn ephemeral(&self) -> &EphemeralRuntimeBinding {
        &self.ephemeral
    }
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }
}

impl core::fmt::Debug for RuntimeSessionBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RuntimeSessionBinding")
            .field("stable", &self.stable)
            .field("ephemeral", &self.ephemeral)
            .finish_non_exhaustive()
    }
}

/// Stable validation failures for local session contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalSessionContractError {
    /// The authority identity is not a UUIDv7.
    InvalidAuthorityId(InvalidIdReason),
    /// The daemon instance identity is not a UUIDv7.
    InvalidDaemonInstanceId(InvalidIdReason),
    /// The selected runtime profile is empty.
    EmptyProfileId,
    /// The capability digest is all zeroes.
    EmptyCapabilityDigest,
    /// The daemon launch generation must be positive.
    InvalidLaunchGeneration,
    /// A replay contract named a different authorization epoch.
    AuthorizationEpochMismatch,
    /// A replay contract named a different sensitivity ceiling.
    SensitivityCeilingMismatch,
}
