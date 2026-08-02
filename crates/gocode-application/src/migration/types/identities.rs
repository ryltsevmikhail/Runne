use core::fmt;

use gocode_domain::{id::AggregateId, timestamp::Timestamp};
use sha2::{Digest, Sha256};

use super::state::MigrationPhase;

pub const MAX_MIGRATION_ID_BYTES: usize = 128;
pub const MAX_COHORT_DIMENSIONS: usize = 16;
pub const MAX_COHORT_KEY_BYTES: usize = 64;
pub const MAX_COHORT_VALUE_BYTES: usize = 128;

const ALLOWED_COHORT_KEYS: &[&str] = &[
    "deployment_mode",
    "project_class",
    "client_class",
    "feature_profile",
];
const ROUTING_UNIT_DOMAIN_PREFIX: &[u8] = b"gocode-routing-unit\x01";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationValueError {
    Empty {
        field: &'static str,
    },
    TooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    ControlCharacter {
        field: &'static str,
    },
    UnsupportedCohortDimension {
        key: String,
    },
    DuplicateCohortDimension {
        key: String,
    },
    TooManyCohortDimensions {
        max: usize,
        actual: usize,
    },
    ZeroRoutingGeneration,
    SourceAndCandidateMustDiffer,
    CandidateAuthorityBeforeCanary,
    AuthorityGenerationMismatch,
    BindingAuthorityGenerationMismatch,
    RoutingUnitSnapshotMismatch,
    ZeroFencingToken,
    ZeroProfileRevision,
}

macro_rules! migration_identity {
    ($name:ident, $field:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, MigrationValueError> {
                Ok(Self(validate_bounded_string(
                    value.into(),
                    $field,
                    MAX_MIGRATION_ID_BYTES,
                )?))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

migration_identity!(MigrationPlanId, "migration_plan_id");
migration_identity!(MigrationCycleId, "migration_cycle_id");
migration_identity!(DeploymentId, "deployment_id");
migration_identity!(RuntimeGenerationRef, "runtime_generation_ref");
migration_identity!(GateId, "gate_id");
migration_identity!(GatePolicyRef, "gate_policy_ref");
migration_identity!(OperatorId, "operator_id");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactDigest([u8; 32]);

impl ArtifactDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for ArtifactDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoutingGeneration(u64);

impl RoutingGeneration {
    pub fn new(value: u64) -> Result<Self, MigrationValueError> {
        if value == 0 {
            Err(MigrationValueError::ZeroRoutingGeneration)
        } else {
            Ok(Self(value))
        }
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FencingToken([u8; 32]);

impl FencingToken {
    pub fn new(bytes: [u8; 32]) -> Result<Self, MigrationValueError> {
        if bytes == [0; 32] {
            Err(MigrationValueError::ZeroFencingToken)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeAuthority {
    Source(RuntimeGenerationRef),
    Candidate(RuntimeGenerationRef),
}

impl RuntimeAuthority {
    fn generation(&self) -> &RuntimeGenerationRef {
        match self {
            Self::Source(generation) | Self::Candidate(generation) => generation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackDisposition {
    Eligible,
    Ineligible,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CohortDimension {
    key: String,
    value: String,
}

impl CohortDimension {
    pub fn new(
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, MigrationValueError> {
        Ok(Self {
            key: validate_bounded_string(key.into(), "cohort_key", MAX_COHORT_KEY_BYTES)?,
            value: validate_bounded_string(value.into(), "cohort_value", MAX_COHORT_VALUE_BYTES)?,
        })
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CohortSelector(Vec<CohortDimension>);

impl CohortSelector {
    pub fn new(mut dimensions: Vec<CohortDimension>) -> Result<Self, MigrationValueError> {
        if dimensions.len() > MAX_COHORT_DIMENSIONS {
            return Err(MigrationValueError::TooManyCohortDimensions {
                max: MAX_COHORT_DIMENSIONS,
                actual: dimensions.len(),
            });
        }
        for dimension in &dimensions {
            if !ALLOWED_COHORT_KEYS.contains(&dimension.key()) {
                return Err(MigrationValueError::UnsupportedCohortDimension {
                    key: dimension.key.clone(),
                });
            }
        }
        dimensions.sort();
        if let Some(dimension) = dimensions
            .windows(2)
            .find(|pair| pair[0].key == pair[1].key)
            .map(|pair| &pair[0])
        {
            return Err(MigrationValueError::DuplicateCohortDimension {
                key: dimension.key.clone(),
            });
        }
        Ok(Self(dimensions))
    }

    pub fn dimensions(&self) -> &[CohortDimension] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FeatureProfileRef {
    pub profile_id: String,
    pub profile_revision: u16,
    pub profile_digest: ArtifactDigest,
}

impl FeatureProfileRef {
    pub fn new(
        profile_id: impl Into<String>,
        profile_revision: u16,
        profile_digest: ArtifactDigest,
    ) -> Result<Self, MigrationValueError> {
        if profile_revision == 0 {
            return Err(MigrationValueError::ZeroProfileRevision);
        }
        Ok(Self {
            profile_id: validate_bounded_string(
                profile_id.into(),
                "profile_id",
                MAX_MIGRATION_ID_BYTES,
            )?,
            profile_revision,
            profile_digest,
        })
    }
}
