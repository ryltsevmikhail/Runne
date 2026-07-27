use core::fmt;

use sha2::{Digest, Sha256};

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingUnit {
    pub deployment: DeploymentId,
    pub cohort: CohortSelector,
    pub feature_profile: FeatureProfileRef,
    pub contract_digest: ArtifactDigest,
    pub schema_digest: ArtifactDigest,
    pub config_digest: ArtifactDigest,
}

impl RoutingUnit {
    pub fn digest(&self) -> ArtifactDigest {
        let mut hasher = Sha256::new();
        hasher.update(ROUTING_UNIT_DOMAIN_PREFIX);
        update_length_prefixed(&mut hasher, self.deployment.as_str());
        hasher.update((self.cohort.dimensions().len() as u16).to_be_bytes());
        for dimension in self.cohort.dimensions() {
            update_length_prefixed(&mut hasher, dimension.key());
            update_length_prefixed(&mut hasher, dimension.value());
        }
        update_length_prefixed(&mut hasher, &self.feature_profile.profile_id);
        hasher.update(self.feature_profile.profile_revision.to_be_bytes());
        hasher.update(self.contract_digest.as_bytes());
        hasher.update(self.schema_digest.as_bytes());
        hasher.update(self.config_digest.as_bytes());
        ArtifactDigest::from_bytes(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum GateFamily {
    StoreIntegrity = 1,
    CanonicalAudit = 2,
    SecurityPolicy = 3,
    PlatformCertification = 4,
    RuntimeHealth = 5,
    RecoveryReadiness = 6,
    DrainReadiness = 7,
    RollbackReadiness = 8,
    CapacitySlo = 9,
    ShadowIsolation = 10,
}

impl GateFamily {
    pub const ALL: [Self; 10] = [
        Self::StoreIntegrity,
        Self::CanonicalAudit,
        Self::SecurityPolicy,
        Self::PlatformCertification,
        Self::RuntimeHealth,
        Self::RecoveryReadiness,
        Self::DrainReadiness,
        Self::RollbackReadiness,
        Self::CapacitySlo,
        Self::ShadowIsolation,
    ];
}

fn validate_bounded_string(
    value: String,
    field: &'static str,
    max: usize,
) -> Result<String, MigrationValueError> {
    if value.is_empty() {
        return Err(MigrationValueError::Empty { field });
    }
    if value.len() > max {
        return Err(MigrationValueError::TooLong {
            field,
            max,
            actual: value.len(),
        });
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return Err(MigrationValueError::ControlCharacter { field });
    }
    Ok(value)
}

fn update_length_prefixed(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update((bytes.len() as u16).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_reject_empty_control_and_oversized_values() {
        assert!(MigrationPlanId::new("").is_err());
        assert!(MigrationPlanId::new("bad\nplan").is_err());
        assert!(MigrationPlanId::new("x".repeat(MAX_MIGRATION_ID_BYTES + 1)).is_err());
    }

    #[test]
    fn routing_unit_digest_is_canonical_and_domain_separated() {
        let unit = test_routing_unit();
        assert_eq!(
            unit.digest().to_string(),
            "sha256:deac818dd599a0d7b8e1974203a63e9044de37c6833f5d946d8fa0da3f7b36fa"
        );
    }

    #[test]
    fn cohort_selector_rejects_untrusted_dimensions() {
        assert!(
            CohortSelector::new(vec![
                CohortDimension::new("taskrun_id", "018f2e3a").unwrap()
            ])
            .is_err()
        );
    }

    fn test_routing_unit() -> RoutingUnit {
        RoutingUnit {
            deployment: DeploymentId::new("production").unwrap(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
                CohortDimension::new("deployment_mode", "public").unwrap(),
            ])
            .unwrap(),
            feature_profile: FeatureProfileRef::new(
                "default",
                1,
                ArtifactDigest::from_bytes([1; 32]),
            )
            .unwrap(),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            schema_digest: ArtifactDigest::from_bytes([3; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
        }
    }
}
