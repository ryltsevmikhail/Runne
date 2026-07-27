//! Exact release feature claims used by production migration routing.

use std::collections::BTreeMap;

use super::{
    error::MigrationError,
    platform::{
        FilesystemClass, PlatformArchitecture, PlatformOs, PlatformTuple, PlatformVfs, ProcessModel,
    },
    types::{ArtifactDigest, FeatureProfileRef},
};

const MAX_RELEASE_ID_BYTES: usize = 128;

/// Lifecycle status of one exact feature claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureStatus {
    /// Contract exists but has no implementation.
    Specified,
    /// Implementation is scheduled.
    Planned,
    /// Code exists without complete production evidence.
    Implemented,
    /// Exact claim passed its governed evidence gates.
    Verified,
    /// The implementation is known to be incompatible.
    Incompatible,
    /// The feature is intentionally unsupported.
    Unsupported,
    /// Work is deferred outside the current release.
    Deferred,
}

/// Exact lookup key required before routing one feature profile to Candidate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FeatureClaimRequest {
    /// Exact runtime release identity.
    pub runtime_release: String,
    /// Exact certified platform tuple.
    pub platform: PlatformTuple,
    /// Full pinned source baseline commit SHA.
    pub source_baseline_sha: String,
    /// Feature profile identity, revision and artifact digest.
    pub feature_profile: FeatureProfileRef,
    /// Canonical contract digest.
    pub contract_digest: ArtifactDigest,
    /// Canonical schema digest.
    pub schema_digest: ArtifactDigest,
    /// Compatibility profile digest.
    pub profile_digest: ArtifactDigest,
    /// Translation mapping digest.
    pub mapping_digest: ArtifactDigest,
    /// Exact runtime configuration digest.
    pub config_digest: ArtifactDigest,
}

/// One release claim and the evidence establishing its current status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFeatureClaim {
    /// Exact runtime release identity.
    pub runtime_release: String,
    /// Exact certified platform tuple.
    pub platform: PlatformTuple,
    /// Full pinned source baseline commit SHA.
    pub source_baseline_sha: String,
    /// Feature profile identity, revision and artifact digest.
    pub feature_profile: FeatureProfileRef,
    /// Canonical contract digest.
    pub contract_digest: ArtifactDigest,
    /// Canonical schema digest.
    pub schema_digest: ArtifactDigest,
    /// Compatibility profile digest.
    pub profile_digest: ArtifactDigest,
    /// Translation mapping digest.
    pub mapping_digest: ArtifactDigest,
    /// Exact runtime configuration digest.
    pub config_digest: ArtifactDigest,
    /// Current claim lifecycle status.
    pub status: FeatureStatus,
    /// Canonical governed evidence artifact digest.
    pub evidence_digest: ArtifactDigest,
}

impl From<&ReleaseFeatureClaim> for FeatureClaimRequest {
    fn from(claim: &ReleaseFeatureClaim) -> Self {
        Self {
            runtime_release: claim.runtime_release.clone(),
            platform: claim.platform.clone(),
            source_baseline_sha: claim.source_baseline_sha.clone(),
            feature_profile: claim.feature_profile.clone(),
            contract_digest: claim.contract_digest,
            schema_digest: claim.schema_digest,
            profile_digest: claim.profile_digest,
            mapping_digest: claim.mapping_digest,
            config_digest: claim.config_digest,
        }
    }
}

/// Closed feature-registry mutation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureMatrixError {
    /// Claim contains an invalid identity, platform extension or zero digest.
    InvalidClaim,
    /// The exact immutable key was already registered with changed semantics.
    ConflictingClaim,
}

/// Exact, wildcard-free registry of release feature claims.
#[derive(Debug, Clone, Default)]
pub struct VerifiedFeatureRegistry {
    claims: BTreeMap<FeatureClaimRequest, ReleaseFeatureClaim>,
}

impl VerifiedFeatureRegistry {
    /// Insert one immutable exact claim.
    ///
    /// Repeating the byte-semantically identical claim is idempotent.
    pub fn insert(&mut self, claim: ReleaseFeatureClaim) -> Result<(), FeatureMatrixError> {
        validate_claim(&claim)?;
        let key = FeatureClaimRequest::from(&claim);
        if let Some(existing) = self.claims.get(&key) {
            return if existing == &claim {
                Ok(())
            } else {
                Err(FeatureMatrixError::ConflictingClaim)
            };
        }
        self.claims.insert(key, claim);
        Ok(())
    }

    /// Require one exact claim to be present and verified.
    pub fn require_verified(
        &self,
        request: &FeatureClaimRequest,
    ) -> Result<&ReleaseFeatureClaim, MigrationError> {
        if let Some(claim) = self.claims.get(request) {
            return if claim.status == FeatureStatus::Verified {
                Ok(claim)
            } else {
                Err(MigrationError::UnsupportedFeatureProfile)
            };
        }

        if self.claims.keys().any(|candidate| {
            candidate.feature_profile.profile_id == request.feature_profile.profile_id
                && candidate.feature_profile.profile_revision
                    == request.feature_profile.profile_revision
        }) {
            Err(MigrationError::RoutingUnitMismatch)
        } else {
            Err(MigrationError::UnsupportedFeatureProfile)
        }
    }
}

fn validate_claim(claim: &ReleaseFeatureClaim) -> Result<(), FeatureMatrixError> {
    if !valid_bounded(&claim.runtime_release, MAX_RELEASE_ID_BYTES)
        || claim.source_baseline_sha.len() != 40
        || !claim
            .source_baseline_sha
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !valid_platform(&claim.platform)
        || [
            claim.feature_profile.profile_digest,
            claim.contract_digest,
            claim.schema_digest,
            claim.profile_digest,
            claim.mapping_digest,
            claim.config_digest,
            claim.evidence_digest,
        ]
        .iter()
        .any(|digest| digest.as_bytes() == &[0; 32])
    {
        return Err(FeatureMatrixError::InvalidClaim);
    }
    Ok(())
}

fn valid_platform(platform: &PlatformTuple) -> bool {
    valid_os(&platform.os)
        && valid_architecture(&platform.architecture)
        && valid_filesystem(&platform.filesystem)
        && valid_vfs(&platform.vfs)
        && valid_process_model(&platform.process_model)
        && platform.sandbox_profile_digest.as_bytes() != &[0; 32]
}

fn valid_os(value: &PlatformOs) -> bool {
    !matches!(value, PlatformOs::Other(extension) if !valid_bounded(extension, 64))
}

fn valid_architecture(value: &PlatformArchitecture) -> bool {
    !matches!(value, PlatformArchitecture::Other(extension) if !valid_bounded(extension, 64))
}

fn valid_filesystem(value: &FilesystemClass) -> bool {
    !matches!(value, FilesystemClass::Other(extension) if !valid_bounded(extension, 64))
}

fn valid_vfs(value: &PlatformVfs) -> bool {
    !matches!(value, PlatformVfs::Other(extension) if !valid_bounded(extension, 64))
}

fn valid_process_model(value: &ProcessModel) -> bool {
    !matches!(value, ProcessModel::Other(extension) if !valid_bounded(extension, 64))
}

fn valid_bounded(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{
        error::MigrationError,
        platform::{
            FilesystemClass, PlatformArchitecture, PlatformOs, PlatformTuple, PlatformVfs,
            ProcessModel,
        },
        types::{ArtifactDigest, FeatureProfileRef},
    };

    #[test]
    fn only_verified_exact_claim_is_production_routable() {
        let mut registry = VerifiedFeatureRegistry::default();
        registry
            .insert(claim("taskrun", FeatureStatus::Verified))
            .unwrap();
        registry
            .insert(claim("messages", FeatureStatus::Implemented))
            .unwrap();
        registry
            .insert(claim("tools", FeatureStatus::Unsupported))
            .unwrap();

        assert!(registry.require_verified(&request("taskrun", 4)).is_ok());
        assert_eq!(
            registry.require_verified(&request("messages", 4)),
            Err(MigrationError::UnsupportedFeatureProfile)
        );
        assert_eq!(
            registry.require_verified(&request("taskrun", 99)),
            Err(MigrationError::RoutingUnitMismatch)
        );
    }

    #[test]
    fn duplicate_conflicting_claim_is_rejected() {
        let mut registry = VerifiedFeatureRegistry::default();
        registry
            .insert(claim("taskrun", FeatureStatus::Verified))
            .unwrap();
        let mut conflicting = claim("taskrun", FeatureStatus::Verified);
        conflicting.evidence_digest = digest(99);

        assert_eq!(
            registry.insert(conflicting),
            Err(FeatureMatrixError::ConflictingClaim)
        );
    }

    fn claim(profile_id: &str, status: FeatureStatus) -> ReleaseFeatureClaim {
        ReleaseFeatureClaim {
            runtime_release: "gocode-runtime-0.1.0".into(),
            platform: platform(),
            source_baseline_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
            feature_profile: FeatureProfileRef::new(profile_id, 1, digest(3)).unwrap(),
            contract_digest: digest(4),
            schema_digest: digest(5),
            profile_digest: digest(6),
            mapping_digest: digest(7),
            config_digest: digest(8),
            status,
            evidence_digest: digest(9),
        }
    }

    fn request(profile_id: &str, contract_digest: u8) -> FeatureClaimRequest {
        let mut request = FeatureClaimRequest::from(&claim(profile_id, FeatureStatus::Verified));
        request.contract_digest = digest(contract_digest);
        request
    }

    fn platform() -> PlatformTuple {
        PlatformTuple {
            os: PlatformOs::MacOs,
            architecture: PlatformArchitecture::Aarch64,
            filesystem: FilesystemClass::LocalDurable,
            vfs: PlatformVfs::AppleFullFsync,
            process_model: ProcessModel::Sandboxed,
            sandbox_profile_digest: digest(2),
        }
    }

    fn digest(value: u8) -> ArtifactDigest {
        ArtifactDigest::from_bytes([value; 32])
    }
}
