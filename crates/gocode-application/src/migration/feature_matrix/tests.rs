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
