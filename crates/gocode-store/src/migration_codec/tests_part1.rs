    use gocode_application::migration::types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        FencingToken, MigrationCycleId, MigrationPlanId, RollbackDisposition, RoutingGeneration,
        RoutingSnapshot, RoutingUnit, RuntimeAuthority, RuntimeBinding, RuntimeGenerationRef,
    };
    use gocode_application::migration::{
        manifests::{
            ArtifactRef, ArtifactValidation, CandidateValidationReport, CutoverManifest,
            CutoverManifestFields, DrainReportArtifact, ImportDisposition, MigrationCounts,
            MigrationReport, MigrationReportFields, RollbackPolicy,
        },
        ports::CutoverIntent,
        rollout::{CanaryPolicy, CutoverPolicy, RolloutStep},
    };
    use gocode_domain::{
        id::{AggregateId, TaskRunId},
        timestamp::Timestamp,
    };

    use super::*;

    const GOLDEN_ROUTING_SNAPSHOT_HEX: &str = concat!(
        "010000000000000002",
        "000e72756e74696d652d6c6567616379",
        "000e72756e74696d652d6e6174697665",
        "0001",
        "000c636c69656e745f636c617373",
        "00077072656d69756d",
        "02",
        "000e72756e74696d652d6e6174697665",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0404040404040404040404040404040404040404040404040404040404040404",
        "0707070707070707070707070707070707070707070707070707070707070707",
        "01",
        "000000000000000a"
    );
    const GOLDEN_CUTOVER_MANIFEST_HEX: &str = "02001261727469666163743a2f2f6375746f7665720c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0006706c616e2d3100076379636c652d3101000a70726f64756374696f6e0001000c636c69656e745f636c61737300077072656d69756d000764656661756c7400010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404001961727469666163743a2f2f736f757263652d72656c656173650d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d000e72756e74696d652d6c6567616379001c61727469666163743a2f2f63616e6469646174652d72656c656173650e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e000e72756e74696d652d6e6174697665001761727469666163743a2f2f65766964656e63652d7365740f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f001861727469666163743a2f2f696d706f72742d7265706f72740808080808080808080808080808080808080808080808080808080808080808001761727469666163743a2f2f647261696e2d7265706f72741010101010101010101010101010101010101010101010101010101010101010001f61727469666163743a2f2f63616e6469646174652d76616c69646174696f6e1111111111111111111111111111111111111111111111111111111111111111000000000000002a000000000000000201000000000000012c002161727469666163743a2f2f6f70657261746f722d617574686f72697a6174696f6e121212121212121212121212121212121212121212121212121212121212121200186375746f7665722d707265706172653a76323a61613a62620000000000000011000000000000001200000000000000c8";

    #[test]
    fn routing_snapshot_codec_has_literal_golden_bytes() {
        let bytes = encode_routing_snapshot(&golden_snapshot()).unwrap();

        assert_eq!(hex(&bytes), GOLDEN_ROUTING_SNAPSHOT_HEX);
        assert_eq!(decode_routing_snapshot(&bytes).unwrap(), golden_snapshot());
    }

    #[test]
    fn migration_codec_rejects_unknown_version_and_trailing_bytes() {
        assert_eq!(
            decode_routing_snapshot(&[0xff]),
            Err(MigrationCodecError::UnknownVersion { actual: 255 })
        );

        let mut bytes = encode_routing_snapshot(&golden_snapshot()).unwrap();
        bytes.push(0);
        assert_eq!(
            decode_routing_snapshot(&bytes),
            Err(MigrationCodecError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn cutover_manifest_roundtrips_and_rejects_digest_corruption() {
        let manifest = golden_cutover_manifest();
        let bytes = encode_cutover_manifest(&manifest).unwrap();
        assert_eq!(hex(&bytes), golden_cutover_manifest_v5_hex());
        assert_eq!(decode_cutover_manifest(&bytes).unwrap(), manifest);

        let mut expansion = manifest.clone();
        expansion.intent = CutoverIntent::CohortExpansion;
        expansion.rollout_policy = CutoverPolicy::CohortExpansion(
            RolloutStep::new(
                RoutingGeneration::new(2).unwrap(),
                golden_routing_unit().cohort,
                2_048,
                Duration::from_micros(100),
                Timestamp::from_unix_micros(100),
                Timestamp::from_unix_micros(200),
                GatePolicyRef::new("policy-v1").unwrap(),
            )
            .unwrap(),
        );
        let expansion_bytes = encode_cutover_manifest(&expansion).unwrap();
        assert_eq!(
            decode_cutover_manifest(&expansion_bytes).unwrap(),
            expansion
        );

        let mut default_native = manifest.clone();
        default_native.intent = CutoverIntent::DefaultNative;
        default_native.rollout_policy = CutoverPolicy::DefaultNative(
            PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
                source_profile: golden_routing_unit().feature_profile,
            },
        );
        let default_native_bytes = encode_cutover_manifest(&default_native).unwrap();
        assert_eq!(
            decode_cutover_manifest(&default_native_bytes).unwrap(),
            default_native
        );

        let mut corrupt = bytes;
        corrupt[21..53].fill(0);
        assert_eq!(
            decode_cutover_manifest(&corrupt),
            Err(MigrationCodecError::InvalidValue { field: "manifest" })
        );
    }

    #[test]
    fn runtime_binding_codec_has_literal_bytes_and_rejects_trailing_data() {
        let generation = RuntimeGenerationRef::new("runtime-native").unwrap();
        let binding = RuntimeBinding::new(
            AggregateId::TaskRun(taskrun_id()),
            RuntimeAuthority::Candidate(generation.clone()),
            generation,
            RoutingGeneration::new(2).unwrap(),
            FencingToken::new([7; 32]).unwrap(),
            Timestamp::from_unix_micros(10),
        )
        .unwrap();
        let bytes = encode_runtime_binding(&binding).unwrap();

        assert_eq!(
            hex(&bytes),
            concat!(
                "0101",
                "018f2e3a8d5c7b208d9a000000000001",
                "02",
                "000e72756e74696d652d6e6174697665",
                "000e72756e74696d652d6e6174697665",
                "0000000000000002",
                "0707070707070707070707070707070707070707070707070707070707070707",
                "000000000000000a"
            )
        );
        assert_eq!(decode_runtime_binding(&bytes).unwrap(), binding);

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            decode_runtime_binding(&trailing),
            Err(MigrationCodecError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn report_rollback_and_retirement_codecs_are_closed_and_roundtrip() {
        let report = golden_migration_report();
        let report_bytes = encode_migration_report(&report).unwrap();
        assert_eq!(decode_migration_report(&report_bytes).unwrap(), report);

        let rollback = RollbackManifest {
            manifest: artifact("rollback", 20),
            plan_id: MigrationPlanId::new("rollback-plan").unwrap(),
            cycle_id: MigrationCycleId::new("rollback-cycle").unwrap(),
            parent_plan_id: MigrationPlanId::new("plan-1").unwrap(),
            routing_unit: golden_routing_unit(),
            candidate_high_water: 43,
            changed_state_inventory: artifact("changed-state", 21),
            reconciliation_report: artifact("reconciliation", 22),
            reverse_migration_contract: Some(artifact("reverse-contract", 23)),
            expected_routing_generation: RoutingGeneration::new(3).unwrap(),
            operator_authorization: artifact("rollback-authorization", 24),
            created_at: Timestamp::from_unix_micros(400),
        };
        let rollback_bytes = encode_rollback_manifest(&rollback).unwrap();
        assert_eq!(decode_rollback_manifest(&rollback_bytes).unwrap(), rollback);

        let retirement = RetirementManifest {
            manifest: artifact("retirement", 25),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            final_drain_report: artifact("final-drain", 26),
            reference_inventory_digest: ArtifactDigest::from_bytes([30; 32]),
            platform_verification_set: artifact("platform-verification", 31),
            closed_windows_evidence: artifact("closed-windows", 32),
            disabled_legacy_authority: artifact("disabled-legacy", 33),
            final_audit: artifact("final-audit", 27),
            removal_diff: artifact("removal-diff", 28),
            removal_suite: artifact("removal-suite", 34),
            retention_until: Timestamp::from_unix_micros(900),
            operator_authorization: artifact("retirement-authorization", 29),
            created_at: Timestamp::from_unix_micros(500),
        };
        let mut retirement_bytes = encode_retirement_manifest(&retirement).unwrap();
        assert_eq!(
            decode_retirement_manifest(&retirement_bytes).unwrap(),
            retirement
        );
        retirement_bytes.push(0);
        assert_eq!(
            decode_retirement_manifest(&retirement_bytes),
            Err(MigrationCodecError::TrailingBytes { remaining: 1 })
        );
    }
