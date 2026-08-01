    fn golden_snapshot() -> RoutingSnapshot {
        let source = RuntimeGenerationRef::new("runtime-legacy").unwrap();
        let candidate = RuntimeGenerationRef::new("runtime-native").unwrap();
        RoutingSnapshot {
            routing_generation: RoutingGeneration::new(2).unwrap(),
            source,
            candidate: candidate.clone(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
            ])
            .unwrap(),
            authority: RuntimeAuthority::Candidate(candidate),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            profile_digest: ArtifactDigest::from_bytes([1; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
            fencing_token: FencingToken::new([7; 32]).unwrap(),
            rollback_disposition: RollbackDisposition::Eligible,
            committed_at: Timestamp::from_unix_micros(10),
        }
    }

    fn golden_cutover_manifest_v5_hex() -> String {
        const INTENT_END: usize = 142;
        const POLICY_COHORT: &str = "0001000c636c69656e745f636c61737300077072656d69756d";
        let (prefix, suffix) = GOLDEN_CUTOVER_MANIFEST_HEX.split_at(INTENT_END);
        format!("05{}01{POLICY_COHORT}00000040{suffix}", &prefix[2..])
    }

    fn golden_cutover_manifest() -> CutoverManifest {
        let report = golden_migration_report();
        CutoverManifest::new(CutoverManifestFields {
            manifest: artifact("cutover", 12),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            intent: CutoverIntent::InternalCanary,
            rollout_policy: CutoverPolicy::InternalCanary(
                CanaryPolicy::new(golden_routing_unit().cohort, 64).unwrap(),
            ),
            routing_unit: golden_routing_unit(),
            source_release: artifact("source-release", 13),
            source_generation: RuntimeGenerationRef::new("runtime-legacy").unwrap(),
            candidate_release: artifact("candidate-release", 14),
            candidate_generation: RuntimeGenerationRef::new("runtime-native").unwrap(),
            frozen_evidence_set: artifact("evidence-set", 15),
            migration_report: report,
            drain_report: DrainReportArtifact {
                report: artifact("drain-report", 16),
                complete: true,
                timed_out: false,
                unresolved_effects: 0,
                source_high_water: 42,
            },
            candidate_validation: CandidateValidationReport {
                report: artifact("candidate-validation", 17),
                validation: ArtifactValidation::Passed,
            },
            expected_routing_generation: RoutingGeneration::new(2).unwrap(),
            routing_generation_at_prepare: RoutingGeneration::new(2).unwrap(),
            rollback_policy: RollbackPolicy::BeforeCandidateWrites,
            retention_until: Timestamp::from_unix_micros(300),
            operator_authorization: artifact("operator-authorization", 18),
            prepared_transition_id: "cutover-prepare:v2:aa:bb".to_owned(),
            expected_plan_version: 17,
            prepared_plan_version: 18,
            prepared_at: Timestamp::from_unix_micros(200),
        })
        .unwrap()
    }

    fn golden_migration_report() -> MigrationReport {
        MigrationReport::new(MigrationReportFields {
            report: artifact("import-report", 8),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            source_snapshot: artifact("source-snapshot", 9),
            source_high_water: 42,
            source_generation: RuntimeGenerationRef::new("runtime-legacy").unwrap(),
            candidate_generation: RuntimeGenerationRef::new("runtime-native").unwrap(),
            counts: MigrationCounts {
                imported: 10,
                skipped: 0,
                unsupported: 0,
                rejected: 0,
                unknown: 0,
                lossy: 0,
                ambiguous: 0,
            },
            schema: artifact("schema", 3),
            mapping: artifact("mapping", 11),
            profile: artifact("profile", 1),
            integrity: ArtifactValidation::Passed,
            rebuild: ArtifactValidation::Passed,
            disposition: ImportDisposition::Clean,
            created_at: Timestamp::from_unix_micros(100),
        })
        .unwrap()
    }

    fn golden_routing_unit() -> RoutingUnit {
        RoutingUnit {
            deployment: DeploymentId::new("production").unwrap(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
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

    fn artifact(name: &str, byte: u8) -> ArtifactRef {
        ArtifactRef::new(
            format!("artifact://{name}"),
            ArtifactDigest::from_bytes([byte; 32]),
        )
        .unwrap()
    }

    fn taskrun_id() -> TaskRunId {
        "018f2e3a-8d5c-7b20-8d9a-000000000001".parse().unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
