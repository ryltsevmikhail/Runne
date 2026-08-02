fn required_evidence_for(target: MigrationPhase) -> MigrationEvidence {
    match target {
        MigrationPhase::Foundation => MigrationEvidence::Baseline {
            source_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".to_owned(),
            inventory_digest: ArtifactDigest::from_bytes([8; 32]),
            fixture_digest: ArtifactDigest::from_bytes([9; 32]),
        },
        MigrationPhase::ReadOnlyParity => MigrationEvidence::Foundation {
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            store_integrity_digest: ArtifactDigest::from_bytes([10; 32]),
            deterministic_test_digest: ArtifactDigest::from_bytes([11; 32]),
        },
        MigrationPhase::SimulatedShadow => MigrationEvidence::ReadOnlyParity {
            import_report_digest: ArtifactDigest::from_bytes([12; 32]),
            completeness_digest: ArtifactDigest::from_bytes([13; 32]),
            canonical_mutation_count: 0,
        },
        other => panic!("no source-only evidence fixture for {other:?}"),
    }
}

fn test_plan() -> MigrationPlan {
    MigrationPlan {
        plan_id: plan_id(),
        cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
        cycle_kind: MigrationCycleKind::Forward,
        source: source_generation(),
        candidate: candidate_generation(),
        phase: MigrationPhase::Baseline,
        status: MigrationPlanStatus::Active,
        routing_unit: routing_unit(),
        gate_policy: GatePolicyRef::new("policy-v1").unwrap(),
        plan_version: 0,
        created_at: Timestamp::from_unix_micros(1),
    }
}

fn source_snapshot() -> RoutingSnapshot {
    RoutingSnapshot::new(
        RoutingGeneration::new(1).unwrap(),
        source_generation(),
        candidate_generation(),
        MigrationPhase::Baseline,
        RuntimeAuthority::Source(source_generation()),
        routing_unit(),
        FencingToken::new([7; 32]).unwrap(),
        RollbackDisposition::Eligible,
        Timestamp::from_unix_micros(1),
    )
    .unwrap()
}

fn rollback_input() -> StartRollbackInput {
    StartRollbackInput {
        parent_plan_id: plan_id(),
        rollback_plan: MigrationPlan {
            plan_id: rollback_plan_id(),
            cycle_id: MigrationCycleId::new("cycle-rollback-1").unwrap(),
            cycle_kind: MigrationCycleKind::Rollback {
                parent_cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            },
            source: candidate_generation(),
            candidate: source_generation(),
            phase: MigrationPhase::Baseline,
            status: MigrationPlanStatus::Active,
            routing_unit: routing_unit(),
            gate_policy: GatePolicyRef::new("policy-v1").unwrap(),
            plan_version: 0,
            created_at: Timestamp::from_unix_micros(20),
        },
        initial_snapshot: RoutingSnapshot::new(
            RoutingGeneration::new(2).unwrap(),
            candidate_generation(),
            source_generation(),
            MigrationPhase::Baseline,
            RuntimeAuthority::Source(candidate_generation()),
            routing_unit(),
            FencingToken::new([8; 32]).unwrap(),
            RollbackDisposition::Eligible,
            Timestamp::from_unix_micros(20),
        )
        .unwrap(),
    }
}

fn plan_id() -> MigrationPlanId {
    MigrationPlanId::new("plan-1").unwrap()
}

fn rollback_plan_id() -> MigrationPlanId {
    MigrationPlanId::new("plan-rollback-1").unwrap()
}

fn source_generation() -> RuntimeGenerationRef {
    RuntimeGenerationRef::new("runtime-legacy").unwrap()
}

fn candidate_generation() -> RuntimeGenerationRef {
    RuntimeGenerationRef::new("runtime-native").unwrap()
}

fn routing_unit() -> RoutingUnit {
    RoutingUnit {
        deployment: DeploymentId::new("production").unwrap(),
        cohort: CohortSelector::new(vec![
            CohortDimension::new("client_class", "premium").unwrap(),
        ])
        .unwrap(),
        feature_profile: FeatureProfileRef::new("default", 1, ArtifactDigest::from_bytes([1; 32]))
            .unwrap(),
        contract_digest: ArtifactDigest::from_bytes([2; 32]),
        schema_digest: ArtifactDigest::from_bytes([3; 32]),
        config_digest: ArtifactDigest::from_bytes([4; 32]),
    }
}

fn unrelated_routing_unit() -> RoutingUnit {
    RoutingUnit {
        deployment: DeploymentId::new("production").unwrap(),
        cohort: CohortSelector::new(vec![
            CohortDimension::new("client_class", "standard").unwrap(),
        ])
        .unwrap(),
        feature_profile: FeatureProfileRef::new("default", 1, ArtifactDigest::from_bytes([1; 32]))
            .unwrap(),
        contract_digest: ArtifactDigest::from_bytes([2; 32]),
        schema_digest: ArtifactDigest::from_bytes([3; 32]),
        config_digest: ArtifactDigest::from_bytes([4; 32]),
    }
}

fn unrelated_source_snapshot() -> RoutingSnapshot {
    RoutingSnapshot::new(
        RoutingGeneration::new(1).unwrap(),
        source_generation(),
        candidate_generation(),
        MigrationPhase::Baseline,
        RuntimeAuthority::Source(source_generation()),
        unrelated_routing_unit(),
        FencingToken::new([6; 32]).unwrap(),
        RollbackDisposition::Eligible,
        Timestamp::from_unix_micros(1),
    )
    .unwrap()
}
