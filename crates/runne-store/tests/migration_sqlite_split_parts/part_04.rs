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

fn gate_evidence(family: GateFamily, suffix: u8) -> GateEvidence {
    GateEvidence {
        gate_id: GateId::new(format!("gate-{suffix}")).unwrap(),
        gate_revision: 1,
        family,
        source_generation: source_generation(),
        candidate_generation: candidate_generation(),
        cohort: routing_unit().cohort,
        contract_digest: routing_unit().contract_digest,
        profile_digest: routing_unit().feature_profile.profile_digest,
        config_digest: routing_unit().config_digest,
        measured_at: Timestamp::from_unix_micros(50),
        valid_until: Timestamp::from_unix_micros(300),
        status: GateStatus::Passed,
        evidence_digest: ArtifactDigest::from_bytes([suffix; 32]),
    }
}

fn rollback_input() -> StartRollbackInput {
    let rollback_plan = MigrationPlan {
        plan_id: MigrationPlanId::new("plan-rollback-1").unwrap(),
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
    };
    StartRollbackInput {
        parent_plan_id: plan_id(),
        rollback_plan,
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

fn stage_context() -> MigrationCommandContext {
    command_context(1, 0, None)
}

fn command_context(
    command_suffix: u8,
    expected_plan_version: u64,
    expected_routing_generation: Option<RoutingGeneration>,
) -> MigrationCommandContext {
    MigrationCommandContext {
        command_id: format!("018f2e3a-8d5c-7b20-8d9a-{command_suffix:012x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("migration-{command_suffix}")).unwrap(),
        operator_id: OperatorId::new("operator-1").unwrap(),
        expected_plan_version,
        expected_routing_generation,
        evaluated_at: Timestamp::from_unix_micros(100),
    }
}

fn prepare_cutover_input(
    evidence_set_digest: ArtifactDigest,
    source_high_water: u64,
) -> PrepareCutoverInput {
    PrepareCutoverInput {
        plan_id: plan_id(),
        intent: CutoverIntent::InternalCanary,
        rollout_policy: CutoverPolicy::InternalCanary(
            CanaryPolicy::new(routing_unit().cohort, 64).unwrap(),
        ),
        manifest: artifact("cutover-manifest", 30),
        source_release: artifact("source-release", 31),
        candidate_release: artifact("candidate-release", 32),
        frozen_evidence_set: ArtifactRef::new("artifact://evidence-set", evidence_set_digest)
            .unwrap(),
        migration_report: MigrationReport::new(MigrationReportFields {
            report: artifact("migration-report", 33),
            plan_id: plan_id(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            source_snapshot: artifact("source-snapshot", 34),
            source_high_water,
            source_generation: source_generation(),
            candidate_generation: candidate_generation(),
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
            mapping: artifact("mapping", 35),
            profile: artifact("profile", 1),
            integrity: ArtifactValidation::Passed,
            rebuild: ArtifactValidation::Passed,
            disposition: ImportDisposition::Clean,
            created_at: Timestamp::from_unix_micros(90),
        })
        .unwrap(),
        drain_report: DrainReportArtifact {
            report: artifact("drain-report", 36),
            complete: true,
            timed_out: false,
            unresolved_effects: 0,
            source_high_water,
        },
        candidate_validation: CandidateValidationReport {
            report: artifact("candidate-validation", 37),
            validation: ArtifactValidation::Passed,
        },
        rollback_policy: RollbackPolicy::BeforeCandidateWrites,
        retention_until: Timestamp::from_unix_micros(1_000),
        operator_authorization: artifact("operator-authorization", 38),
    }
}

fn artifact(name: &str, byte: u8) -> ArtifactRef {
    ArtifactRef::new(
        format!("artifact://{name}"),
        ArtifactDigest::from_bytes([byte; 32]),
    )
    .unwrap()
}

fn fingerprint(suffix: u8) -> MigrationCommandFingerprint {
    MigrationCommandFingerprint::from_bytes([suffix; 32])
}

fn audit(
    context: &MigrationCommandContext,
    plan: &MigrationPlan,
    action: MigrationAuditAction,
    suffix: u8,
) -> MigrationAuditRecord {
    MigrationAuditRecord {
        record_id: ArtifactDigest::from_bytes([suffix; 32]),
        plan_id: plan.plan_id.clone(),
        command_id: context.command_id,
        operator_id: context.operator_id.clone(),
        action,
        recorded_at: Timestamp::from_unix_micros(i64::from(suffix)),
    }
}

fn transition(identity: &str, plan: &MigrationPlan) -> MigrationTransition {
    MigrationTransition {
        transition_id: identity.to_owned(),
        plan_id: plan.plan_id.clone(),
        cycle_id: plan.cycle_id.clone(),
        from: MigrationPhase::Baseline,
        to: MigrationPhase::Baseline,
        plan_version: plan.plan_version,
        occurred_at: Timestamp::from_unix_micros(1),
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

fn source_snapshot(routing_generation: RoutingGeneration) -> RoutingSnapshot {
    RoutingSnapshot::new(
        routing_generation,
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

fn plan_id() -> MigrationPlanId {
    MigrationPlanId::new("plan-1").unwrap()
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

fn durable_counts(connection: &Connection) -> [i64; 5] {
    [
        row_count(connection, "migration_plans"),
        row_count(connection, "routing_snapshots"),
        row_count(connection, "routing_head"),
        row_count(connection, "migration_receipts"),
        row_count(connection, "migration_audit"),
    ]
}
