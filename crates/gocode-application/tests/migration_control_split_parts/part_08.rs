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

fn prepare_cohort_expansion_input(
    evidence_set_digest: ArtifactDigest,
    source_high_water: u64,
    rollout_step: RolloutStep,
    unresolved_effects: u64,
    artifact_byte: u8,
) -> PrepareCutoverInput {
    PrepareCutoverInput {
        plan_id: plan_id(),
        intent: CutoverIntent::CohortExpansion,
        rollout_policy: CutoverPolicy::CohortExpansion(rollout_step),
        manifest: artifact(&format!("cohort-manifest-{artifact_byte}"), artifact_byte),
        source_release: artifact("source-release", 31),
        candidate_release: artifact("candidate-release", 32),
        frozen_evidence_set: ArtifactRef::new("artifact://evidence-set", evidence_set_digest)
            .unwrap(),
        migration_report: MigrationReport::new(MigrationReportFields {
            report: artifact(
                &format!("cohort-migration-report-{artifact_byte}"),
                artifact_byte + 1,
            ),
            plan_id: plan_id(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            source_snapshot: artifact(
                &format!("cohort-source-snapshot-{artifact_byte}"),
                artifact_byte + 2,
            ),
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
            mapping: artifact(
                &format!("cohort-mapping-{artifact_byte}"),
                artifact_byte + 3,
            ),
            profile: artifact("profile", 1),
            integrity: ArtifactValidation::Passed,
            rebuild: ArtifactValidation::Passed,
            disposition: ImportDisposition::Clean,
            created_at: Timestamp::from_unix_micros(90),
        })
        .unwrap(),
        drain_report: DrainReportArtifact {
            report: artifact(
                &format!("cohort-drain-report-{artifact_byte}"),
                artifact_byte + 4,
            ),
            complete: true,
            timed_out: false,
            unresolved_effects,
            source_high_water,
        },
        candidate_validation: CandidateValidationReport {
            report: artifact(
                &format!("cohort-candidate-validation-{artifact_byte}"),
                artifact_byte + 5,
            ),
            validation: ArtifactValidation::Passed,
        },
        rollback_policy: RollbackPolicy::BeforeCandidateWrites,
        retention_until: Timestamp::from_unix_micros(1_000),
        operator_authorization: artifact(
            &format!("cohort-operator-authorization-{artifact_byte}"),
            artifact_byte + 6,
        ),
    }
}

fn valid_rollout_step(previous_generation: u64, admission_limit: u32) -> RolloutStep {
    RolloutStep::new(
        RoutingGeneration::new(previous_generation).unwrap(),
        routing_unit().cohort,
        admission_limit,
        Duration::from_micros(50),
        Timestamp::from_unix_micros(50),
        Timestamp::from_unix_micros(100),
        GatePolicyRef::new("policy-v1").unwrap(),
    )
    .unwrap()
}

fn artifact(name: &str, byte: u8) -> ArtifactRef {
    ArtifactRef::new(
        format!("artifact://{name}"),
        ArtifactDigest::from_bytes([byte; 32]),
    )
    .unwrap()
}

fn retirement_input() -> RetireSourceInput {
    let readiness = complete_retirement_readiness();
    RetireSourceInput {
        plan_id: plan_id(),
        manifest: RetirementManifest {
            manifest: artifact("retirement", 100),
            plan_id: plan_id(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            final_drain_report: artifact("final-drain", 101),
            reference_inventory_digest: readiness.reference_inventory.digest(),
            platform_verification_set: artifact("platform-verification", 102),
            closed_windows_evidence: artifact("closed-windows", 103),
            disabled_legacy_authority: artifact("disabled-legacy", 104),
            final_audit: artifact("final-audit", 105),
            removal_diff: artifact("removal-diff", 106),
            removal_suite: artifact("removal-suite", 107),
            retention_until: Timestamp::from_unix_micros(1_000),
            operator_authorization: artifact("retirement-authorization", 108),
            created_at: Timestamp::from_unix_micros(100),
        },
        readiness,
    }
}

fn complete_retirement_readiness() -> RetirementReadiness {
    let resolved = |byte| LegacyReferenceSet {
        blocking_count: 0,
        identity_digest: ArtifactDigest::from_bytes([byte; 32]),
        disposition: LegacyReferenceDisposition::Resolved,
    };
    RetirementReadiness {
        reference_inventory: LegacyReferenceInventory {
            active_and_in_flight: resolved(110),
            recovery_candidates: resolved(111),
            uncertain_effects: resolved(112),
            timers_processes_cleanup: resolved(113),
            replay_and_client_cursors: resolved(114),
            audit_and_retention: resolved(115),
            rollback_artifacts: resolved(116),
            credentials_packages_processes: resolved(117),
        },
        legacy_admission_closed: true,
        replacement_platforms_verified: true,
        migration_window_closed: true,
        rollback_window_closed: true,
        credentials_disabled: true,
        processes_disabled: true,
        packages_disabled: true,
        removal_suites_passed: true,
        final_audit_accepted: true,
    }
}

fn omit_retirement_requirement(
    readiness: &mut RetirementReadiness,
    requirement: RetirementRequirement,
) {
    match requirement {
        RetirementRequirement::ReferenceInventoryClear => {
            readiness
                .reference_inventory
                .active_and_in_flight
                .blocking_count = 1;
        }
        RetirementRequirement::LegacyAdmissionClosed => {
            readiness.legacy_admission_closed = false;
        }
        RetirementRequirement::ReplacementPlatformsVerified => {
            readiness.replacement_platforms_verified = false;
        }
        RetirementRequirement::MigrationWindowClosed => {
            readiness.migration_window_closed = false;
        }
        RetirementRequirement::RollbackWindowClosed => {
            readiness.rollback_window_closed = false;
        }
        RetirementRequirement::CredentialsDisabled => readiness.credentials_disabled = false,
        RetirementRequirement::ProcessesDisabled => readiness.processes_disabled = false,
        RetirementRequirement::PackagesDisabled => readiness.packages_disabled = false,
        RetirementRequirement::RemovalSuitesPassed => readiness.removal_suites_passed = false,
        RetirementRequirement::FinalAuditAccepted => readiness.final_audit_accepted = false,
    }
}

fn stage_context() -> MigrationCommandContext {
    command_context(0, None, 1)
}

fn command_context(
    expected_plan_version: u64,
    expected_routing_generation: Option<RoutingGeneration>,
    command_suffix: u64,
) -> MigrationCommandContext {
    MigrationCommandContext {
        command_id: format!("018f2e3a-8d5c-7b20-8d9a-{command_suffix:012x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("migration-command-{command_suffix}"))
            .unwrap(),
        operator_id: OperatorId::new("operator-1").unwrap(),
        expected_plan_version,
        expected_routing_generation,
        evaluated_at: Timestamp::from_unix_micros(100),
    }
}

fn stage_input() -> StagePlanInput {
    StagePlanInput {
        plan: test_plan(),
        initial_snapshot: source_snapshot(),
    }
}
