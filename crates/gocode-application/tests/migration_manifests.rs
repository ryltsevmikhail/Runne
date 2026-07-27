use gocode_application::migration::{
    error::MigrationError,
    manifests::{
        ArtifactRef, ArtifactValidation, CandidateValidationReport, CutoverManifest,
        CutoverManifestFields, DrainReportArtifact, ImportDisposition, MigrationCounts,
        MigrationReport, MigrationReportFields, RollbackPolicy,
    },
    ports::CutoverIntent,
    rollout::CanaryPolicy,
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        MigrationCycleId, MigrationPlanId, RoutingGeneration, RoutingUnit, RuntimeGenerationRef,
    },
};
use gocode_domain::timestamp::Timestamp;

#[test]
fn ambiguous_import_cannot_form_a_cutover_manifest() {
    let report = migration_report(MigrationCounts {
        imported: 10,
        skipped: 0,
        unsupported: 0,
        rejected: 0,
        unknown: 0,
        lossy: 0,
        ambiguous: 1,
    });

    assert_eq!(
        CutoverManifest::new(cutover_fields(report)),
        Err(MigrationError::ImportAmbiguous)
    );
}

#[test]
fn incomplete_drain_cannot_form_a_cutover_manifest() {
    let mut fields = cutover_fields(migration_report(MigrationCounts {
        imported: 10,
        skipped: 0,
        unsupported: 0,
        rejected: 0,
        unknown: 0,
        lossy: 0,
        ambiguous: 0,
    }));
    fields.drain_report.complete = false;

    assert_eq!(
        CutoverManifest::new(fields),
        Err(MigrationError::DrainIncomplete)
    );
}

#[test]
fn complete_artifacts_form_an_immutable_cutover_manifest() {
    let fields = cutover_fields(migration_report(MigrationCounts {
        imported: 10,
        skipped: 0,
        unsupported: 0,
        rejected: 0,
        unknown: 0,
        lossy: 0,
        ambiguous: 0,
    }));
    let manifest = CutoverManifest::new(fields.clone()).unwrap();

    assert_eq!(manifest.source_high_water, 42);
    assert_eq!(manifest.import_report, fields.migration_report.report);
    assert_eq!(
        manifest.expected_routing_generation,
        RoutingGeneration::new(7).unwrap()
    );
}

#[test]
fn missing_candidate_validation_and_stale_routing_generation_fail_closed() {
    let mut fields = cutover_fields(migration_report(MigrationCounts {
        imported: 10,
        skipped: 0,
        unsupported: 0,
        rejected: 0,
        unknown: 0,
        lossy: 0,
        ambiguous: 0,
    }));
    fields.candidate_validation.validation = ArtifactValidation::Failed;
    assert_eq!(
        CutoverManifest::new(fields),
        Err(MigrationError::ProductionGatesUnavailable)
    );

    let mut fields = cutover_fields(migration_report(MigrationCounts {
        imported: 10,
        skipped: 0,
        unsupported: 0,
        rejected: 0,
        unknown: 0,
        lossy: 0,
        ambiguous: 0,
    }));
    fields.routing_generation_at_prepare = RoutingGeneration::new(8).unwrap();
    assert_eq!(
        CutoverManifest::new(fields),
        Err(MigrationError::StorageContractViolation)
    );
}

#[test]
fn explicit_manual_disposition_allows_an_exact_ambiguous_range() {
    let mut report = migration_report(MigrationCounts {
        imported: 9,
        skipped: 1,
        unsupported: 0,
        rejected: 0,
        unknown: 0,
        lossy: 0,
        ambiguous: 1,
    });
    report.disposition = ImportDisposition::ManualAuthorized(artifact("manual-disposition", 19));
    let manifest = CutoverManifest::new(cutover_fields(report)).unwrap();

    assert_eq!(manifest.source_high_water, 42);
}

fn cutover_fields(migration_report: MigrationReport) -> CutoverManifestFields {
    CutoverManifestFields {
        manifest: artifact("cutover", 1),
        plan_id: plan_id(),
        cycle_id: cycle_id(),
        intent: CutoverIntent::InternalCanary,
        canary_policy: CanaryPolicy::new(routing_unit().cohort, 64).unwrap(),
        routing_unit: routing_unit(),
        source_release: artifact("source-release", 2),
        source_generation: RuntimeGenerationRef::new("source-v1").unwrap(),
        candidate_release: artifact("candidate-release", 3),
        candidate_generation: RuntimeGenerationRef::new("candidate-v1").unwrap(),
        frozen_evidence_set: artifact("evidence-set", 4),
        migration_report,
        drain_report: DrainReportArtifact {
            report: artifact("drain-report", 5),
            complete: true,
            timed_out: false,
            unresolved_effects: 0,
            source_high_water: 42,
        },
        candidate_validation: CandidateValidationReport {
            report: artifact("candidate-validation", 6),
            validation: ArtifactValidation::Passed,
        },
        expected_routing_generation: RoutingGeneration::new(7).unwrap(),
        routing_generation_at_prepare: RoutingGeneration::new(7).unwrap(),
        rollback_policy: RollbackPolicy::BeforeCandidateWrites,
        retention_until: Timestamp::from_unix_micros(20_000),
        operator_authorization: artifact("operator-authorization", 7),
        prepared_transition_id: "cutover-prepare:0123456789abcdef".to_owned(),
        expected_plan_version: 4,
        prepared_plan_version: 5,
        prepared_at: Timestamp::from_unix_micros(10_000),
    }
}

fn migration_report(counts: MigrationCounts) -> MigrationReport {
    MigrationReport::new(MigrationReportFields {
        report: artifact("import-report", 8),
        plan_id: plan_id(),
        cycle_id: cycle_id(),
        source_snapshot: artifact("source-snapshot", 9),
        source_high_water: 42,
        source_generation: RuntimeGenerationRef::new("source-v1").unwrap(),
        candidate_generation: RuntimeGenerationRef::new("candidate-v1").unwrap(),
        counts,
        schema: artifact("schema", 10),
        mapping: artifact("mapping", 11),
        profile: artifact("profile", 13),
        integrity: ArtifactValidation::Passed,
        rebuild: ArtifactValidation::Passed,
        disposition: ImportDisposition::Clean,
        created_at: Timestamp::from_unix_micros(9_000),
    })
    .unwrap()
}

fn routing_unit() -> RoutingUnit {
    RoutingUnit {
        deployment: DeploymentId::new("deployment-a").unwrap(),
        cohort: CohortSelector::new(vec![
            CohortDimension::new("deployment_mode", "internal").unwrap(),
        ])
        .unwrap(),
        feature_profile: FeatureProfileRef::new(
            "profile-a",
            1,
            ArtifactDigest::from_bytes([13; 32]),
        )
        .unwrap(),
        contract_digest: ArtifactDigest::from_bytes([14; 32]),
        schema_digest: ArtifactDigest::from_bytes([10; 32]),
        config_digest: ArtifactDigest::from_bytes([15; 32]),
    }
}

fn artifact(name: &str, byte: u8) -> ArtifactRef {
    ArtifactRef::new(
        format!("artifact://{name}"),
        ArtifactDigest::from_bytes([byte; 32]),
    )
    .unwrap()
}

fn plan_id() -> MigrationPlanId {
    MigrationPlanId::new("plan-a").unwrap()
}

fn cycle_id() -> MigrationCycleId {
    MigrationCycleId::new("cycle-a").unwrap()
}
