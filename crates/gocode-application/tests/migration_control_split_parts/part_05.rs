#[test]
fn rollback_cycle_can_commit_cutover_and_restore_source_authority() {
    let (service, _) = seeded_service();
    service
        .start_rollback_cycle(command_context(0, None, 50), rollback_input())
        .unwrap();

    let rb_plan_id = rollback_plan_id();
    for target in [
        MigrationPhase::Foundation,
        MigrationPhase::ReadOnlyParity,
        MigrationPhase::SimulatedShadow,
    ] {
        service
            .record_evidence(
                rollback_next_context(&service),
                RecordEvidenceInput {
                    plan_id: rb_plan_id.clone(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        service
            .advance_phase(rollback_next_context(&service), rb_plan_id.clone(), target)
            .unwrap();
    }

    service
        .record_evidence(
            rollback_next_context(&service),
            RecordEvidenceInput {
                plan_id: rb_plan_id.clone(),
                evidence: MigrationEvidence::SimulatedShadow {
                    semantic_diff_digest: ArtifactDigest::from_bytes([14; 32]),
                    canonical_write_count: 0,
                    external_effect_count: 0,
                    client_acknowledgement_count: 0,
                },
            },
        )
        .unwrap();

    for (index, family) in GateFamily::ALL.into_iter().enumerate() {
        service
            .record_evidence(
                rollback_next_context(&service),
                RecordEvidenceInput {
                    plan_id: rb_plan_id.clone(),
                    evidence: MigrationEvidence::ProductionGate(GateEvidence {
                        gate_id: GateId::new(format!("rb-gate-{}", index + 1)).unwrap(),
                        gate_revision: 1,
                        family,
                        source_generation: candidate_generation(),
                        candidate_generation: source_generation(),
                        cohort: routing_unit().cohort,
                        contract_digest: routing_unit().contract_digest,
                        profile_digest: routing_unit().feature_profile.profile_digest,
                        config_digest: routing_unit().config_digest,
                        measured_at: Timestamp::from_unix_micros(50),
                        valid_until: Timestamp::from_unix_micros(300),
                        status: GateStatus::Passed,
                        evidence_digest: ArtifactDigest::from_bytes(
                            [u8::try_from(index + 1).unwrap(); 32],
                        ),
                    }),
                },
            )
            .unwrap();
    }

    service
        .advance_phase(
            rollback_next_context(&service),
            rb_plan_id.clone(),
            MigrationPhase::InternalCanary,
        )
        .unwrap();

    let evidence_set_digest = rollback_gate_set_digest(&service);
    let prepared = service
        .prepare_cutover(
            rollback_routing_context(&service, 2),
            PrepareCutoverInput {
                plan_id: rb_plan_id.clone(),
                intent: CutoverIntent::Rollback,
                rollout_policy: CutoverPolicy::InternalCanary(
                    CanaryPolicy::new(routing_unit().cohort, 64).unwrap(),
                ),
                manifest: artifact("rollback-manifest", 220),
                source_release: artifact("source-release", 31),
                candidate_release: artifact("candidate-release", 32),
                frozen_evidence_set: ArtifactRef::new(
                    "artifact://evidence-set",
                    evidence_set_digest,
                )
                .unwrap(),
                migration_report: MigrationReport::new(MigrationReportFields {
                    report: artifact("rb-migration-report", 221),
                    plan_id: rb_plan_id.clone(),
                    cycle_id: MigrationCycleId::new("cycle-rollback-1").unwrap(),
                    source_snapshot: artifact("rb-source-snapshot", 222),
                    source_high_water: 0,
                    source_generation: candidate_generation(),
                    candidate_generation: source_generation(),
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
                    mapping: artifact("rb-mapping", 223),
                    profile: artifact("profile", 1),
                    integrity: ArtifactValidation::Passed,
                    rebuild: ArtifactValidation::Passed,
                    disposition: ImportDisposition::Clean,
                    created_at: Timestamp::from_unix_micros(90),
                })
                .unwrap(),
                drain_report: DrainReportArtifact {
                    report: artifact("rb-drain-report", 224),
                    complete: true,
                    timed_out: false,
                    unresolved_effects: 0,
                    source_high_water: 0,
                },
                candidate_validation: CandidateValidationReport {
                    report: artifact("rb-candidate-validation", 225),
                    validation: ArtifactValidation::Passed,
                },
                rollback_policy: RollbackPolicy::BeforeCandidateWrites,
                retention_until: Timestamp::from_unix_micros(1_000),
                operator_authorization: artifact("rb-operator-authorization", 226),
            },
        )
        .unwrap();

    let committed = service
        .commit_cutover(
            rollback_routing_context(&service, 2),
            CommitCutoverInput {
                plan_id: rb_plan_id,
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 0,
                candidate_fencing_token: FencingToken::new([15; 32]).unwrap(),
            },
        )
        .unwrap();

    let snapshot = committed.outcome.routing_snapshot.unwrap();
    assert!(matches!(
        snapshot.authority,
        RuntimeAuthority::Source(ref generation) if generation == &source_generation()
    ));
    assert_eq!(
        snapshot.rollback_disposition,
        RollbackDisposition::Ineligible
    );
}

#[derive(Clone, Default)]
struct MemoryMigrationStore {
    state: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    plans: BTreeMap<String, LoadedMigrationPlan>,
    heads: BTreeMap<ArtifactDigest, RoutingSnapshot>,
    receipts: BTreeMap<
        String,
        (
            IdempotencyKey,
            MigrationCommandFingerprint,
            gocode_application::migration::ports::MigrationCommandOutcome,
        ),
    >,
    audits: Vec<gocode_application::migration::ports::MigrationAuditRecord>,
}

impl MemoryMigrationStore {
    fn insert_routing_head(&self, unit: &RoutingUnit, snapshot: RoutingSnapshot) {
        self.state
            .lock()
            .unwrap()
            .heads
            .insert(unit.digest(), snapshot);
    }

    fn transition_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .plans
            .values()
            .map(|loaded| loaded.transitions.len())
            .sum()
    }

    fn evidence_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .plans
            .values()
            .map(|loaded| loaded.evidence.len())
            .sum()
    }

    fn retirement_manifest_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .plans
            .values()
            .map(|loaded| loaded.retirement_manifests.len())
            .sum()
    }
}
