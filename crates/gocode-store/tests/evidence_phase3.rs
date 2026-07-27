use gocode_application::migration::ports::MigrationControlStore;
use gocode_application::migration::*;
use gocode_domain::{
    id::{CommandId, IdempotencyKey},
    timestamp::Timestamp,
};
use gocode_store::migration_store::SqliteMigrationControlStore;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn evidence_fixtures_deterministic() {
    let u = ru();
    assert_eq!(u.digest(), u.digest());
    let ev = gates::MigrationEvidence::Baseline {
        source_sha: "s".into(),
        inventory_digest: ad(8),
        fixture_digest: ad(9),
    };
    assert_ne!(ev.semantic_digest().as_bytes(), &[0; 32]);
    assert_eq!(ev.identity_digest(), ad(9));
    let rb =
        state::MigrationPlan::new_rollback(pid("rb"), cid("rbc"), &tp(), ru(), gpr("p"), ts(10))
            .unwrap();
    assert!(matches!(
        rb.cycle_kind,
        state::MigrationCycleKind::Rollback { .. }
    ));
}

#[test]
fn evidence_shadow_import_e2e_sqlite() {
    let db = Tdb::new("sh");
    let s = SqliteMigrationControlStore::open(db.p()).unwrap();
    let svc = service::MigrationService::new(s, PS);
    let pi = pid("p1");
    let mut c = 0u64;
    let mut v = 0u64;
    // Stage
    mkctx(&mut c, 0, None, |ctx| {
        svc.stage_plan(
            ctx,
            service::StagePlanInput {
                plan: tp(),
                initial_snapshot: sn(rg(1), sg()),
            },
        )
        .unwrap()
    });
    // Source phases 0–3
    rev(
        &svc,
        &pi,
        &mut c,
        &mut v,
        gates::MigrationEvidence::Baseline {
            source_sha: "s".into(),
            inventory_digest: ad(8),
            fixture_digest: ad(9),
        },
    );
    adv(&svc, &pi, &mut c, &mut v, state::MigrationPhase::Foundation);
    rev(
        &svc,
        &pi,
        &mut c,
        &mut v,
        gates::MigrationEvidence::Foundation {
            contract_digest: ad(2),
            store_integrity_digest: ad(10),
            deterministic_test_digest: ad(11),
        },
    );
    adv(
        &svc,
        &pi,
        &mut c,
        &mut v,
        state::MigrationPhase::ReadOnlyParity,
    );
    rev(
        &svc,
        &pi,
        &mut c,
        &mut v,
        gates::MigrationEvidence::ReadOnlyParity {
            import_report_digest: ad(12),
            completeness_digest: ad(13),
            canonical_mutation_count: 0,
        },
    );
    adv(
        &svc,
        &pi,
        &mut c,
        &mut v,
        state::MigrationPhase::SimulatedShadow,
    );
    rev(
        &svc,
        &pi,
        &mut c,
        &mut v,
        gates::MigrationEvidence::SimulatedShadow {
            semantic_diff_digest: ad(14),
            canonical_write_count: 0,
            external_effect_count: 0,
            client_acknowledgement_count: 0,
        },
    );
    // Verify
    let sh = svc
        .load_plan(&pi)
        .unwrap()
        .unwrap()
        .evidence
        .iter()
        .find_map(|e| match e {
            gates::MigrationEvidence::SimulatedShadow {
                canonical_write_count: w,
                external_effect_count: e,
                client_acknowledgement_count: c,
                ..
            } => Some((*w, *e, *c)),
            _ => None,
        })
        .expect("shadow evidence");
    assert_eq!(sh, (0, 0, 0));
    assert!(matches!(
        svc.routing_head(&ru()).unwrap().unwrap().authority,
        types::RuntimeAuthority::Source(_)
    ));
}

#[test]
fn evidence_full_forward_lifecycle_stage_to_retired() {
    let db = Tdb::new("lifecycle");
    let store = SqliteMigrationControlStore::open(db.p()).unwrap();
    let svc = service::MigrationService::new(store.clone(), PS);
    let pi = pid("p1");
    let mut c = 0;
    let mut v = 0;

    mkctx(&mut c, 0, None, |ctx| {
        svc.stage_plan(
            ctx,
            service::StagePlanInput {
                plan: tp(),
                initial_snapshot: sn(rg(1), sg()),
            },
        )
        .unwrap()
    });
    advance_source_phases(&svc, &pi, &mut c, &mut v);
    record_gates(&svc, &pi, &mut c, &mut v, false);
    adv(
        &svc,
        &pi,
        &mut c,
        &mut v,
        state::MigrationPhase::InternalCanary,
    );

    let digest = gate_digest(&svc, &pi, false);
    let prepared = mkctx(&mut c, v, Some(rg(1)), |ctx| {
        svc.prepare_cutover(ctx, canary_input(pi.clone(), cid("c1"), digest))
            .unwrap()
    });
    v += 1;
    mkctx(&mut c, v, Some(rg(1)), |ctx| {
        svc.commit_cutover(
            ctx,
            service::CommitCutoverInput {
                plan_id: pi.clone(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 100,
                candidate_fencing_token: f(9),
            },
        )
        .unwrap()
    });

    for phase in [
        state::MigrationPhase::CohortRollout,
        state::MigrationPhase::DefaultNative,
        state::MigrationPhase::DrainDeprecate,
        state::MigrationPhase::Retired,
    ] {
        direct_advance(&store, &pi, phase, &mut c);
        let reopened = SqliteMigrationControlStore::open(db.p()).unwrap();
        assert_eq!(reopened.load_plan(&pi).unwrap().unwrap().plan.phase, phase);
    }

    let loaded = store.load_plan(&pi).unwrap().unwrap();
    assert_eq!(
        loaded.transitions.last().unwrap().to,
        state::MigrationPhase::Retired
    );
    assert!(matches!(
        store.load_routing_head(&ru()).unwrap().unwrap().authority,
        types::RuntimeAuthority::Candidate(_)
    ));
}

#[test]
fn evidence_rollback_recovery_e2e() {
    let db = Tdb::new("rollback");
    let store = SqliteMigrationControlStore::open(db.p()).unwrap();
    let svc = service::MigrationService::new(store, PS);
    let pi = pid("p1");
    let mut c = 0;
    let mut v = 0;

    mkctx(&mut c, 0, None, |ctx| {
        svc.stage_plan(
            ctx,
            service::StagePlanInput {
                plan: tp(),
                initial_snapshot: sn(rg(1), sg()),
            },
        )
        .unwrap()
    });
    advance_source_phases(&svc, &pi, &mut c, &mut v);
    record_gates(&svc, &pi, &mut c, &mut v, false);
    adv(
        &svc,
        &pi,
        &mut c,
        &mut v,
        state::MigrationPhase::InternalCanary,
    );
    let digest = gate_digest(&svc, &pi, false);
    let prepared = mkctx(&mut c, v, Some(rg(1)), |ctx| {
        svc.prepare_cutover(ctx, canary_input(pi.clone(), cid("c1"), digest))
            .unwrap()
    });
    v += 1;
    mkctx(&mut c, v, Some(rg(1)), |ctx| {
        svc.commit_cutover(
            ctx,
            service::CommitCutoverInput {
                plan_id: pi.clone(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 100,
                candidate_fencing_token: f(9),
            },
        )
        .unwrap()
    });

    let head = svc.routing_head(&ru()).unwrap().unwrap();
    assert!(matches!(
        head.authority,
        types::RuntimeAuthority::Candidate(_)
    ));
    let parent_before = svc.load_plan(&pi).unwrap().unwrap();
    let rollback = mkctx(&mut c, parent_before.plan.plan_version, None, |ctx| {
        svc.start_rollback_cycle(
            ctx,
            rollback_input(&parent_before.plan, rg(head.routing_generation.get() + 1)),
        )
        .unwrap()
    });
    assert!(matches!(
        rollback.plan.cycle_kind,
        state::MigrationCycleKind::Rollback { .. }
    ));
    assert_eq!(svc.load_plan(&pi).unwrap().unwrap(), parent_before);
    drop(svc);

    let reopened = SqliteMigrationControlStore::open(db.p()).unwrap();
    assert_eq!(
        reopened
            .load_plan(&rollback.plan.plan_id)
            .unwrap()
            .unwrap()
            .plan,
        rollback.plan
    );
    assert_eq!(
        reopened
            .load_routing_head(&ru())
            .unwrap()
            .unwrap()
            .routing_generation,
        head.routing_generation
    );
}

fn advance_source_phases(
    svc: &service::MigrationService<SqliteMigrationControlStore, PS>,
    pi: &types::MigrationPlanId,
    c: &mut u64,
    v: &mut u64,
) {
    for (phase, evidence) in [
        (
            state::MigrationPhase::Foundation,
            gates::MigrationEvidence::Baseline {
                source_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".into(),
                inventory_digest: ad(8),
                fixture_digest: ad(9),
            },
        ),
        (
            state::MigrationPhase::ReadOnlyParity,
            gates::MigrationEvidence::Foundation {
                contract_digest: ad(2),
                store_integrity_digest: ad(10),
                deterministic_test_digest: ad(11),
            },
        ),
        (
            state::MigrationPhase::SimulatedShadow,
            gates::MigrationEvidence::ReadOnlyParity {
                import_report_digest: ad(12),
                completeness_digest: ad(13),
                canonical_mutation_count: 0,
            },
        ),
    ] {
        rev(svc, pi, c, v, evidence);
        adv(svc, pi, c, v, phase);
    }
    rev(
        svc,
        pi,
        c,
        v,
        gates::MigrationEvidence::SimulatedShadow {
            semantic_diff_digest: ad(14),
            canonical_write_count: 0,
            external_effect_count: 0,
            client_acknowledgement_count: 0,
        },
    );
}

fn record_gates(
    svc: &service::MigrationService<SqliteMigrationControlStore, PS>,
    pi: &types::MigrationPlanId,
    c: &mut u64,
    v: &mut u64,
    rollback: bool,
) {
    for (index, family) in types::GateFamily::ALL.into_iter().enumerate() {
        let byte = u8::try_from(index + 20).unwrap();
        let (source, candidate) = if rollback { (cg(), sg()) } else { (sg(), cg()) };
        rev(
            svc,
            pi,
            c,
            v,
            gates::MigrationEvidence::ProductionGate(gates::GateEvidence {
                gate_id: types::GateId::new(format!("gate-{rollback}-{index}")).unwrap(),
                gate_revision: 1,
                family,
                source_generation: source,
                candidate_generation: candidate,
                cohort: ru().cohort,
                contract_digest: ad(2),
                profile_digest: ad(1),
                config_digest: ad(4),
                measured_at: ts(50),
                valid_until: ts(300),
                status: gates::GateStatus::Passed,
                evidence_digest: ad(byte),
            }),
        );
    }
}

fn gate_digest(
    svc: &service::MigrationService<SqliteMigrationControlStore, PS>,
    pi: &types::MigrationPlanId,
    rollback: bool,
) -> types::ArtifactDigest {
    let loaded = svc.load_plan(pi).unwrap().unwrap();
    let (source, candidate) = if rollback { (cg(), sg()) } else { (sg(), cg()) };
    gates::PhaseGatePolicy::for_target(state::MigrationPhase::InternalCanary)
        .unwrap()
        .validate(
            &loaded.evidence,
            &gates::GateContext {
                source_generation: source,
                candidate_generation: candidate,
                cohort: ru().cohort,
                contract_digest: ad(2),
                profile_digest: ad(1),
                config_digest: ad(4),
                now: ts(200),
            },
        )
        .unwrap()
        .digest()
}

fn direct_advance(
    store: &SqliteMigrationControlStore,
    pi: &types::MigrationPlanId,
    target: state::MigrationPhase,
    c: &mut u64,
) {
    let loaded = store.load_plan(pi).unwrap().unwrap();
    let from = loaded.plan.phase;
    let mut plan = loaded.plan;
    plan.advance(target, plan.plan_version).unwrap();
    if target == state::MigrationPhase::Retired {
        plan.status = state::MigrationPlanStatus::Retired;
    }
    let ctx = mkctx(c, plan.plan_version - 1, None, |ctx| ctx);
    let transition = ports::MigrationTransition {
        transition_id: format!("evidence-direct-{}", plan.plan_version),
        plan_id: plan.plan_id.clone(),
        cycle_id: plan.cycle_id.clone(),
        from,
        to: target,
        plan_version: plan.plan_version,
        occurred_at: ctx.evaluated_at,
    };
    let outcome = ports::MigrationCommandOutcome {
        plan: plan.clone(),
        routing_snapshot: None,
        transition_id: transition.transition_id.clone(),
    };
    let audit = ports::MigrationAuditRecord {
        record_id: ad(u8::try_from(100 + plan.plan_version).unwrap()),
        plan_id: plan.plan_id.clone(),
        command_id: ctx.command_id,
        operator_id: ctx.operator_id.clone(),
        action: ports::MigrationAuditAction::AdvancePhase,
        recorded_at: ctx.evaluated_at,
    };
    let commit = ports::MigrationCommit::new(
        ctx,
        ports::MigrationCommandFingerprint::from_bytes(
            [u8::try_from(plan.plan_version).unwrap(); 32],
        ),
        plan,
        vec![ports::MigrationMutation::AppendTransition(transition)],
        outcome,
        Some(audit),
    )
    .unwrap();
    store.commit(commit).unwrap();
}

fn canary_input(
    plan_id: types::MigrationPlanId,
    cycle_id: types::MigrationCycleId,
    evidence_digest: types::ArtifactDigest,
) -> service::PrepareCutoverInput {
    service::PrepareCutoverInput {
        plan_id,
        intent: service::CutoverIntent::InternalCanary,
        rollout_policy: rollout::CutoverPolicy::InternalCanary(
            rollout::CanaryPolicy::new(ru().cohort, 64).unwrap(),
        ),
        manifest: ar("cutover-manifest", 30),
        source_release: ar("source-release", 31),
        candidate_release: ar("candidate-release", 32),
        frozen_evidence_set: manifests::ArtifactRef::new(
            "artifact://evidence-set",
            evidence_digest,
        )
        .unwrap(),
        migration_report: manifests::MigrationReport::new(manifests::MigrationReportFields {
            report: ar("migration-report", 33),
            plan_id: pid("p1"),
            cycle_id,
            source_snapshot: ar("source-snapshot", 34),
            source_high_water: 100,
            source_generation: sg(),
            candidate_generation: cg(),
            counts: manifests::MigrationCounts {
                imported: 10,
                skipped: 0,
                unsupported: 0,
                rejected: 0,
                unknown: 0,
                lossy: 0,
                ambiguous: 0,
            },
            schema: ar("schema", 3),
            mapping: ar("mapping", 35),
            profile: ar("profile", 1),
            integrity: manifests::ArtifactValidation::Passed,
            rebuild: manifests::ArtifactValidation::Passed,
            disposition: manifests::ImportDisposition::Clean,
            created_at: ts(90),
        })
        .unwrap(),
        drain_report: manifests::DrainReportArtifact {
            report: ar("drain-report", 36),
            complete: true,
            timed_out: false,
            unresolved_effects: 0,
            source_high_water: 100,
        },
        candidate_validation: manifests::CandidateValidationReport {
            report: ar("candidate-validation", 37),
            validation: manifests::ArtifactValidation::Passed,
        },
        rollback_policy: manifests::RollbackPolicy::BeforeCandidateWrites,
        retention_until: ts(1_000),
        operator_authorization: ar("operator-authorization", 38),
    }
}

fn rollback_input(
    parent: &state::MigrationPlan,
    generation: types::RoutingGeneration,
) -> service::StartRollbackInput {
    let plan = state::MigrationPlan::new_rollback(
        pid("p-rb"),
        cid("c-rb"),
        parent,
        ru(),
        gpr("p"),
        ts(250),
    )
    .unwrap();
    service::StartRollbackInput {
        rollback_plan: plan,
        parent_plan_id: parent.plan_id.clone(),
        initial_snapshot: types::RoutingSnapshot::new(
            generation,
            cg(),
            sg(),
            state::MigrationPhase::Baseline,
            types::RuntimeAuthority::Source(cg()),
            ru(),
            f(11),
            types::RollbackDisposition::Eligible,
            ts(250),
        )
        .unwrap(),
    }
}

fn ar(name: &str, byte: u8) -> manifests::ArtifactRef {
    manifests::ArtifactRef::new(format!("artifact://{name}"), ad(byte)).unwrap()
}

fn mkctx<T>(
    c: &mut u64,
    ver: u64,
    rg: Option<types::RoutingGeneration>,
    f: impl FnOnce(ports::MigrationCommandContext) -> T,
) -> T {
    let s = *c;
    *c += 1;
    f(ports::MigrationCommandContext {
        command_id: format!("018f2e3a-8d5c-7b20-8d9a-{s:012x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("k-{s}")).unwrap(),
        operator_id: types::OperatorId::new("op").unwrap(),
        expected_plan_version: ver,
        expected_routing_generation: rg,
        evaluated_at: ts(200 + i64::try_from(s).unwrap()),
    })
}
fn rev(
    svc: &service::MigrationService<SqliteMigrationControlStore, PS>,
    pi: &types::MigrationPlanId,
    c: &mut u64,
    v: &mut u64,
    ev: gates::MigrationEvidence,
) {
    mkctx(c, *v, None, |ctx| {
        svc.record_evidence(
            ctx,
            service::RecordEvidenceInput {
                plan_id: pi.clone(),
                evidence: ev,
            },
        )
        .unwrap()
    });
    *v += 1;
}
fn adv(
    svc: &service::MigrationService<SqliteMigrationControlStore, PS>,
    pi: &types::MigrationPlanId,
    c: &mut u64,
    v: &mut u64,
    t: state::MigrationPhase,
) {
    mkctx(c, *v, None, |ctx| {
        svc.advance_phase(ctx, pi.clone(), t).unwrap()
    });
    *v += 1;
}

fn pid(n: &str) -> types::MigrationPlanId {
    types::MigrationPlanId::new(n).unwrap()
}
fn cid(n: &str) -> types::MigrationCycleId {
    types::MigrationCycleId::new(n).unwrap()
}
fn sg() -> types::RuntimeGenerationRef {
    types::RuntimeGenerationRef::new("runtime-legacy").unwrap()
}
fn cg() -> types::RuntimeGenerationRef {
    types::RuntimeGenerationRef::new("runtime-native").unwrap()
}
fn ad(b: u8) -> types::ArtifactDigest {
    types::ArtifactDigest::from_bytes([b; 32])
}
fn ts(us: i64) -> Timestamp {
    Timestamp::from_unix_micros(us)
}
fn f(b: u8) -> types::FencingToken {
    types::FencingToken::new([b; 32]).unwrap()
}
fn rg(v: u64) -> types::RoutingGeneration {
    types::RoutingGeneration::new(v).unwrap()
}
fn gpr(n: &str) -> types::GatePolicyRef {
    types::GatePolicyRef::new(n).unwrap()
}
fn ru() -> types::RoutingUnit {
    types::RoutingUnit {
        deployment: types::DeploymentId::new("p").unwrap(),
        cohort: types::CohortSelector::new(vec![
            types::CohortDimension::new("client_class", "premium").unwrap(),
        ])
        .unwrap(),
        feature_profile: types::FeatureProfileRef::new("d", 1, ad(1)).unwrap(),
        contract_digest: ad(2),
        schema_digest: ad(3),
        config_digest: ad(4),
    }
}
fn tp() -> state::MigrationPlan {
    state::MigrationPlan {
        plan_id: pid("p1"),
        cycle_id: cid("c1"),
        cycle_kind: state::MigrationCycleKind::Forward,
        source: sg(),
        candidate: cg(),
        phase: state::MigrationPhase::Baseline,
        status: state::MigrationPlanStatus::Active,
        routing_unit: ru(),
        gate_policy: gpr("p"),
        plan_version: 0,
        created_at: ts(1),
    }
}
fn sn(g: types::RoutingGeneration, s: types::RuntimeGenerationRef) -> types::RoutingSnapshot {
    types::RoutingSnapshot::new(
        g,
        s.clone(),
        cg(),
        state::MigrationPhase::Baseline,
        types::RuntimeAuthority::Source(s),
        ru(),
        f(7),
        types::RollbackDisposition::Eligible,
        ts(1),
    )
    .unwrap()
}

#[derive(Clone, Copy)]
struct PS;
impl ports::ShadowExecutionPort for PS {
    fn evaluate(
        &self,
        _: ports::SanitizedShadowInput,
    ) -> Result<ports::ShadowDiffReport, ports::ShadowExecutionError> {
        Err(ports::ShadowExecutionError::InvalidInput)
    }
}

struct Tdb {
    p: PathBuf,
}
impl Tdb {
    fn new(n: &str) -> Self {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self {
            p: std::env::temp_dir().join(format!("gev-{n}-{}-{ns}.sqlite", std::process::id())),
        }
    }
    fn p(&self) -> &Path {
        &self.p
    }
}
impl Drop for Tdb {
    fn drop(&mut self) {
        for s in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{s}", self.p.display()));
        }
    }
}
