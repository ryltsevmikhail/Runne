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
