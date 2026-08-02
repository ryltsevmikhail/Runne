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
