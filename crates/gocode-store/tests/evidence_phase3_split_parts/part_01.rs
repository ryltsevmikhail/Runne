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
fn evidence_direct_store_lineage_stops_at_default_native() {
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
    ] {
        direct_advance(&store, &pi, phase, &mut c);
        let reopened = SqliteMigrationControlStore::open(db.p()).unwrap();
        assert_eq!(reopened.load_plan(&pi).unwrap().unwrap().plan.phase, phase);
    }

    let loaded = store.load_plan(&pi).unwrap().unwrap();
    assert_eq!(
        loaded.transitions.last().unwrap().to,
        state::MigrationPhase::DefaultNative
    );
    assert!(matches!(
        store.load_routing_head(&ru()).unwrap().unwrap().authority,
        types::RuntimeAuthority::Candidate(_)
    ));
}
