#[test]
fn prepared_cutover_and_canary_head_survive_reopen() {
    let db = TempDb::new("prepared-cutover-reopen");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);
    let mut version = service
        .stage_plan(stage_context(), stage_input())
        .unwrap()
        .plan
        .plan_version;
    for (target, evidence_suffix, advance_suffix) in [
        (MigrationPhase::Foundation, 2_u8, 3_u8),
        (MigrationPhase::ReadOnlyParity, 4, 5),
        (MigrationPhase::SimulatedShadow, 6, 7),
    ] {
        service
            .record_evidence(
                command_context(evidence_suffix, version, None),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        version += 1;
        version = service
            .advance_phase(
                command_context(advance_suffix, version, None),
                plan_id(),
                target,
            )
            .unwrap()
            .plan
            .plan_version;
    }
    service
        .record_evidence(
            command_context(8, version, None),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::SimulatedShadow {
                    semantic_diff_digest: ArtifactDigest::from_bytes([14; 32]),
                    canonical_write_count: 0,
                    external_effect_count: 0,
                    client_acknowledgement_count: 0,
                },
            },
        )
        .unwrap();
    version += 1;
    for (index, family) in GateFamily::ALL.into_iter().enumerate() {
        let suffix = u8::try_from(index + 20).unwrap();
        service
            .record_evidence(
                command_context(suffix, version, None),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: MigrationEvidence::ProductionGate(gate_evidence(family, suffix)),
                },
            )
            .unwrap();
        version += 1;
    }
    version = service
        .advance_phase(
            command_context(39, version, None),
            plan_id(),
            MigrationPhase::InternalCanary,
        )
        .unwrap()
        .plan
        .plan_version;
    let loaded = service.load_plan(&plan_id()).unwrap().unwrap();
    let evidence_set_digest = PhaseGatePolicy::for_target(MigrationPhase::InternalCanary)
        .unwrap()
        .validate(
            &loaded.evidence,
            &GateContext {
                source_generation: loaded.plan.source.clone(),
                candidate_generation: loaded.plan.candidate.clone(),
                cohort: loaded.plan.routing_unit.cohort.clone(),
                contract_digest: loaded.plan.routing_unit.contract_digest,
                profile_digest: loaded.plan.routing_unit.feature_profile.profile_digest,
                config_digest: loaded.plan.routing_unit.config_digest,
                now: Timestamp::from_unix_micros(100),
            },
        )
        .unwrap()
        .digest();
    let prepared = service
        .prepare_cutover(
            command_context(40, version, Some(RoutingGeneration::new(1).unwrap())),
            prepare_cutover_input(evidence_set_digest, 4242),
        )
        .unwrap();
    let committed = service
        .commit_cutover(
            command_context(
                41,
                prepared.outcome.plan.plan_version,
                Some(RoutingGeneration::new(1).unwrap()),
            ),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id.clone(),
                observed_source_high_water: 4242,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        )
        .unwrap();
    assert!(matches!(
        committed
            .outcome
            .routing_snapshot
            .as_ref()
            .unwrap()
            .authority,
        RuntimeAuthority::Candidate(_)
    ));
    let before = service.load_plan(&plan_id()).unwrap().unwrap();
    assert_eq!(before.cutover_manifests.len(), 1);
    assert_eq!(before.migration_reports.len(), 1);
    assert_eq!(before.cutover_manifests[0].source_high_water, 4242);
    assert_eq!(
        before.cutover_manifests[0].prepared_transition_id,
        prepared.outcome.transition_id
    );
    drop(service);

    let reopened = SqliteMigrationControlStore::open(db.path()).unwrap();
    assert_eq!(reopened.load_plan(&plan_id()).unwrap().unwrap(), before);
    assert!(matches!(
        reopened
            .load_routing_head(&routing_unit())
            .unwrap()
            .unwrap()
            .authority,
        RuntimeAuthority::Candidate(_)
    ));
    drop(reopened);

    let connection = db.writer();
    connection
        .execute("DELETE FROM migration_reports", [])
        .unwrap();
    drop(connection);
    let corrupted = SqliteMigrationControlStore::open(db.path()).unwrap();
    assert_eq!(
        corrupted.load_plan(&plan_id()),
        Err(MigrationStoreError::CorruptData)
    );
}

fn stage_commit() -> MigrationCommit {
    stage_commit_for(
        test_plan(),
        source_snapshot(RoutingGeneration::new(1).unwrap()),
        1,
    )
}

fn stage_input() -> StagePlanInput {
    StagePlanInput {
        plan: test_plan(),
        initial_snapshot: source_snapshot(RoutingGeneration::new(1).unwrap()),
    }
}

fn stage_commit_for(plan: MigrationPlan, snapshot: RoutingSnapshot, suffix: u8) -> MigrationCommit {
    let context = command_context(suffix, 0, None);
    let fingerprint = fingerprint(suffix);
    let transition = transition(&format!("transition-stage-{suffix}"), &plan);
    let outcome = MigrationCommandOutcome {
        plan: plan.clone(),
        routing_snapshot: Some(snapshot.clone()),
        transition_id: transition.transition_id.clone(),
    };
    let audit = audit(&context, &plan, MigrationAuditAction::StagePlan, suffix);

    MigrationCommit::new(
        context,
        fingerprint,
        plan.clone(),
        vec![
            MigrationMutation::InsertPlan(plan),
            MigrationMutation::AppendTransition(transition),
            MigrationMutation::AppendRoutingSnapshot(snapshot),
        ],
        outcome,
        Some(audit),
    )
    .unwrap()
}

fn routing_commit(suffix: u8) -> MigrationCommit {
    let plan = test_plan();
    let snapshot = source_snapshot(RoutingGeneration::new(2).unwrap());
    let context = command_context(suffix, 0, Some(RoutingGeneration::new(1).unwrap()));
    let fingerprint = fingerprint(suffix);
    let outcome = MigrationCommandOutcome {
        plan: plan.clone(),
        routing_snapshot: Some(snapshot.clone()),
        transition_id: format!("routing-{suffix}"),
    };
    let audit = audit(
        &context,
        &plan,
        MigrationAuditAction::PrepareCutover,
        suffix,
    );

    MigrationCommit::new(
        context,
        fingerprint,
        plan,
        vec![
            MigrationMutation::AppendRoutingSnapshot(snapshot),
            MigrationMutation::AdvanceRoutingHead {
                unit_digest: routing_unit().digest(),
                expected: RoutingGeneration::new(1).unwrap(),
                next: RoutingGeneration::new(2).unwrap(),
            },
        ],
        outcome,
        Some(audit),
    )
    .unwrap()
}

fn evidence_commit() -> MigrationCommit {
    let mut plan = test_plan();
    plan.record_mutation(0).unwrap();
    let context = command_context(4, 0, None);
    let fingerprint = fingerprint(4);
    let evidence = MigrationEvidence::Baseline {
        source_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".to_owned(),
        inventory_digest: ArtifactDigest::from_bytes([8; 32]),
        fixture_digest: ArtifactDigest::from_bytes([9; 32]),
    };
    let outcome = MigrationCommandOutcome {
        plan: plan.clone(),
        routing_snapshot: None,
        transition_id: "evidence-4".to_owned(),
    };
    let audit = audit(&context, &plan, MigrationAuditAction::RecordEvidence, 4);
    MigrationCommit::new(
        context,
        fingerprint,
        plan,
        vec![MigrationMutation::AppendEvidence(evidence)],
        outcome,
        Some(audit),
    )
    .unwrap()
}
