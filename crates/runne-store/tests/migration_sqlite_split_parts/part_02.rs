#[test]
fn full_baseline_to_shadow_lifecycle_remains_source_only_in_sqlite() {
    let db = TempDb::new("baseline-to-shadow");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);
    let staged = service.stage_plan(stage_context(), stage_input()).unwrap();
    let mut expected_version = staged.plan.plan_version;
    let phases = [
        (MigrationPhase::Foundation, 2_u8, 3_u8),
        (MigrationPhase::ReadOnlyParity, 4, 5),
        (MigrationPhase::SimulatedShadow, 6, 7),
    ];

    for (target, evidence_suffix, advance_suffix) in phases {
        service
            .record_evidence(
                command_context(evidence_suffix, expected_version, None),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        expected_version += 1;
        let advanced = service
            .advance_phase(
                command_context(advance_suffix, expected_version, None),
                plan_id(),
                target,
            )
            .unwrap();
        expected_version = advanced.plan.plan_version;
        assert!(matches!(
            service
                .routing_head(&routing_unit())
                .unwrap()
                .unwrap()
                .authority,
            RuntimeAuthority::Source(_)
        ));
    }

    let loaded = service.load_plan(&plan_id()).unwrap().unwrap();
    assert_eq!(loaded.plan.phase, MigrationPhase::SimulatedShadow);
    assert_eq!(loaded.plan.plan_version, 6);
    assert_eq!(loaded.transitions.len(), 4);
    assert_eq!(loaded.evidence.len(), 3);
}

#[test]
fn duplicate_stage_and_evidence_commands_replay_original_outcomes() {
    let db = TempDb::new("duplicate-control");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);

    let staged = service.stage_plan(stage_context(), stage_input()).unwrap();
    let stage_retry = service.stage_plan(stage_context(), stage_input()).unwrap();
    assert_eq!(staged, stage_retry);
    let evidence_context = command_context(2, 0, None);
    let evidence_input = RecordEvidenceInput {
        plan_id: plan_id(),
        evidence: required_evidence_for(MigrationPhase::Foundation),
    };
    let evidence = service
        .record_evidence(evidence_context.clone(), evidence_input.clone())
        .unwrap();
    let evidence_retry = service
        .record_evidence(evidence_context, evidence_input)
        .unwrap();
    assert_eq!(evidence, evidence_retry);

    let connection = db.reader();
    assert_eq!(row_count(&connection, "migration_transitions"), 1);
    assert_eq!(row_count(&connection, "migration_evidence"), 1);
    assert_eq!(row_count(&connection, "migration_receipts"), 2);
    assert_eq!(row_count(&connection, "migration_audit"), 2);
}

#[test]
fn crash_reopen_preserves_phase_evidence_and_source_head() {
    let db = TempDb::new("control-reopen");
    let original_store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(original_store, PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();
    service
        .record_evidence(
            command_context(2, 0, None),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: required_evidence_for(MigrationPhase::Foundation),
            },
        )
        .unwrap();
    service
        .advance_phase(
            command_context(3, 1, None),
            plan_id(),
            MigrationPhase::Foundation,
        )
        .unwrap();
    let before_plan = service.load_plan(&plan_id()).unwrap().unwrap();
    let before_head = service.routing_head(&routing_unit()).unwrap();
    drop(service);

    let reopened_store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let reopened = MigrationService::new(reopened_store, PureShadow);
    assert_eq!(
        reopened.load_plan(&plan_id()).unwrap().unwrap(),
        before_plan
    );
    assert_eq!(reopened.routing_head(&routing_unit()).unwrap(), before_head);
    assert!(matches!(
        before_head.unwrap().authority,
        RuntimeAuthority::Source(_)
    ));
}

#[test]
fn stale_plan_version_changes_no_durable_rows() {
    let db = TempDb::new("stale-plan");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();
    let connection = db.reader();
    let before = migration_durable_counts(&connection);

    assert!(
        service
            .advance_phase(
                command_context(2, 99, None),
                plan_id(),
                MigrationPhase::Foundation,
            )
            .is_err()
    );
    assert_eq!(migration_durable_counts(&connection), before);
}

#[test]
fn rollback_cycle_starts_at_baseline_without_mutating_parent() {
    let db = TempDb::new("rollback-cycle");
    let store = SqliteMigrationControlStore::open(db.path()).unwrap();
    let service = MigrationService::new(store, PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();
    let parent = service.load_plan(&plan_id()).unwrap().unwrap();

    let rollback = service
        .start_rollback_cycle(command_context(8, 0, None), rollback_input())
        .unwrap();

    assert_eq!(rollback.plan.phase, MigrationPhase::Baseline);
    assert_ne!(rollback.plan.cycle_id, parent.plan.cycle_id);
    assert_eq!(service.load_plan(&plan_id()).unwrap().unwrap(), parent);
    assert!(matches!(
        rollback.snapshot.authority,
        RuntimeAuthority::Source(_)
    ));
    assert_eq!(
        service
            .routing_head(&routing_unit())
            .unwrap()
            .unwrap()
            .routing_generation,
        RoutingGeneration::new(1).unwrap()
    );
}
