#[test]
fn lifecycle_begin_drain_has_no_durable_effect() {
    let (service, store) = seeded_service();
    {
        let mut state = store.state.lock().unwrap();
        let loaded = state.plans.get_mut(plan_id().as_str()).unwrap();
        loaded.plan.phase = MigrationPhase::DefaultNative;
        loaded.plan.plan_version = 6;
        let head = state.heads.get_mut(&routing_unit().digest()).unwrap();
        head.authority = RuntimeAuthority::Candidate(candidate_generation());
    }
    let before = lifecycle_state(&service, &store);

    assert_eq!(
        service.begin_drain(
            next_context(&service),
            BeginDrainInput {
                plan_id: plan_id(),
                cohort: routing_unit().cohort,
            },
        ),
        Err(MigrationError::DrainBlocked)
    );
    assert_eq!(lifecycle_state(&service, &store), before);
}

#[test]
fn retirement_requires_every_exit_condition_without_mutation() {
    for missing in RetirementRequirement::ALL {
        let (service, _) = draining_service();
        let before = service.load_plan(&plan_id()).unwrap();
        let mut input = retirement_input();
        omit_retirement_requirement(&mut input.readiness, missing);

        assert_eq!(
            service.retire_source(next_context(&service), input),
            Err(MigrationError::RetirementBlocked)
        );
        assert_eq!(service.load_plan(&plan_id()).unwrap(), before);
    }
}

#[test]
fn lifecycle_retire_source_has_no_durable_effect() {
    let (service, store) = draining_service();
    let before = lifecycle_state(&service, &store);

    assert_eq!(
        service.retire_source(next_context(&service), retirement_input()),
        Err(MigrationError::RetirementBlocked)
    );

    assert_eq!(lifecycle_state(&service, &store), before);
}

#[test]
fn rollback_cycle_is_source_only_and_does_not_rewrite_parent() {
    let (service, _) = seeded_service();
    let parent_before = service.load_plan(&plan_id()).unwrap();

    let output = service
        .start_rollback_cycle(command_context(0, None, 50), rollback_input())
        .unwrap();

    assert_ne!(output.plan.plan_id, plan_id());
    assert!(matches!(
        output.snapshot.authority,
        RuntimeAuthority::Source(_)
    ));
    assert_eq!(service.load_plan(&plan_id()).unwrap(), parent_before);
}

#[test]
fn rollback_cycle_rejects_a_stale_parent_version_without_mutation() {
    let (service, _) = seeded_service();

    assert_eq!(
        service.start_rollback_cycle(command_context(1, None, 51), rollback_input()),
        Err(MigrationError::PlanVersionConflict {
            expected: 1,
            actual: 0,
        })
    );
    assert!(service.load_plan(&rollback_plan_id()).unwrap().is_none());
}

#[test]
fn emergency_revoke_restores_source_authority_and_disables_further_rollback() {
    let (service, _) = canary_active_service();
    let before_head = service.routing_head(&routing_unit()).unwrap().unwrap();
    assert_eq!(
        before_head.rollback_disposition,
        RollbackDisposition::Eligible
    );

    let output = service
        .emergency_revoke(
            emergency_revoke_context(&service),
            EmergencyRevokeInput {
                plan_id: plan_id(),
                operator_authorization: artifact("emergency-auth", 200),
                emergency_reason: "candidate-data-corruption".to_owned(),
                new_fencing_token: FencingToken::new([13; 32]).unwrap(),
            },
        )
        .unwrap();

    let snapshot = output.outcome.routing_snapshot.unwrap();
    assert!(matches!(
        snapshot.authority,
        RuntimeAuthority::Source(ref generation) if generation == &source_generation()
    ));
    assert_eq!(
        snapshot.rollback_disposition,
        RollbackDisposition::Ineligible
    );
    assert_eq!(
        snapshot.routing_generation.get(),
        before_head.routing_generation.get() + 1
    );
}

#[test]
fn emergency_revoke_is_idempotent() {
    let (service, _) = canary_active_service();
    let context = emergency_revoke_context(&service);
    let input = EmergencyRevokeInput {
        plan_id: plan_id(),
        operator_authorization: artifact("emergency-auth", 201),
        emergency_reason: "candidate-data-corruption".to_owned(),
        new_fencing_token: FencingToken::new([14; 32]).unwrap(),
    };

    let first = service
        .emergency_revoke(context.clone(), input.clone())
        .unwrap();
    let retry = service.emergency_revoke(context, input).unwrap();
    assert_eq!(
        first.outcome.routing_snapshot,
        retry.outcome.routing_snapshot
    );
}

#[test]
fn emergency_revoke_rejects_non_production_phases() {
    let (service, _) = seeded_service();

    assert_eq!(
        service.emergency_revoke(
            next_context(&service),
            EmergencyRevokeInput {
                plan_id: plan_id(),
                operator_authorization: artifact("emergency-auth", 202),
                emergency_reason: "test".to_owned(),
                new_fencing_token: FencingToken::new([15; 32]).unwrap(),
            },
        ),
        Err(MigrationError::EmergencyRevokeIneligible)
    );
}
