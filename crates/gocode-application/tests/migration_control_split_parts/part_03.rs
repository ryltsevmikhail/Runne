#[test]
fn each_cohort_expansion_allocates_exactly_one_new_generation() {
    let (service, _) = canary_active_service();
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::CohortRollout,
        )
        .unwrap();
    let evidence_set_digest = current_gate_set_digest(&service, MigrationPhase::CohortRollout);

    let first_prepared = service
        .prepare_cutover(
            next_routing_generation_context(&service, 2),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                20,
                valid_rollout_step(2, 2_048),
                0,
                60,
            ),
        )
        .unwrap();
    let first = service
        .commit_cutover(
            next_routing_generation_context(&service, 2),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: first_prepared.outcome.transition_id,
                observed_source_high_water: 20,
                candidate_fencing_token: FencingToken::new([10; 32]).unwrap(),
            },
        )
        .unwrap()
        .outcome
        .routing_snapshot
        .unwrap();

    let before_non_expanding_step = service.load_plan(&plan_id()).unwrap();
    assert_eq!(
        service.prepare_cutover(
            next_routing_generation_context(&service, 3),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                21,
                valid_rollout_step(3, 2_048),
                0,
                65,
            ),
        ),
        Err(MigrationError::ProductionGatesUnavailable)
    );
    assert_eq!(
        service.load_plan(&plan_id()).unwrap(),
        before_non_expanding_step
    );

    let second_prepared = service
        .prepare_cutover(
            next_routing_generation_context(&service, 3),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                21,
                valid_rollout_step(3, 4_096),
                0,
                70,
            ),
        )
        .unwrap();
    let second = service
        .commit_cutover(
            next_routing_generation_context(&service, 3),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: second_prepared.outcome.transition_id,
                observed_source_high_water: 21,
                candidate_fencing_token: FencingToken::new([11; 32]).unwrap(),
            },
        )
        .unwrap()
        .outcome
        .routing_snapshot
        .unwrap();

    assert_eq!(first.routing_generation.get(), 3);
    assert_eq!(
        second.routing_generation.get(),
        first.routing_generation.get() + 1
    );
}

#[test]
fn default_native_preserves_candidate_authority_and_exact_fallback_profile() {
    let (service, _) = canary_active_service();
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::CohortRollout,
        )
        .unwrap();
    let cohort_evidence = current_gate_set_digest(&service, MigrationPhase::CohortRollout);
    let cohort_prepared = service
        .prepare_cutover(
            next_routing_generation_context(&service, 2),
            prepare_cohort_expansion_input(
                cohort_evidence,
                20,
                valid_rollout_step(2, 2_048),
                0,
                80,
            ),
        )
        .unwrap();
    service
        .commit_cutover(
            next_routing_generation_context(&service, 2),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: cohort_prepared.outcome.transition_id,
                observed_source_high_water: 20,
                candidate_fencing_token: FencingToken::new([10; 32]).unwrap(),
            },
        )
        .unwrap();
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::DefaultNative,
        )
        .unwrap();

    let evidence_set_digest = current_gate_set_digest(&service, MigrationPhase::DefaultNative);
    let mut input = prepare_cohort_expansion_input(
        evidence_set_digest,
        30,
        valid_rollout_step(3, 4_096),
        0,
        90,
    );
    input.intent = CutoverIntent::DefaultNative;
    input.rollout_policy =
        CutoverPolicy::DefaultNative(PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
            source_profile: routing_unit().feature_profile,
        });
    let prepared = service
        .prepare_cutover(next_routing_generation_context(&service, 3), input)
        .unwrap();
    let snapshot = service
        .commit_cutover(
            next_routing_generation_context(&service, 3),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 30,
                candidate_fencing_token: FencingToken::new([11; 32]).unwrap(),
            },
        )
        .unwrap()
        .outcome
        .routing_snapshot
        .unwrap();

    assert_eq!(snapshot.routing_generation.get(), 4);
    assert!(matches!(
        snapshot.authority,
        RuntimeAuthority::Candidate(ref generation) if generation == &candidate_generation()
    ));
}

#[test]
fn production_control_primitives_fail_closed_without_mutation() {
    let (service, _) = seeded_service();
    let before_plan = service.load_plan(&plan_id()).unwrap();
    let before_head = service.routing_head(&routing_unit()).unwrap();

    assert_eq!(
        service.prepare_cutover(
            command_context(0, None, 60),
            prepare_cutover_input(ArtifactDigest::from_bytes([20; 32]), 10),
        ),
        Err(MigrationError::ProductionGatesUnavailable)
    );
    assert_eq!(
        service.commit_cutover(
            command_context(0, None, 61),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: "prepared-1".to_owned(),
                observed_source_high_water: 10,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        ),
        Err(MigrationError::ProductionGatesUnavailable)
    );
    assert_eq!(
        service.begin_drain(
            command_context(0, None, 62),
            BeginDrainInput {
                plan_id: plan_id(),
                cohort: routing_unit().cohort,
            },
        ),
        Err(MigrationError::DrainBlocked)
    );
    assert_eq!(
        service.retire_source(command_context(0, None, 63), retirement_input(),),
        Err(MigrationError::RetirementBlocked)
    );

    assert_eq!(service.load_plan(&plan_id()).unwrap(), before_plan);
    assert_eq!(service.routing_head(&routing_unit()).unwrap(), before_head);
}

#[test]
fn lifecycle_generic_transition_to_drain_deprecate_has_no_durable_effect() {
    let (service, store) = seeded_service();
    {
        let mut state = store.state.lock().unwrap();
        let loaded = state.plans.get_mut(plan_id().as_str()).unwrap();
        loaded.plan.phase = MigrationPhase::DefaultNative;
        loaded.plan.plan_version = 6;
    }
    let before = lifecycle_state(&service, &store);

    assert_eq!(
        service.advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::DrainDeprecate,
        ),
        Err(MigrationError::SpecializedTransitionRequired {
            target: MigrationPhase::DrainDeprecate,
        })
    );
    assert_eq!(lifecycle_state(&service, &store), before);
}

#[test]
fn lifecycle_generic_transition_to_retired_has_no_durable_effect() {
    let (service, store) = draining_service();
    let before = lifecycle_state(&service, &store);

    assert_eq!(
        service.advance_phase(next_context(&service), plan_id(), MigrationPhase::Retired),
        Err(MigrationError::SpecializedTransitionRequired {
            target: MigrationPhase::Retired,
        })
    );
    assert_eq!(lifecycle_state(&service, &store), before);
}
