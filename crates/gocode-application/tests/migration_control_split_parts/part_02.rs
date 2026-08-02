#[test]
fn complete_phase4_gate_set_permits_internal_canary_eligibility() {
    let (service, store) = shadow_ready_service();
    record_phase4_evidence_except(&service, None);
    let unrelated_unit = unrelated_routing_unit();
    let unrelated_snapshot = unrelated_source_snapshot();
    store.insert_routing_head(&unrelated_unit, unrelated_snapshot.clone());

    let output = service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::InternalCanary,
        )
        .unwrap();

    assert_eq!(output.plan.phase, MigrationPhase::InternalCanary);
    assert!(matches!(
        service
            .routing_head(&routing_unit())
            .unwrap()
            .unwrap()
            .authority,
        RuntimeAuthority::Source(_)
    ));
    let evidence_set_digest = current_phase4_gate_set_digest(&service);
    let prepared = service
        .prepare_cutover(
            next_routing_context(&service),
            prepare_cutover_input(evidence_set_digest, 10),
        )
        .unwrap();
    let before_mismatched_high_water = service.load_plan(&plan_id()).unwrap();
    let before_mismatched_head = service.routing_head(&routing_unit()).unwrap();
    assert_eq!(
        service.commit_cutover(
            next_routing_context(&service),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id.clone(),
                observed_source_high_water: 11,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        ),
        Err(MigrationError::StorageContractViolation)
    );
    assert_eq!(
        service.load_plan(&plan_id()).unwrap(),
        before_mismatched_high_water
    );
    assert_eq!(
        service.routing_head(&routing_unit()).unwrap(),
        before_mismatched_head
    );
    let committed = service
        .commit_cutover(
            next_routing_context(&service),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 10,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        )
        .unwrap();
    let snapshot = committed.outcome.routing_snapshot.unwrap();
    assert!(matches!(
        snapshot.authority,
        RuntimeAuthority::Candidate(ref generation) if generation == &candidate_generation()
    ));
    assert_eq!(snapshot.cohort, routing_unit().cohort);
    assert_eq!(snapshot.routing_generation.get(), 2);
    assert_eq!(
        service.routing_head(&unrelated_unit).unwrap(),
        Some(unrelated_snapshot)
    );
}

#[test]
fn revocation_between_prepare_and_commit_blocks_cutover() {
    let (service, _) = shadow_ready_service();
    record_phase4_evidence_except(&service, None);
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::InternalCanary,
        )
        .unwrap();
    let evidence_set_digest = current_phase4_gate_set_digest(&service);
    let prepared = service
        .prepare_cutover(
            next_routing_context(&service),
            prepare_cutover_input(evidence_set_digest, 10),
        )
        .unwrap();
    service
        .record_evidence(
            next_context(&service),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::ProductionGate(phase4_gate_evidence(
                    GateFamily::CanonicalAudit,
                    GateStatus::Revoked {
                        reason: GateRevocationReason::SecurityRevoked,
                    },
                    99,
                )),
            },
        )
        .unwrap();
    let before_plan = service.load_plan(&plan_id()).unwrap();
    let before_head = service.routing_head(&routing_unit()).unwrap();

    assert_eq!(
        service.commit_cutover(
            next_routing_context(&service),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 10,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        ),
        Err(MigrationError::GateRevoked {
            family: GateFamily::CanonicalAudit,
        })
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before_plan);
    assert_eq!(service.routing_head(&routing_unit()).unwrap(), before_head);
}

#[test]
fn cohort_expansion_requires_complete_observation_and_resolved_effects() {
    let (service, _) = canary_active_service();
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::CohortRollout,
        )
        .unwrap();
    let evidence_set_digest = current_gate_set_digest(&service, MigrationPhase::CohortRollout);
    let before = service.load_plan(&plan_id()).unwrap();

    assert_eq!(
        service.prepare_cutover(
            next_routing_generation_context(&service, 2),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                20,
                RolloutStep::new(
                    RoutingGeneration::new(2).unwrap(),
                    routing_unit().cohort,
                    2_048,
                    Duration::from_micros(50),
                    Timestamp::from_unix_micros(51),
                    Timestamp::from_unix_micros(101),
                    GatePolicyRef::new("policy-v1").unwrap(),
                )
                .unwrap(),
                0,
                50,
            ),
        ),
        Err(MigrationError::ObservationWindowIncomplete)
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before);

    let mut rollback_unavailable = prepare_cohort_expansion_input(
        evidence_set_digest,
        20,
        valid_rollout_step(2, 2_048),
        0,
        59,
    );
    rollback_unavailable.rollback_policy = RollbackPolicy::ManualOnly;
    assert_eq!(
        service.prepare_cutover(
            next_routing_generation_context(&service, 2),
            rollback_unavailable,
        ),
        Err(MigrationError::RollbackIneligible)
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before);

    assert_eq!(
        service.prepare_cutover(
            next_routing_generation_context(&service, 2),
            prepare_cohort_expansion_input(
                evidence_set_digest,
                20,
                valid_rollout_step(2, 2_048),
                1,
                60,
            ),
        ),
        Err(MigrationError::UnresolvedEffect)
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before);
}
