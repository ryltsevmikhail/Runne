fn canary_active_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let (service, store) = shadow_ready_service();
    record_phase4_evidence_except(&service, None);
    service
        .advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::InternalCanary,
        )
        .unwrap();
    let evidence_set_digest = current_gate_set_digest(&service, MigrationPhase::InternalCanary);
    let prepared = service
        .prepare_cutover(
            next_routing_generation_context(&service, 1),
            prepare_cutover_input(evidence_set_digest, 10),
        )
        .unwrap();
    service
        .commit_cutover(
            next_routing_generation_context(&service, 1),
            CommitCutoverInput {
                plan_id: plan_id(),
                prepared_transition_id: prepared.outcome.transition_id,
                observed_source_high_water: 10,
                candidate_fencing_token: FencingToken::new([9; 32]).unwrap(),
            },
        )
        .unwrap();
    (service, store)
}

fn draining_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let (service, store) = seeded_service();
    {
        let mut state = store.state.lock().unwrap();
        let loaded = state.plans.get_mut(plan_id().as_str()).unwrap();
        loaded.plan.phase = MigrationPhase::DrainDeprecate;
        loaded.plan.plan_version = 7;
    }
    (service, store)
}

fn lifecycle_state(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
    store: &MemoryMigrationStore,
) -> LifecycleState {
    let plan = service.load_plan(&plan_id()).unwrap();
    let head = service.routing_head(&routing_unit()).unwrap();
    let transition_count = store.transition_count();
    let retirement_manifest_count = store.retirement_manifest_count();
    let state = store.state.lock().unwrap();

    (
        plan,
        head,
        transition_count,
        retirement_manifest_count,
        state.receipts.clone(),
        state.audits.clone(),
    )
}

type LifecycleState = (
    Option<LoadedMigrationPlan>,
    Option<RoutingSnapshot>,
    usize,
    usize,
    BTreeMap<
        String,
        (
            IdempotencyKey,
            MigrationCommandFingerprint,
            runne_application::migration::ports::MigrationCommandOutcome,
        ),
    >,
    Vec<runne_application::migration::ports::MigrationAuditRecord>,
);

fn record_phase4_evidence_except(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
    omitted: Option<GateFamily>,
) {
    for (index, family) in GateFamily::ALL.into_iter().enumerate() {
        if omitted == Some(family) {
            continue;
        }
        service
            .record_evidence(
                next_context(service),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: MigrationEvidence::ProductionGate(phase4_gate_evidence(
                        family,
                        GateStatus::Passed,
                        u8::try_from(index + 1).unwrap(),
                    )),
                },
            )
            .unwrap();
    }
}

fn phase4_gate_evidence(family: GateFamily, status: GateStatus, suffix: u8) -> GateEvidence {
    GateEvidence {
        gate_id: GateId::new(format!("gate-{suffix}")).unwrap(),
        gate_revision: 1,
        family,
        source_generation: source_generation(),
        candidate_generation: candidate_generation(),
        cohort: routing_unit().cohort,
        contract_digest: routing_unit().contract_digest,
        profile_digest: routing_unit().feature_profile.profile_digest,
        config_digest: routing_unit().config_digest,
        measured_at: Timestamp::from_unix_micros(50),
        valid_until: Timestamp::from_unix_micros(300),
        status,
        evidence_digest: ArtifactDigest::from_bytes([suffix; 32]),
    }
}

fn current_phase4_gate_set_digest(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> ArtifactDigest {
    current_gate_set_digest(service, MigrationPhase::InternalCanary)
}

fn current_gate_set_digest(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
    target: MigrationPhase,
) -> ArtifactDigest {
    let loaded = service.load_plan(&plan_id()).unwrap().unwrap();
    PhaseGatePolicy::for_target(target)
        .unwrap()
        .validate(
            &loaded.evidence,
            &GateContext {
                source_generation: loaded.plan.source,
                candidate_generation: loaded.plan.candidate,
                cohort: loaded.plan.routing_unit.cohort,
                contract_digest: loaded.plan.routing_unit.contract_digest,
                profile_digest: loaded.plan.routing_unit.feature_profile.profile_digest,
                config_digest: loaded.plan.routing_unit.config_digest,
                now: Timestamp::from_unix_micros(100),
            },
        )
        .unwrap()
        .digest()
}

fn next_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> MigrationCommandContext {
    let version = service
        .load_plan(&plan_id())
        .unwrap()
        .unwrap()
        .plan
        .plan_version;
    command_context(version, None, version + 2)
}

fn emergency_revoke_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> MigrationCommandContext {
    let version = service
        .load_plan(&plan_id())
        .unwrap()
        .unwrap()
        .plan
        .plan_version;
    command_context(version, None, version + 80)
}

fn rollback_next_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> MigrationCommandContext {
    let version = service
        .load_plan(&rollback_plan_id())
        .unwrap()
        .unwrap()
        .plan
        .plan_version;
    command_context_for_rb(version, 200 + version)
}

fn command_context_for_rb(
    expected_plan_version: u64,
    command_suffix: u64,
) -> MigrationCommandContext {
    MigrationCommandContext {
        command_id: format!("018f2e3a-8d5c-7b20-8d9a-{command_suffix:012x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("rb-command-{command_suffix}")).unwrap(),
        operator_id: OperatorId::new("operator-1").unwrap(),
        expected_plan_version,
        expected_routing_generation: None,
        evaluated_at: Timestamp::from_unix_micros(100),
    }
}

fn rollback_routing_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
    generation: u64,
) -> MigrationCommandContext {
    let mut context = rollback_next_context(service);
    context.expected_routing_generation = Some(RoutingGeneration::new(generation).unwrap());
    context
}

fn rollback_gate_set_digest(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> ArtifactDigest {
    let loaded = service.load_plan(&rollback_plan_id()).unwrap().unwrap();
    PhaseGatePolicy::for_target(MigrationPhase::InternalCanary)
        .unwrap()
        .validate(
            &loaded.evidence,
            &GateContext {
                source_generation: loaded.plan.source,
                candidate_generation: loaded.plan.candidate,
                cohort: loaded.plan.routing_unit.cohort,
                contract_digest: loaded.plan.routing_unit.contract_digest,
                profile_digest: loaded.plan.routing_unit.feature_profile.profile_digest,
                config_digest: loaded.plan.routing_unit.config_digest,
                now: Timestamp::from_unix_micros(100),
            },
        )
        .unwrap()
        .digest()
}

fn next_routing_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
) -> MigrationCommandContext {
    next_routing_generation_context(service, 1)
}

fn next_routing_generation_context(
    service: &MigrationService<MemoryMigrationStore, PureShadow>,
    generation: u64,
) -> MigrationCommandContext {
    let mut context = next_context(service);
    context.expected_routing_generation = Some(RoutingGeneration::new(generation).unwrap());
    context
}
