use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use gocode_application::migration::{
    error::MigrationError,
    gates::MigrationEvidence,
    ports::{
        LoadedMigrationPlan, MigrationCommandContext, MigrationCommandFingerprint, MigrationCommit,
        MigrationCommitResult, MigrationControlStore, MigrationMutation, MigrationReceipt,
        MigrationReceiptLookup, MigrationStoreError, SanitizedShadowInput, ShadowDiffReport,
        ShadowExecutionError, ShadowExecutionPort,
    },
    service::{MigrationService, RecordEvidenceInput, StagePlanInput, StartRollbackInput},
    state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        FencingToken, GatePolicyRef, MigrationCycleId, MigrationPlanId, OperatorId,
        RollbackDisposition, RoutingGeneration, RoutingSnapshot, RoutingUnit, RuntimeAuthority,
        RuntimeGenerationRef,
    },
};
use gocode_domain::{
    id::{CommandId, IdempotencyKey},
    timestamp::Timestamp,
};

#[test]
fn stage_plan_is_idempotent_and_source_only() {
    let store = MemoryMigrationStore::default();
    let service = MigrationService::new(store.clone(), PureShadow);

    let first = service.stage_plan(stage_context(), stage_input()).unwrap();
    let retry = service.stage_plan(stage_context(), stage_input()).unwrap();

    assert_eq!(first, retry);
    assert!(matches!(
        first.snapshot.authority,
        RuntimeAuthority::Source(_)
    ));
    assert_eq!(store.transition_count(), 1);
}

#[test]
fn stage_plan_rejects_same_command_with_a_different_candidate() {
    let store = MemoryMigrationStore::default();
    let service = MigrationService::new(store.clone(), PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();

    let replacement = RuntimeGenerationRef::new("runtime-native-replacement").unwrap();
    let mut conflicting = stage_input();
    conflicting.plan.candidate = replacement.clone();
    conflicting.initial_snapshot = RoutingSnapshot::new(
        RoutingGeneration::new(1).unwrap(),
        source_generation(),
        replacement,
        MigrationPhase::Baseline,
        RuntimeAuthority::Source(source_generation()),
        routing_unit(),
        FencingToken::new([7; 32]).unwrap(),
        RollbackDisposition::Eligible,
        Timestamp::from_unix_micros(1),
    )
    .unwrap();

    assert_eq!(
        service.stage_plan(stage_context(), conflicting),
        Err(MigrationError::StorageContractViolation)
    );
    assert_eq!(store.transition_count(), 1);
}

#[test]
fn phases_zero_through_three_never_select_candidate() {
    let (service, _) = seeded_service();

    for target in [
        MigrationPhase::Foundation,
        MigrationPhase::ReadOnlyParity,
        MigrationPhase::SimulatedShadow,
    ] {
        service
            .record_evidence(
                next_context(&service),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        service
            .advance_phase(next_context(&service), plan_id(), target)
            .unwrap();

        let head = service.routing_head(&routing_unit()).unwrap().unwrap();
        assert!(matches!(head.authority, RuntimeAuthority::Source(_)));
    }
}

#[test]
fn advance_phase_rejects_non_adjacent_target_before_evidence_lookup() {
    let (service, _) = seeded_service();

    assert_eq!(
        service.advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::SimulatedShadow,
        ),
        Err(MigrationError::InvalidPhaseTransition {
            from: MigrationPhase::Baseline,
            to: MigrationPhase::SimulatedShadow,
        })
    );
}

#[test]
fn record_evidence_rejects_same_command_with_changed_semantics() {
    let (service, store) = seeded_service();
    let context = next_context(&service);
    service
        .record_evidence(
            context.clone(),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::Baseline {
                    source_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".to_owned(),
                    inventory_digest: ArtifactDigest::from_bytes([8; 32]),
                    fixture_digest: ArtifactDigest::from_bytes([9; 32]),
                },
            },
        )
        .unwrap();

    assert_eq!(
        service.record_evidence(
            context,
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::Baseline {
                    source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                    inventory_digest: ArtifactDigest::from_bytes([8; 32]),
                    fixture_digest: ArtifactDigest::from_bytes([9; 32]),
                },
            },
        ),
        Err(MigrationError::StorageContractViolation)
    );
    assert_eq!(store.evidence_count(), 1);
}

#[test]
fn record_evidence_rejects_scope_mismatch_without_mutation() {
    let (service, store) = seeded_service();

    assert_eq!(
        service.record_evidence(
            next_context(&service),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::Foundation {
                    contract_digest: ArtifactDigest::from_bytes([99; 32]),
                    store_integrity_digest: ArtifactDigest::from_bytes([10; 32]),
                    deterministic_test_digest: ArtifactDigest::from_bytes([11; 32]),
                },
            },
        ),
        Err(MigrationError::EvidenceScopeMismatch)
    );
    assert_eq!(store.evidence_count(), 0);
}

#[test]
fn canary_transition_fails_closed_before_gate_implementation() {
    let (service, _) = shadow_ready_service();
    let before = service.load_plan(&plan_id()).unwrap();

    assert_eq!(
        service.advance_phase(
            next_context(&service),
            plan_id(),
            MigrationPhase::InternalCanary,
        ),
        Err(MigrationError::ProductionGatesUnavailable)
    );
    assert_eq!(service.load_plan(&plan_id()).unwrap(), before);
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

#[derive(Clone, Default)]
struct MemoryMigrationStore {
    state: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    plans: BTreeMap<String, LoadedMigrationPlan>,
    heads: BTreeMap<ArtifactDigest, RoutingSnapshot>,
    receipts: BTreeMap<
        String,
        (
            IdempotencyKey,
            MigrationCommandFingerprint,
            gocode_application::migration::ports::MigrationCommandOutcome,
        ),
    >,
}

impl MemoryMigrationStore {
    fn transition_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .plans
            .values()
            .map(|loaded| loaded.transitions.len())
            .sum()
    }

    fn evidence_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .plans
            .values()
            .map(|loaded| loaded.evidence.len())
            .sum()
    }
}

impl MigrationControlStore for MemoryMigrationStore {
    fn load_plan(
        &self,
        plan_id: &MigrationPlanId,
    ) -> Result<Option<LoadedMigrationPlan>, MigrationStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .plans
            .get(plan_id.as_str())
            .cloned())
    }

    fn load_routing_head(
        &self,
        unit: &RoutingUnit,
    ) -> Result<Option<RoutingSnapshot>, MigrationStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .heads
            .get(&unit.digest())
            .cloned())
    }

    fn lookup_receipt(
        &self,
        context: &MigrationCommandContext,
        fingerprint: &MigrationCommandFingerprint,
    ) -> Result<MigrationReceiptLookup, MigrationStoreError> {
        let state = self.state.lock().unwrap();
        let Some((stored_key, stored_fingerprint, stored_result)) =
            state.receipts.get(&context.command_id.to_string())
        else {
            return Ok(MigrationReceiptLookup::Miss);
        };
        if stored_key == &context.idempotency_key && stored_fingerprint == fingerprint {
            Ok(MigrationReceiptLookup::Duplicate {
                stored_result: Box::new(stored_result.clone()),
            })
        } else {
            Err(MigrationStoreError::IdempotencyConflict)
        }
    }

    fn commit(
        &self,
        commit: MigrationCommit,
    ) -> Result<MigrationCommitResult, MigrationStoreError> {
        let mut state = self.state.lock().unwrap();
        let command_key = commit.context().command_id.to_string();
        if let Some((stored_key, stored_fingerprint, stored_result)) =
            state.receipts.get(&command_key)
        {
            if stored_key == &commit.context().idempotency_key
                && stored_fingerprint == commit.fingerprint()
            {
                return Ok(MigrationCommitResult::Duplicate {
                    stored_result: stored_result.clone(),
                });
            }
            return Err(MigrationStoreError::IdempotencyConflict);
        }

        if let Some(existing) = state.plans.get(commit.guard_plan_id().as_str())
            && existing.plan.plan_version != commit.context().expected_plan_version
        {
            return Err(MigrationStoreError::PlanVersionConflict {
                expected: commit.context().expected_plan_version,
                actual: existing.plan.plan_version,
            });
        }

        let mutations = commit.mutations().to_vec();
        for mutation in &mutations {
            match mutation {
                MigrationMutation::InsertPlan(plan) => {
                    state.plans.insert(
                        plan.plan_id.to_string(),
                        LoadedMigrationPlan {
                            plan: plan.clone(),
                            transitions: Vec::new(),
                            evidence: Vec::new(),
                        },
                    );
                }
                MigrationMutation::AppendTransition(transition) => {
                    state
                        .plans
                        .get_mut(transition.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .transitions
                        .push(transition.clone());
                }
                MigrationMutation::AppendEvidence(evidence) => {
                    state
                        .plans
                        .get_mut(commit.plan().plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .evidence
                        .push(evidence.clone());
                }
                MigrationMutation::AppendRoutingSnapshot(snapshot) => {
                    state
                        .heads
                        .insert(commit.plan().routing_unit.digest(), snapshot.clone());
                }
                MigrationMutation::AdvanceRoutingHead { .. }
                | MigrationMutation::InsertRuntimeBinding(_) => {}
            }
        }

        state
            .plans
            .get_mut(commit.plan().plan_id.as_str())
            .ok_or(MigrationStoreError::CorruptData)?
            .plan = commit.plan().clone();

        let outcome = commit.outcome().clone();
        let receipt = MigrationReceipt {
            command_id: commit.context().command_id,
            idempotency_key: commit.context().idempotency_key.clone(),
            fingerprint: *commit.fingerprint(),
            stored_result: outcome.clone(),
            committed_at: Timestamp::from_unix_micros(100),
        };
        state.receipts.insert(
            command_key,
            (
                commit.context().idempotency_key.clone(),
                *commit.fingerprint(),
                outcome,
            ),
        );
        Ok(MigrationCommitResult::Committed { receipt })
    }
}

#[derive(Clone, Copy)]
struct PureShadow;

impl ShadowExecutionPort for PureShadow {
    fn evaluate(
        &self,
        _input: SanitizedShadowInput,
    ) -> Result<ShadowDiffReport, ShadowExecutionError> {
        Err(ShadowExecutionError::InvalidInput)
    }
}

fn seeded_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let store = MemoryMigrationStore::default();
    let service = MigrationService::new(store.clone(), PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();
    (service, store)
}

fn shadow_ready_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let (service, store) = seeded_service();
    for target in [
        MigrationPhase::Foundation,
        MigrationPhase::ReadOnlyParity,
        MigrationPhase::SimulatedShadow,
    ] {
        service
            .record_evidence(
                next_context(&service),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        service
            .advance_phase(next_context(&service), plan_id(), target)
            .unwrap();
    }
    service
        .record_evidence(
            next_context(&service),
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
    (service, store)
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

fn stage_context() -> MigrationCommandContext {
    command_context(0, None, 1)
}

fn command_context(
    expected_plan_version: u64,
    expected_routing_generation: Option<RoutingGeneration>,
    command_suffix: u64,
) -> MigrationCommandContext {
    MigrationCommandContext {
        command_id: format!("018f2e3a-8d5c-7b20-8d9a-{command_suffix:012x}")
            .parse::<CommandId>()
            .unwrap(),
        idempotency_key: IdempotencyKey::new(format!("migration-command-{command_suffix}"))
            .unwrap(),
        operator_id: OperatorId::new("operator-1").unwrap(),
        expected_plan_version,
        expected_routing_generation,
    }
}

fn stage_input() -> StagePlanInput {
    StagePlanInput {
        plan: test_plan(),
        initial_snapshot: source_snapshot(),
    }
}

fn required_evidence_for(target: MigrationPhase) -> MigrationEvidence {
    match target {
        MigrationPhase::Foundation => MigrationEvidence::Baseline {
            source_sha: "66495a2a22cd0a57efcc4f721e65532f0987b4e8".to_owned(),
            inventory_digest: ArtifactDigest::from_bytes([8; 32]),
            fixture_digest: ArtifactDigest::from_bytes([9; 32]),
        },
        MigrationPhase::ReadOnlyParity => MigrationEvidence::Foundation {
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            store_integrity_digest: ArtifactDigest::from_bytes([10; 32]),
            deterministic_test_digest: ArtifactDigest::from_bytes([11; 32]),
        },
        MigrationPhase::SimulatedShadow => MigrationEvidence::ReadOnlyParity {
            import_report_digest: ArtifactDigest::from_bytes([12; 32]),
            completeness_digest: ArtifactDigest::from_bytes([13; 32]),
            canonical_mutation_count: 0,
        },
        other => panic!("no source-only evidence fixture for {other:?}"),
    }
}

fn test_plan() -> MigrationPlan {
    MigrationPlan {
        plan_id: plan_id(),
        cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
        cycle_kind: MigrationCycleKind::Forward,
        source: source_generation(),
        candidate: candidate_generation(),
        phase: MigrationPhase::Baseline,
        status: MigrationPlanStatus::Active,
        routing_unit: routing_unit(),
        gate_policy: GatePolicyRef::new("policy-v1").unwrap(),
        plan_version: 0,
        created_at: Timestamp::from_unix_micros(1),
    }
}

fn source_snapshot() -> RoutingSnapshot {
    RoutingSnapshot::new(
        RoutingGeneration::new(1).unwrap(),
        source_generation(),
        candidate_generation(),
        MigrationPhase::Baseline,
        RuntimeAuthority::Source(source_generation()),
        routing_unit(),
        FencingToken::new([7; 32]).unwrap(),
        RollbackDisposition::Eligible,
        Timestamp::from_unix_micros(1),
    )
    .unwrap()
}

fn rollback_input() -> StartRollbackInput {
    StartRollbackInput {
        parent_plan_id: plan_id(),
        rollback_plan: MigrationPlan {
            plan_id: rollback_plan_id(),
            cycle_id: MigrationCycleId::new("cycle-rollback-1").unwrap(),
            cycle_kind: MigrationCycleKind::Rollback {
                parent_cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            },
            source: candidate_generation(),
            candidate: source_generation(),
            phase: MigrationPhase::Baseline,
            status: MigrationPlanStatus::Active,
            routing_unit: routing_unit(),
            gate_policy: GatePolicyRef::new("policy-v1").unwrap(),
            plan_version: 0,
            created_at: Timestamp::from_unix_micros(20),
        },
        initial_snapshot: RoutingSnapshot::new(
            RoutingGeneration::new(2).unwrap(),
            candidate_generation(),
            source_generation(),
            MigrationPhase::Baseline,
            RuntimeAuthority::Source(candidate_generation()),
            routing_unit(),
            FencingToken::new([8; 32]).unwrap(),
            RollbackDisposition::Eligible,
            Timestamp::from_unix_micros(20),
        )
        .unwrap(),
    }
}

fn plan_id() -> MigrationPlanId {
    MigrationPlanId::new("plan-1").unwrap()
}

fn rollback_plan_id() -> MigrationPlanId {
    MigrationPlanId::new("plan-rollback-1").unwrap()
}

fn source_generation() -> RuntimeGenerationRef {
    RuntimeGenerationRef::new("runtime-legacy").unwrap()
}

fn candidate_generation() -> RuntimeGenerationRef {
    RuntimeGenerationRef::new("runtime-native").unwrap()
}

fn routing_unit() -> RoutingUnit {
    RoutingUnit {
        deployment: DeploymentId::new("production").unwrap(),
        cohort: CohortSelector::new(vec![
            CohortDimension::new("client_class", "premium").unwrap(),
        ])
        .unwrap(),
        feature_profile: FeatureProfileRef::new("default", 1, ArtifactDigest::from_bytes([1; 32]))
            .unwrap(),
        contract_digest: ArtifactDigest::from_bytes([2; 32]),
        schema_digest: ArtifactDigest::from_bytes([3; 32]),
        config_digest: ArtifactDigest::from_bytes([4; 32]),
    }
}
